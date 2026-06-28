#!/usr/bin/env python3
"""
geosite2dns.py - 将 geosite 分类转换为 openppp2 dns-rules.txt (绕过列表)

原理:
  dns-rules.txt 是绕过列表——只放需要直连(不走隧道)的域名。
  未匹配到的域名默认全走隧道，无需在文件中列出。

支持三种数据源:
  1. GitHub 源文件 (--from-source, 推荐): 支持 @cn 子分类
  2. geosite.dat protobuf (-g): 离线可用, @cn 被合并
  3. mosdns 解包目录 (-x): 本地预处理

输出格式 (83 bytes/行):
  domain                       ljust(69) /dns-ip/nic + CRLF
  full:domain                  ljust(69) /dns-ip/nic + CRLF
  regexp:pattern               ljust(69) /dns-ip/nic + CRLF

用法:
  python geosite2dns.py -m mapping.yaml -o dns-rules.txt        # 自动检测
  python geosite2dns.py -m mapping.yaml -o dns-rules.txt --from-source  # GitHub
  python geosite2dns.py -g geosite.dat --list-categories        # 列出分类
"""

import os
import sys
import json
import re
import hashlib
import argparse
import tempfile
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from collections import OrderedDict

# ============================================================
# 配置
# ============================================================

GEOSITE_URL = (
    "https://github.com/MetaCubeX/meta-rules-dat/"
    "releases/download/latest/geosite.dat"
)
GEOSITE_SHA256_URL = (
    "https://github.com/MetaCubeX/meta-rules-dat/"
    "releases/download/latest/geosite.dat.sha256sum"
)

# MetaCubeX GitHub 原始源文件
META_REPO_RAW = "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite"

# ============================================================
# Protobuf 最小解析器 (仅限 geosite.dat 格式)
# ============================================================

class ProtobufDecoder:
    """最小 protobuf 解码器，仅处理 geosite.dat 用到的类型"""

    WIRE_VARINT = 0
    WIRE_64BIT = 1
    WIRE_LENGTH_DELIMITED = 2
    WIRE_32BIT = 5

    @staticmethod
    def _decode_varint(data, offset):
        """解码 varint，返回 (值, 新偏移)"""
        value = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            value |= (byte & 0x7F) << shift
            shift += 7
            offset += 1
            if not (byte & 0x80):
                return value, offset
        raise ValueError("Varint 解码失败: 数据不完整")

    @staticmethod
    def _decode_tag(data, offset):
        """解码 (field_number, wire_type, 新偏移)"""
        tag, offset = ProtobufDecoder._decode_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x7
        return field_number, wire_type, offset

    @staticmethod
    def decode_geosite_list(data):
        """解码 GeoSiteList，返回 {country_code: [(type, value), ...]}"""
        result = OrderedDict()
        offset = 0
        while offset < len(data):
            field_number, wire_type, offset = ProtobufDecoder._decode_tag(data, offset)
            
            if wire_type == ProtobufDecoder.WIRE_LENGTH_DELIMITED:
                length, offset = ProtobufDecoder._decode_varint(data, offset)
                if field_number == 1:  # GeoSite entry
                    entry_data = data[offset:offset + length]
                    country, domains = ProtobufDecoder._decode_geosite(entry_data)
                    result[country] = domains
                offset += length
            elif wire_type == ProtobufDecoder.WIRE_VARINT:
                _, offset = ProtobufDecoder._decode_varint(data, offset)
            elif wire_type == ProtobufDecoder.WIRE_64BIT:
                offset += 8
            elif wire_type == ProtobufDecoder.WIRE_32BIT:
                offset += 4
            else:
                raise ValueError(f"未知 wire_type: {wire_type} @ offset {offset}")
        return result

    @staticmethod
    def _decode_geosite(data):
        """解码单个 GeoSite，返回 (country_code, [(type, value), ...])"""
        country_code = ""
        domains = []
        offset = 0
        while offset < len(data):
            field_number, wire_type, offset = ProtobufDecoder._decode_tag(data, offset)
            
            if wire_type == ProtobufDecoder.WIRE_LENGTH_DELIMITED:
                length, offset = ProtobufDecoder._decode_varint(data, offset)
                if field_number == 1:  # country_code (string)
                    country_code = data[offset:offset + length].decode('utf-8')
                elif field_number == 2:  # domains (embedded message)
                    domain_data = data[offset:offset + length]
                    domain = ProtobufDecoder._decode_domain(domain_data)
                    domains.append(domain)
                offset += length
            elif wire_type == ProtobufDecoder.WIRE_VARINT:
                _, offset = ProtobufDecoder._decode_varint(data, offset)
            else:
                offset += 8 if wire_type == ProtobufDecoder.WIRE_64BIT else 4
        
        return country_code, domains

    @staticmethod
    def _decode_domain(data):
        """解码单个 Domain，返回 (type_int, value_string)"""
        domain_type = 0  # Plain
        value = ""
        offset = 0
        while offset < len(data):
            field_number, wire_type, offset = ProtobufDecoder._decode_tag(data, offset)
            
            if wire_type == ProtobufDecoder.WIRE_VARINT:
                val, offset = ProtobufDecoder._decode_varint(data, offset)
                if field_number == 1:  # type
                    domain_type = val
            elif wire_type == ProtobufDecoder.WIRE_LENGTH_DELIMITED:
                length, offset = ProtobufDecoder._decode_varint(data, offset)
                if field_number == 2:  # value
                    value = data[offset:offset + length].decode('utf-8')
                # field 3 = attribute (跳过)
                offset += length
            else:
                offset += 8 if wire_type == ProtobufDecoder.WIRE_64BIT else 4
        
        return (domain_type, value)


# ============================================================
# geosite.dat 下载与校验
# ============================================================

def download_file(url, dest_path, desc="下载中"):
    """下载文件，显示进度"""
    print(f"[*] {desc}: {url}")
    
    def report(block_count, block_size, total_size):
        downloaded = block_count * block_size
        if total_size > 0:
            percent = min(100, downloaded * 100 // total_size)
            sys.stdout.write(f"\r    {percent}% ({downloaded // 1024}KB / {total_size // 1024}KB)")
            sys.stdout.flush()
    
    urllib.request.urlretrieve(url, dest_path, reporthook=report)
    print(f"\r    ✓ 下载完成: {dest_path}")
    return dest_path


def verify_sha256(file_path, expected_hex):
    """校验 SHA256"""
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    actual = h.hexdigest()
    return actual == expected_hex


def download_geosite(dest_path=None):
    """下载 geosite.dat，自动校验"""
    if dest_path is None:
        dest_path = os.path.join(tempfile.gettempdir(), "geosite.dat")
    
    if os.path.exists(dest_path):
        print(f"[✓] 本地 geosite.dat 已存在: {dest_path}")
        return dest_path
    
    print("[*] 下载 geosite.dat...")
    try:
        # 尝试下载 SHA256 校验文件
        sha_path = dest_path + ".sha256sum"
        try:
            download_file(GEOSITE_SHA256_URL, sha_path, desc="下载校验文件")
            with open(sha_path) as f:
                expected = f.read().strip().split()[0]
        except Exception:
            expected = None
        
        # 下载 geosite.dat
        download_file(GEOSITE_URL, dest_path, desc="下载 geosite.dat")
        
        # 校验
        if expected:
            if verify_sha256(dest_path, expected):
                print("[✓] SHA256 校验通过")
            else:
                print("[!] SHA256 校验失败，文件可能损坏")
                os.remove(dest_path)
                return None
        
        return dest_path
    except Exception as e:
        print(f"[!] 下载失败: {e}")
        return None


# ============================================================
# 使用 mosdns v2dat 解包
# ============================================================

def unpack_with_mosdns(geosite_path, output_dir):
    """使用 mosdns v2dat unpack-domain 解包"""
    print("[*] 使用 mosdns v2dat 解包...")
    
    # 查找 mosdns
    mosdns_bin = None
    for candidate in ["mosdns", "mosdns.exe"]:
        try:
            subprocess.run([candidate, "version"], 
                         capture_output=True, timeout=5)
            mosdns_bin = candidate
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    
    if mosdns_bin is None:
        print("[!] 未找到 mosdns，回退到 Python 解析器")
        return None
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        result = subprocess.run(
            [mosdns_bin, "v2dat", "unpack-domain", "-o", output_dir, geosite_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"[!] mosdns v2dat 失败: {result.stderr}")
            return None
        
        # 收集解包出的文件
        txt_files = {}
        for f in os.listdir(output_dir):
            if f.startswith("geosite_") and f.endswith(".txt"):
                category = f[len("geosite_"):-len(".txt")]
                txt_files[category] = os.path.join(output_dir, f)
        
        print(f"[✓] mosdns 解包完成，共 {len(txt_files)} 个分类")
        return txt_files
    except Exception as e:
        print(f"[!] mosdns 执行失败: {e}")
        return None


def load_unpacked_file(file_path):
    """加载 mosdns 解包后的 txt 文件，返回域名列表"""
    domains = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # mosdns 输出格式:
            # domain:xxx  → 域名后缀匹配
            # full:xxx    → 完整域名匹配
            # regexp:xxx  → 正则
            # keyword:xxx → 关键词
            if line.startswith('domain:'):
                domains.append(('domain', line[7:]))
            elif line.startswith('full:'):
                domains.append(('full', line[5:]))
            elif line.startswith('regexp:'):
                domains.append(('regexp', line[7:]))
            elif line.startswith('keyword:'):
                domains.append(('keyword', line[8:]))
            else:
                # 无前缀 → 域名后缀匹配
                domains.append(('domain', line))
    return domains


# ============================================================
# 从 GitHub 源文件拉取分类 (支持 @cn)
# ============================================================

def fetch_source_list(category):
    """
    从 MetaCubeX GitHub 仓库拉取原始 .list 文件
    
    例如 steam@cn → https://.../steam%40cn.list
    返回 (category名大写, [(type, value)]) 或 None
    """
    # URL 编码 @ 为 %40
    filename = f"{category}.list"
    url_filename = filename.replace('@', '%40')
    url = f"{META_REPO_RAW}/{url_filename}"
    
    print(f"  [*] 从源文件拉取: geosite/{filename}")
    
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/plain',
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        print(f"  [!] 拉取失败 (HTTP {e.code}): {filename}")
        return None
    except Exception as e:
        print(f"  [!] 拉取失败: {e}")
        return None
    
    domains = parse_source_list(content)
    print(f"  [✓] 拉取 {category}: {len(domains)} 条")
    return (category.upper(), domains)


def parse_source_list(content):
    """
    解析 MetaCubeX 原始 .list 文件格式
    
    格式:
      # 注释
      +domain.com       → 域名后缀匹配 (domain类型)
      .domain.com       → 同上
      full:domain.com   → 完全匹配 (full类型)
      bare.domain.com   → 裸域名, 完全匹配 (full类型)
      regexp:pattern    → 正则
    """
    domains = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('!!'):
            continue
        
        if line.startswith('full:'):
            domains.append((3, line[5:]))  # type 3 = Full
        elif line.startswith('regexp:'):
            domains.append((1, line[7:]))  # type 1 = Regexp
        elif line.startswith('domain:'):
            pass  # domain: 前缀用于关键词匹配，跳过
        elif line.startswith('+'):
            value = line[1:]
            # +.alibaba → 去掉 + 和 . → alibaba (保持和下面 . 前缀处理一致)
            if value.startswith('.'):
                value = value[1:]
            domains.append((2, value))     # type 2 = Domain (后缀匹配)
        elif line.startswith('.'):
            domains.append((2, line[1:]))  # type 2 = Domain (后缀匹配)
        else:
            # 裸域名 → Full (精确匹配)
            domains.append((3, line))      # type 3 = Full
    
    return domains


# ============================================================
# 使用 Python 解析 geosite.dat
# ============================================================

def parse_geosite_with_python(geosite_path, wanted_categories=None):
    """使用 Python 解析 geosite.dat，返回 {category: [(type, value)]}"""
    print(f"[*] 使用 Python 解析 {geosite_path}...")
    
    with open(geosite_path, 'rb') as f:
        data = f.read()
    
    try:
        all_entries = ProtobufDecoder.decode_geosite_list(data)
    except Exception as e:
        print(f"[!] 解析失败: {e}")
        return None
    
    if wanted_categories:
        result = {}
        for cat in wanted_categories:
            # 支持模糊匹配: 如果 cat 在 all_entries 中直接取
            # 否则尝试全小写匹配
            if cat in all_entries:
                result[cat] = all_entries[cat]
            else:
                # 尝试不区分大小写
                for k, v in all_entries.items():
                    if k.lower() == cat.lower():
                        result[cat] = v
                        break
                else:
                    print(f"[!] 警告: 分类 '{cat}' 未在 geosite.dat 中找到")
        return result
    else:
        return all_entries


# ============================================================
# 域名转换与输出
# ============================================================

def convert_domains_to_dns_rules(domains, dns_ip):
    """
    将域名列表转换为 dns-rules.txt 格式的行
    
    绕过列表原则: 只放需要直连的域名，action 固定为 /nic
    未匹配的域名默认走隧道。
    
    domains: [(type, value), ...]
      type: 'domain' → 域名后缀匹配 (steampowered.com)
            'full'   → 完全匹配 (full:www.steampowered.com)
            'regexp' → 正则表达式 (regexp:^cdn.+\\.myqcloud\\.com$)
            'keyword' → 跳过 (不适合转换)
    dns_ip: DNS 服务器 IP
            '0.0.0.0' = 黑洞拦截 (广告)
    """
    lines = []
    skipped = 0
    is_blackhole = (dns_ip == '0.0.0.0')
    pad_width = 69  # 匹配原版 dns-rules.txt 格式, domain 部分填充到 69 字符
    
    for dtype, value in domains:
        if not value:
            continue
        
        # 兼容 protobuf 整数类型 (0=Plain, 1=Regex, 2=Domain, 3=Full)
        # 和 mosdns 字符串类型 ('domain', 'full', 'regexp', 'keyword')
        if dtype in (0, 2) or dtype == 'domain':
            entry = value
        elif dtype in (3,) or dtype == 'full':
            entry = f"full:{value}"
        elif dtype in (1,) or dtype == 'regexp':
            entry = f"regexp:{value}"
        else:
            # keyword 类型 → 跳过
            skipped += 1
            continue
        
        # 原版格式: 左部分填充到 69 字符 + /dns/nic
        line = entry.ljust(pad_width) + f"/{dns_ip}/nic"
        lines.append(line)
    
    return lines, skipped


def generate_dns_rules(mapping_config, geosite_data, output_path):
    """
    根据映射配置和 geosite 数据生成 dns-rules.txt (绕过列表)
    
    dns-rules.txt 本质是"绕过列表"——只放需要直连的域名。
    所有未匹配的域名默认走隧道，无需在文件中列出。
    
    mapping_config: {
        'header': str,               # 文件头注释
        'mappings': [                # 映射列表 (只放需要直连/拦截的分类)
            {
                'category': 'cn',    # geosite 分类名
                'dns': '223.5.5.5',  # DNS 服务器
            },
            {
                'category': 'category-ads-all',  # 广告拦截
                'dns': '0.0.0.0',   # 0.0.0.0 = 黑洞拦截
            },
            {
                'category': 'custom',  # 特殊: 来自本地文件
                'dns': '223.5.5.5',
                'domain_file': 'my_domains.txt',
            },
        ]
    }
    """
    all_lines = []
    seen = set()  # 去重
    stats = {}
    total_skipped = 0
    
    # 纯数据模式: 不输出注释/空行/分隔线，完全匹配原版 dns-rules.txt
    for mapping in mapping_config.get('mappings', []):
        category = mapping.get('category', '')
        dns_ip = mapping.get('dns', '223.5.5.5')
        
        # 处理自定义域名文件
        if category == 'custom' and mapping.get('domain_file'):
            domain_file = mapping['domain_file']
            if os.path.exists(domain_file):
                custom_domains = []
                with open(domain_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            custom_domains.append(('domain', line))
                lines, skipped = convert_domains_to_dns_rules(
                    custom_domains, dns_ip
                )
                for l in lines:
                    if l not in seen:
                        all_lines.append(l)
                        seen.add(l)
                total_skipped += skipped
                stats[category] = {'total': len(lines), 'skipped': skipped}
            else:
                print(f"[!] 自定义域名文件不存在: {domain_file}")
            continue
        
        # 处理 geosite 分类
        if category in geosite_data:
            domains = geosite_data[category]
            lines, skipped = convert_domains_to_dns_rules(domains, dns_ip)
            for l in lines:
                if l not in seen:
                    all_lines.append(l)
                    seen.add(l)
            total_skipped += skipped
            stats[category] = {'total': len(lines), 'skipped': skipped}
        else:
            # 尝试大小写不敏感匹配
            found = False
            for k, v in geosite_data.items():
                if k.lower() == category.lower():
                    lines, skipped = convert_domains_to_dns_rules(v, dns_ip)
                    for l in lines:
                        if l not in seen:
                            all_lines.append(l)
                            seen.add(l)
                    total_skipped += skipped
                    stats[category] = {'total': len(lines), 'skipped': skipped}
                    found = True
                    break
            if not found:
                print(f"[!] 警告: geosite 分类 '{category}' 未找到")
                stats[category] = {'total': 0, 'skipped': 0}
    
    # 处理手工维护的正则表达式规则
    pad_width = 69
    for re_entry in mapping_config.get('regexps', []):
        pattern = re_entry.get('pattern', '')
        dns_ip = re_entry.get('dns', '223.5.5.5')
        if pattern:
            entry = f"regexp:{pattern}"
            line = entry.ljust(pad_width) + f"/{dns_ip}/nic"
            if line not in seen:
                all_lines.append(line)
                seen.add(line)
    
    if mapping_config.get('regexps'):
        stats['regexps'] = {'total': len(mapping_config['regexps']), 'skipped': 0}
    
    # 写入文件 (CRLF, 原版格式)
    content = '\r\n'.join(all_lines) + '\r\n'
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(content.encode('utf-8'))
    
    # 打印统计
    print(f"\n[✓] 已生成: {output_path}")
    print(f"    总行数: {len(all_lines)}")
    print(f"    跳过 (regexp/keyword): {total_skipped}")
    print(f"\n    分类统计:")
    for cat, s in stats.items():
        print(f"      {cat}: {s['total']} 条规则")
    
    return len(all_lines)


# ============================================================
# 主流程
# ============================================================

def load_mapping_config(config_path):
    """加载映射配置文件（YAML 或 JSON）"""
    if not os.path.exists(config_path):
        print(f"[!] 映射文件不存在: {config_path}")
        return None
    
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 尝试 YAML 优先
    try:
        import yaml
        config = yaml.safe_load(content)
        print(f"[✓] 已加载 YAML 映射配置: {config_path}")
        return config
    except ImportError:
        pass
    except yaml.YAMLError:
        pass
    
    # 回退 JSON
    try:
        config = json.loads(content)
        print(f"[✓] 已加载 JSON 映射配置: {config_path}")
        return config
    except json.JSONDecodeError:
        pass
    
    print(f"[!] 无法解析映射配置: {config_path} (需要 YAML 或 JSON)")
    return None


def list_categories(geosite_path):
    """列出 geosite.dat 中所有可用的分类"""
    print(f"[*] 读取 {geosite_path} 中的分类列表...")
    
    # 先尝试 mosdns
    with tempfile.TemporaryDirectory() as tmpdir:
        txt_files = unpack_with_mosdns(geosite_path, tmpdir)
        if txt_files:
            print(f"\n[✓] geosite.dat 可用分类 (共 {len(txt_files)} 个):")
            categories = sorted(txt_files.keys())
            for cat in categories:
                # 统计每个分类的域名数
                domains = load_unpacked_file(txt_files[cat])
                domain_count = len([d for d in domains if d[0] in ('domain', 'full')])
                print(f"  {cat:30s} ({domain_count} 域名)")
            return categories
    
    # 回退 Python 解析
    data = parse_geosite_with_python(geosite_path)
    if data:
        print(f"\n[✓] geosite.dat 可用分类 (共 {len(data)} 个):")
        categories = sorted(data.keys())
        for cat in categories:
            total = len(data[cat])
            plain = len([d for d in data[cat] if d[0] == 0 or d[0] == 2])
            print(f"  {cat:30s} ({plain} 域名 / {total} 总条目)")
        return categories
    
    print("[!] 无法读取 geosite.dat")
    return []


def main():
    parser = argparse.ArgumentParser(
        description="geosite2dns.py - 将 geosite 分类转换为 openppp2 dns-rules.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════════════╗
║                        使用示例                                      ║
╚══════════════════════════════════════════════════════════════════════╝

  1) GitHub 源文件方式 (推荐，支持 @cn 子分类)
     python geosite2dns.py -m geosite-mapping.yaml -o dns-rules.txt

  2) 指定 geosite.dat 文件
     python geosite2dns.py -m geosite-mapping.yaml -g ./geosite.dat -o dns-rules.txt

  3) 自动下载 geosite.dat
     python geosite2dns.py -m geosite-mapping.yaml -o dns-rules.txt

  4) 列出 geosite.dat 中所有可用分类
     python geosite2dns.py -g ./geosite.dat --list-categories

  5) 使用 mosdns 解包后的目录
     mosdns v2dat unpack-domain -o ./geosite/ ./geosite.dat
     python geosite2dns.py -m geosite-mapping.yaml -x ./geosite/ -o dns-rules.txt

╔══════════════════════════════════════════════════════════════════════╗
║                      YAML 映射配置格式                                 ║
╚══════════════════════════════════════════════════════════════════════╝

  from_source: true          # true=GitHub 源文件, false=geosite.dat
                             # 优先级: CLI > YAML

  mappings:
    - category: cn           # geosite 分类名
      dns: 223.5.5.5         # 直连 DNS; 0.0.0.0 = 黑洞拦截
    - category: custom       # 本地文件
      dns: 223.5.5.5
      domain_file: my_domains.txt

  regexps:                   # 手工维护的正则 (可选)
    - pattern: '^cdn\\d-.*\\.myqcloud\\.com$'
      dns: 223.5.5.5

╔══════════════════════════════════════════════════════════════════════╗
║                        工作原理                                       ║
╚══════════════════════════════════════════════════════════════════════╝

  dns-rules.txt 是绕过列表——只放需要直连(不走隧道)的域名。
  未匹配到的域名默认全走隧道，无需在文件中列出。

  输出格式: 每条 83 bytes
    domain部分.ljust(69) + /dns-ip/nic + CRLF
  纯数据模式: 无注释、无空行、无分隔线
"""
    )
    parser.add_argument('-m', '--mapping', default='geosite-mapping.yaml',
                        help='映射配置文件路径 (默认: geosite-mapping.yaml)')
    parser.add_argument('-o', '--output', default='dns-rules.txt',
                        help='输出文件路径 (默认: dns-rules.txt)')
    parser.add_argument('-g', '--geosite-dat',
                        help='geosite.dat 文件路径 (留空自动下载)')
    parser.add_argument('-x', '--extracted-dir',
                        help='mosdns v2dat 解包后的目录 (跳过 geosite.dat 解析)')
    parser.add_argument('--from-source', action='store_true',
                        help='从 MetaCubeX GitHub 源文件拉取 (支持 @cn 子分类)')
    parser.add_argument('--list-categories', action='store_true',
                        help='列出 geosite.dat 中所有可用分类')
    parser.add_argument('--keep-temp', action='store_true',
                        help='保留临时文件 (调试用)')
    parser.add_argument('--no-download', action='store_true',
                        help='不从网络下载 geosite.dat')
    
    args = parser.parse_args()
    
    # 如果只是列出分类
    if args.list_categories:
        if not args.geosite_dat:
            print("[!] 需要提供 geosite.dat 路径 (--geosite-dat)")
            return 1
        list_categories(args.geosite_dat)
        return 0
    
    # 加载映射配置
    config = load_mapping_config(args.mapping)
    if config is None:
        print(f"[!] 请创建映射配置文件: {args.mapping}")
        print("    参考: python geosite2dns.py --help")
        return 1
    
    # 获取需要的分类列表
    mappings = config.get('mappings', [])
    needed_categories = set()
    for m in mappings:
        cat = m.get('category', '')
        if cat and cat != 'custom':
            needed_categories.add(cat)
    
    geosite_data = OrderedDict()
    
    # 方式 0: 从 GitHub 源文件拉取 (支持 @cn)
    # 优先级: CLI --from-source > CLI -g > YAML from_source
    use_from_source = config.get('from_source', False)
    if args.from_source:
        use_from_source = True
    elif args.geosite_dat or args.extracted_dir:
        use_from_source = False
    if use_from_source:
        print(f"[*] 从 MetaCubeX GitHub 源文件拉取分类...")
        for m in mappings:
            cat = m.get('category', '')
            if not cat or cat == 'custom':
                continue
            result = fetch_source_list(cat)
            if result:
                name, domains = result
                geosite_data[cat] = domains
        if not geosite_data:
            print("[!] 未能从源文件拉取任何数据")
            return 1
    
    # 方式 1: 使用 mosdns 解包后的目录
    elif args.extracted_dir:
        print(f"[*] 从解包目录加载: {args.extracted_dir}")
        for m in mappings:
            cat = m.get('category', '')
            if not cat or cat == 'custom':
                continue
            txt_path = os.path.join(args.extracted_dir, f"geosite_{cat}.txt")
            alt_path = os.path.join(args.extracted_dir, f"{cat}.txt")
            
            found_path = None
            if os.path.exists(txt_path):
                found_path = txt_path
            elif os.path.exists(alt_path):
                found_path = alt_path
            
            if found_path:
                domains = load_unpacked_file(found_path)
                geosite_data[cat] = domains
                print(f"[✓] 已加载 {cat}: {len(domains)} 条目")
            else:
                print(f"[!] 未找到分类文件: {cat}")
    
    # 方式 2: 使用 Python 解析 geosite.dat
    elif args.geosite_dat:
        data = parse_geosite_with_python(args.geosite_dat, needed_categories)
        if data:
            geosite_data = data
    else:
        # 方式 3: 自动下载
        if args.no_download:
            print("[!] 未指定 geosite.dat 且 --no-download，无法继续")
            return 1
        
        print("[*] 未指定 geosite.dat，尝试自动下载...")
        geosite_path = download_geosite()
        if not geosite_path:
            print("[!] 下载失败，请手动下载 geosite.dat")
            return 1
        
        # 先尝试 mosdns 解包（速度更快）
        if not geosite_data:
            tmpdir = tempfile.mkdtemp() if args.keep_temp else tempfile.mkdtemp()
            txt_files = unpack_with_mosdns(geosite_path, tmpdir)
            if txt_files:
                for cat in needed_categories:
                    if cat in txt_files:
                        domains = load_unpacked_file(txt_files[cat])
                        geosite_data[cat] = domains
            elif not args.keep_temp:
                import shutil
                shutil.rmtree(tmpdir, ignore_errors=True)
        
        # 回退 Python 解析
        if not geosite_data:
            data = parse_geosite_with_python(geosite_path, needed_categories)
            if data:
                geosite_data = data
    
    if not geosite_data:
        print("[!] 未能获取任何 geosite 数据")
        return 1
    
    # 生成 dns-rules.txt
    generate_dns_rules(config, geosite_data, args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
