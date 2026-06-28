# dns-rules_geosite_generator

将 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 geosite 分类数据转换为 [openppp2](https://github.com/liulilittle/openppp2) 的 `dns-rules.txt` 绕过列表格式。

---

## 原理

`dns-rules.txt` 是一个**绕过列表（Bypass List）**——只存放需要**直连**（不走隧道）的域名规则。

- ✅ 文件中匹配到的域名 → 使用指定的 DNS 直连解析
- ⏩ 未匹配到的域名 → 默认全部走隧道，无需在文件中列出

> 输出格式为纯数据模式，无注释、无空行、无分隔线，每条记录固定 **83 bytes**：
> ```
> domain部分.ljust(69) + /dns-ip/nic + CRLF
> ```

---

## 功能特性

- **三种数据源支持**：
  - **GitHub 源文件**（推荐）：直接从 MetaCubeX 仓库拉取原始 `.list` 文件，支持 `@cn` 子分类（如 `category-games@cn`）
  - **geosite.dat Protobuf**：解析 MetaCubeX 发布的二进制 protobuf 文件，一次下载可离线使用
  - **mosdns 解包目录**：使用 `mosdns v2dat` 解包后的本地目录
- **自动下载**：可自动下载并校验 geosite.dat（含 SHA256 校验）
- **内置 Protobuf 解码器**：纯 Python 实现的最小 protobuf 解析器，无需外部依赖
- **灵活映射配置**：通过 YAML 配置文件定义分类 → DNS 的映射关系
- **自定义域名**：支持加载本地域名文件
- **正则表达式规则**：支持手工维护的正则规则
- **列出分类**：可列出 geosite.dat 中所有可用分类及其域名数量

---

## 快速开始

```bash
# 方式 1: GitHub 源文件方式（推荐，支持 @cn 子分类）
python geosite2dns.py -m geosite-mapping.yaml -o dns-rules.txt --from-source

# 方式 2: 自动下载 geosite.dat（无需网络时离线可用）
python geosite2dns.py -m geosite-mapping.yaml -o dns-rules.txt

# 方式 3: 指定本地 geosite.dat 文件
python geosite2dns.py -m geosite-mapping.yaml -g ./geosite.dat -o dns-rules.txt

# 方式 4: 使用 mosdns 解包后的目录
mosdns v2dat unpack-domain -o ./geosite/ ./geosite.dat
python geosite2dns.py -m geosite-mapping.yaml -x ./geosite/ -o dns-rules.txt
```

### 列出 geosite.dat 中的分类

```bash
python geosite2dns.py -g ./geosite.dat --list-categories
```

---

## YAML 映射配置

配置文件 `geosite-mapping.yaml` 控制哪些分类写入绕过列表以及使用的 DNS：

```yaml
# 数据源方式
from_source: true   # true = GitHub 源文件（推荐）; false = geosite.dat

# 分类映射列表（只放需要直连/拦截的分类）
mappings:
  - category: cn                     # geosite 分类名
    dns: 223.5.5.5                   # 直连 DNS; 0.0.0.0 = 黑洞拦截广告

  - category: apple
    dns: 223.5.5.5

  - category: custom                 # 自定义本地域名文件
    dns: 223.5.5.5
    domain_file: my_domains.txt      # 每行一个域名

# 手工维护的正则规则（可选）
regexps:
  - pattern: '.+\\.awsdns-cn-[0-9][0-9]\\.(biz|com|net|top)$'
    dns: 223.5.5.5
```

### 常见场景

| 场景 | 配置 |
|------|------|
| **国内域名直连** | `category: cn`, `dns: 223.5.5.5` |
| **广告拦截** | `category: category-ads-all`, `dns: 0.0.0.0` |
| **自定义 DNS** | 在 mapping 中指定不同的 DNS IP |
| **本地文件** | `category: custom` + `domain_file` |

---

## 命令行参数

| 参数 | 说明 |
|------|------|
| `-m, --mapping` | 映射配置文件路径（默认: `geosite-mapping.yaml`） |
| `-o, --output` | 输出文件路径（默认: `dns-rules.txt`） |
| `-g, --geosite-dat` | geosite.dat 文件路径（留空自动下载） |
| `-x, --extracted-dir` | mosdns v2dat 解包后的目录 |
| `--from-source` | 从 GitHub 源文件拉取（支持 `@cn` 子分类） |
| `--list-categories` | 列出 geosite.dat 中所有可用分类 |
| `--keep-temp` | 保留临时文件（调试用） |
| `--no-download` | 不从网络下载 geosite.dat |

---

## 输出文件示例

生成的 `dns-rules.txt` 每行格式（domain 部分左对齐填充至 69 字符）：

```
cn                                                                   /223.5.5.5/nic
full:www.example.com                                                 /223.5.5.5/nic
regexp:^cdn\d-.+\.myqcloud\.com$                                     /223.5.5.5/nic
```

---

## 部署到服务器

```bash
# 上传 dns-rules.txt 到服务器
scp dns-rules.txt root@your-server:/opt/ppp/

# 重启 openppp2 服务
ssh root@your-server systemctl restart openppp2
```

---

## 项目文件结构

```
dns-rules_geosite_generator/
├── geosite2dns.py           # 主要转换脚本
├── geosite-mapping.yaml     # YAML 映射配置文件
├── dns-rules.txt            # 输出的绕过列表
└── README.md                # 本文件
```

---

## 依赖

- **Python 3.6+**
- **PyYAML**（推荐，用于解析 YAML 配置；回退支持 JSON）
- **mosdns**（可选，用于 `-x` 解包目录方式）

---

## 许可证

本项目遵循开源许可证。请参考具体源代码文件中的许可证声明。
