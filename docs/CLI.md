# 命令行手册

```
voxhound <子命令> [选项]
```

| 子命令 | 用途 |
|---|---|
| `demo` | 完整模拟会话，不需要权限、不需要网络 |
| `analyze 文件` | 离线分析 `.pcap` / `.pcapng` / gzip 压缩包 |
| `sniff -i 网卡` | 在线抓包（Npcap/libpcap，或 Linux AF_PACKET） |
| `extract 文件 -o 输出` | 把命中过滤条件的帧写出为新 pcap |
| `interfaces` | 列出网卡与当前抓包后端 |
| `rules [--check 路径]` | 列出规则、校验规则文件或目录 |
| `gui [目标]` | 启动桌面端 |
| `version` | 版本、Python、平台、libpcap 状态（等价于 `--version`） |

> 英文原文见 [`CLI.en.md`](CLI.en.md)。

## 输出选项（analyze / sniff / demo 通用）

| 选项 | 产物 |
|---|---|
| `--report 报告.html` | 自包含 HTML 报告（内联 CSS + SVG，零网络请求） |
| `--markdown 摘要.md` | 紧凑 Markdown 摘要，适合工单与 PR |
| `--json 结果.json` | 完整 JSON（会话、事件、发现、产物、主机） |
| `--ndjson 事件.ndjson` | 一行一个 JSON，便于接日志管道 |
| `--csv 会话.csv` | 会话表 CSV |
| `--store 会话.db` | SQLite（会话、事件、发现、产物元数据） |
| `--artifacts 目录` | 还原出的载荷写入磁盘（WAV、图片、文档） |
| `-w, --write 抓包.pcap` | 分析的同时把抓到的帧镜像成 pcap |
| `--rules 路径` | 追加规则文件或目录 |
| `--no-rules` / `--no-heuristics` | 关闭内置规则 / 行为检测 |
| `--quiet` | 不输出进度 |

## `analyze`

```bash
voxhound analyze capture.pcapng \
  --filter "tcp port 443" \
  --verify-checksums \
  --report report.html --store session.db --artifacts carved/
```

| 选项 | 含义 |
|---|---|
| `--filter 表达式` | BPF 风格过滤子集（见下） |
| `--verify-checksums` | 校验 IPv4/TCP/UDP 校验和（更慢） |
| `--replay --speed N` | 按原始节奏回放文件，便于演示在线效果 |

## `sniff`

```bash
sudo voxhound sniff -i eth0 --filter "udp" --duration 60 -w live.pcap --report live.html
```

| 选项 | 含义 |
|---|---|
| `-i, --interface` | 网卡名（`voxhound interfaces` 可列出） |
| `--snaplen` | 快照长度（字节，默认 262144） |
| `--buffer-mb` | 内核抓包缓冲（默认 16 MB） |
| `--no-promisc` | 不请求混杂模式 |
| `--raw-socket` | 仅 Linux：用 AF_PACKET 替代 libpcap（需 `CAP_NET_RAW`） |
| `--duration` | N 秒后停止（Ctrl-C 也会优雅收尾） |

## `demo`

```bash
voxhound demo --demo-duration 30 --speed 2 --seed 7 --report demo.html --artifacts out/
```

生成确定性流量（TLS、h2c、WebSocket、G.711 通话、QUIC Initial、端口扫描、周期回连），并跑完整条管线。相同 `--seed` 生成字节级一致的结果，回归对比靠它。

## `extract`

```bash
voxhound extract big.pcap -o tls.pcap --filter "tcp port 443" --limit 5000
```

对文件做二次遍历：解码、匹配、按原字节写出。常量内存，能处理比内存还大的抓包。

## 过滤器语法

libpcap 语法的严格子集，同一个字符串既可用于内核过滤（在线），也可用于 Python 谓词（离线）：

```
tcp | udp | icmp | icmp6 | arp | ip | ip6
[src|dst] host 10.0.0.1
[src|dst] net 10.0.0.0/8
[src|dst] port 443 | portrange 8000-8100
len > 1000 | contains "SILK"
not X | X and Y | X or Y | ( X )
```

`tcp port 443` 不写 `and` 也可以（隐式与），与 tcpdump 一致。语法之外的写法会被拒绝并指出位置，静默匹配一切的过滤器比报错更危险。

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 完成，无高危发现 |
| `1` | 完成，存在高危发现 |
| `2` | 完成，存在严重发现 |
| `3` | 参数错误、文件不存在、抓包源不可用，或桌面端缺少 PySide6 |
| `130` | 被中断（Ctrl-C） |

## 环境变量

| 变量 | 作用 |
|---|---|
| `NO_COLOR` | 关闭命令行 ANSI 颜色 |

## CI 用法

```bash
# nightly 抓包里出现严重发现就让构建失败
voxhound analyze nightly.pcap --quiet --report nightly.html --json nightly.json || exit $?

# 把传感器写的任意格式转换成统一 pcap
voxhound analyze sensor.pcapng --write normalised.pcap --report sensor.html --quiet
```
