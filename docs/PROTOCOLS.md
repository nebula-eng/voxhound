# 协议支持矩阵

VoxHound 解析什么、只识别什么、边界在哪。未标注为「解析」的协议，一律按不透明字节处理。

> 英文原文见 [`PROTOCOLS.en.md`](PROTOCOLS.en.md)。

## 链路层

| 链路类型 | 状态 | 说明 |
|---|---|---|
| 以太网（1） | 解析 | 叠加的 802.1Q / 802.1ad 标签保留在 `Packet.vlan` |
| Linux cooked v1 / v2（113/276） | 解析 | 对应 `tcpdump -i any` |
| BSD loopback / NULL（0） | 解析 | 自动识别地址族 |
| 裸 IP（101）、IPv4（228）、IPv6（229） | 解析 | |
| MPLS（0x8847/0x8848） | 解封装 | 标签栈走到栈底 |
| PPPoE 会话（0x8864） | 解封装 | PPP 协议 → IPv4/IPv6 |
| 802.3 LLC/SNAP | 解析 | 否则按不透明处理 |
| 802.11 / radiotap（105/127） | 不支持 | 监听模式 Wi-Fi 不在范围内 |

## 网络层

| 协议 | 状态 | 细节 |
|---|---|---|
| IPv4 | 解析 | 选项解析、可选头部校验和、分片重组（先到先得、30 秒、4 096 条） |
| IPv6 | 解析 | 扩展头链（HopByHop、Routing、Fragment、DestOpts）逐层走通；分片重组 |
| ARP | 解析 | 请求/应答、发送方与目标地址 |
| ICMP / ICMPv6 | 解析 | echo、不可达、超时、包过大 |
| GRE / ESP / AH | 识别 | 不解载荷（ESP 本身就是加密的） |

## 传输层

| 协议 | 状态 | 细节 |
|---|---|---|
| TCP | 解析 | 完整选项（MSS、WS、SACK、时间戳、TFO）、选项顺序签名、标志位、乱序重组、重传与重复统计、空洞检测、32 位回绕 |
| UDP | 解析 | 按长度字段截取载荷 |
| SCTP | 识别 | 不重组 |
| QUIC | 见下 | 基于 UDP，识别长/短头部 |

## 应用层

### TLS（TCP）

| 项目 | 状态 |
|---|---|
| ClientHello：SNI、ALPN、版本、套件、扩展、组、签名算法 | 解析 |
| ServerHello：协商版本、套件、ALPN | 解析 |
| 证书链：主体、签发者、CN/O、SAN、有效期、签名算法 | 解析（纯结构遍历，不做签名验证） |
| JA3、JA4、JA4S | 计算 |
| 告警（close_notify、handshake_failure、unrecognized_name…） | 解析 |
| 加密应用数据 | 仅计数（大小、方向） |
| TLS 1.3 记录解密 | 未实现（路线图：SSLKEYLOGFILE） |

### QUIC

| 项目 | 状态 |
|---|---|
| 长头部：版本、DCID、SCID、token、包序号 | 解析 |
| Initial 包解密（RFC 9001，密钥由 DCID 推导） | 解析，每流最多 6 个 Initial / 8 KiB |
| CRYPTO 帧 → TLS ClientHello → SNI、ALPN、JA4Q | 解析 |
| 服务端 Initial 中的 ServerHello | 解析 |
| 0-RTT / Handshake / 1-RTT | 识别、计数，不解密 |
| 版本协商、Retry | 识别 |

### HTTP

| 项目 | 状态 |
|---|---|
| HTTP/1.0–1.1 请求行/状态行与头部 | 解析 |
| `Content-Length`、`Transfer-Encoding: chunked`、trailer | 解析 |
| 单连接流水线请求 | 解析（按方向维护状态） |
| Upgrade → WebSocket | 识别并切换解析器 |
| 正文还原（按魔数判断真实类型） | 解析 |
| HTTP/2（h2c 前言）帧：HEADERS、CONTINUATION、DATA、SETTINGS、PING、GOAWAY、RST_STREAM | 解析 |
| HPACK：静态表、动态表、整数/字符串、Huffman | 解析 |
| 基于 TLS 的 HTTP/2 | 不解（已加密） |

### WebSocket

帧（文本、二进制、关闭、ping、pong）、掩码、分片、消息重组。超过 8 KiB 的 base64 载荷会被解码并还原。

### DNS

| 项目 | 状态 |
|---|---|
| 头部、问题、回答、授权、附加 | 解析 |
| 名称压缩指针（带环路保护） | 解析 |
| A、AAAA、CNAME、NS、PTR、MX、TXT、SOA、SRV、SVCB/HTTPS | 解析 |
| EDNS0 / OPT | 通过附加段识别 |
| 查询标签的 DGA 打分 | 计算 |
| DNS over TCP（2 字节长度前缀） | 解析 |
| DoH / DoT | 在 TLS 内，只有元数据 |

### 语音与媒体

| 项目 | 状态 |
|---|---|
| RTP 头部、CSRC 列表、扩展头、填充 | 解析 |
| RTP 重排（256 包窗口）、RFC 3550 抖动、丢包、重复 | 计算 |
| G.711 µ-law / A-law → 16 位 PCM → WAV | 解析并导出 |
| Opus / G.722 / AAC 载荷 | 导出原始数据与时间信息（无解码器） |
| RTCP SR/RR/SDES/BYE | 识别并计数 |
| SIP：请求/状态行、Call-ID、From/To、User-Agent、SDP `m=`/`c=`/`rtpmap` | 解析 |
| SDP → RTP 端口关联 | 记录在会话上，不自动合并 |
| RTMP 握手 | 识别 |

### 基础设施类

| 协议 | 状态 |
|---|---|
| STUN：绑定请求/响应、USERNAME、SOFTWARE、XOR-MAPPED-ADDRESS | 解析 |
| MQTT 3.1.1/5.0：CONNECT、CONNACK、PUBLISH、SUBSCRIBE | 解析 |
| SSH、FTP、SMTP、POP3、IMAP、Redis、RTMP | 横幅识别 |

## 已知限制

1. 重组从抓到的第一个字节开始。 中途开始的抓包无法回看更早的字节。
2. 非 HTTP 流只扫描每个方向的前 64 KiB。 从任意 TCP 流里还原大体积媒体是另一个问题（见路线图）。
3. 仅在 `--verify-checksums` 时校验校验和；在线抓包默认跳过，把 CPU 留给重组。
4. 不做跨 VLAN 或跨隧道的 IP 重组，除 MPLS/PPPoE 外不做隧道解封装。
5. 加密载荷只计数、不窥探，唯一例外是 QUIC Initial，其密钥本就属于协议的一部分。
