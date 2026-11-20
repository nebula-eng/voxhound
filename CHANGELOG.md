# 变更记录

本文件记录所有值得注意的改动。格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-11-16

首个公开版本。引擎、桌面端与文档一并交付。

### 引擎

- 抓包：经典 pcap（双字节序、µs/ns）与 pcapng（SHB/IDB/EPB/SPB/ISB、`if_tsresol`、丢包计数），
  gzip 透明解压；通过 ctypes 运行时绑定 Npcap/libpcap（immediate mode、缓冲调优）；
  Linux `AF_PACKET` 兜底（无 libpcap 也能跑）；确定性流量模拟器。
- 解码：以太网（叠加 VLAN、MPLS、PPPoE、LLC/SNAP）、Linux SLL/SLL2、loopback、裸 IP；
  IPv4 分片与可选校验和；IPv6 扩展头链与分片重组；TCP 完整选项解析；UDP；ICMP/ICMPv6；ARP。
- TCP 重组：有符号 32 位序号算术（回绕安全）、乱序缓冲、重叠「先到先得」、
  重传/重复统计、空洞检测与超时恢复。
- 应用层：TLS 1.2/1.3（SNI、ALPN、版本、套件、证书链与 X.509 身份）、
  HTTP/1.1（chunked、流水线、正文还原）、HTTP/2 与完整 HPACK 解码器
  （静态/动态表 + 由 RFC 7541 生成的 Huffman 表）、WebSocket、DNS（压缩指针、EDNS、DGA 打分）、
  QUIC Initial 包解密（纯 Python AES-128-GCM + HKDF，RFC 9001）、RTP/RTCP、SIP/SDP、STUN、MQTT、横幅类协议。
- 语音：按 SSRC 的 RTP 流，RFC 3550 抖动与丢包、重排缓冲，G.711 µ-law/A-law 解码为 PCM 并写出
  可播放 WAV；无法解码的编码导出原始载荷。
- 情报：JA4、JA4S、JA3、JA4T、p0f 风格系统提示、X.509 结构解析与主机名匹配。
- 检测：16 条内置 JSON 规则 + 四类行为检测（端口扫描、周期回连（变异系数）、DNS 隧道、数据外传）。
- 输出：自包含 HTML 报告（内联 SVG 图表）、Markdown、JSON、NDJSON、CSV、
  二次遍历的过滤导出 pcap、SQLite 会话库、产物导出。

### 桌面端

- 六页 PySide6 控制台：仪表盘、会话、数据包、媒体、发现、设置。
- 自绘图表（面积、圆环、条形、波形），不引入任何图表依赖。
- 跨线程批量信号、有界模型、实时抓包控制、快捷键。
- 内置演示数据源，没有抓包驱动也能完整使用。

### 质量

- 82 个测试，引擎语句覆盖率 72%（界面按设计排除）。
- 密码学锚定 FIPS-197 与 NIST GCM 向量；JA4 锚定 FoxIO 公布的 Chrome 套件哈希；
  Huffman 表用 Kraft 等式与往返编解码验证。
- `ruff` 全绿；CI 覆盖 Linux / Windows / macOS 与 Python 3.10–3.13。

### 发布前打磨

- 界面：六页全中文；严重度改为着色胶囊，行选中改为低饱和深蓝；
  会话详情四列布局；数据包页摘要列不再被「应用」列挤窄；媒体页表格收紧、预览放大；
  设置页改为「抓包 / 关于」双卡，规则表新增「说明」列与严重度胶囊。
- 媒体：图片产物直接按原图预览；语音用 `QAudioSink` 直接播放 PCM，
  不依赖 Qt 的多媒体解码插件（很多 pip 安装并不带），带播放头、暂停与重播。
  演示用 WAV 改为三段语音包络，波形不再是实心色块。
- 语义：仪表盘「协议事件」副标题改为 DNS/TLS 等构成，「产物」副标题改为语音/图片计数；
  会话结束用报告回填会话表，状态与「活跃会话」不再自相矛盾。
- 修复：HTTP/1.1 chunked 正文跨 TCP 段时，把分块长度误当 Content-Length，
  导致提前完成并雕刻出截断文件；现按分块帧续传，回归测试覆盖。
- 修复：8 位十六进制色值被 Qt 解析为 `#AARRGGBB`，胶囊底色发绿；统一改用 `rgba()`。
- 修复：Windows 的 `pythonw`/`voxhound-gui` 下 `sys.stdout` 为 `None`，CLI 在导入期调用
  `sys.stdout.isatty()` 直接崩溃，双击启动因此打不开窗口；已改为安全探测并加回归测试。
- 启动：新增 `VoxHound.cmd`，双击开界面，把抓包文件拖上去直接打开并分析；
  `voxhound gui <文件>` 现在会预选该文件并自动开始分析。
- 在线抓包（Npcap 1.90 / Windows 11 Wi-Fi 实测）：
  修复 `--duration` 在持续有包时永不触发（截止时间原本只在空读分支检查）；
  合法但超出引擎子集的 BPF（如 `tcp[tcpflags] & tcp-syn != 0`）不再被用户态解析器拒绝，
  实时抓包只由内核过滤，字符串仅用于报告记录；
  网卡列表按真实适配器优先排序，Wi-Fi 标注「默认」，避免误选 WAN Miniport / 蓝牙。

### 发布前的全面审查

- 修复：WebSocket 音频判定里有一段永不成立的分支（`bytes` 与 `str` 前缀比较），
  浏览器把 Opus/SILK 包成 base64 文本帧时完全识别不到；现按「base64 前缀 + 可打印比例」判定，
  并给无起始帧的续帧（RFC 6455 §5.4 协议错误）单独告警，不再伪造一条文本消息。
- 修复：MQTT 遇到畸形 CONNECT（协议名长度越界）会抛 `struct.error` 打断解析；
  QoS 1/2 的 PUBLISH 未跳过 2 字节报文标识，导致载荷长度多算 2 字节、产物偏移错误；
  剩余长度跨段时把半个 varint 当成帧长。三处均已修正并补测试；客户端 ID 不再混入 HTTP Host 列表。
- 修复：STUN 的 IPv6 `XOR-MAPPED-ADDRESS` 用「cookie + 12 字节零」当掩码，
  而 RFC 5389 §15.2 要求「cookie + 事务 ID」，后 12 字节地址一直算错。
  用 RFC 5769 向量与自造往返覆盖 IPv4/IPv6 两种地址。
- 修复（发布阻断）：`--json` 会在写任何文件之前崩溃。`Report.summary()` 对告警用属性访问，
  而报告里存的是 dict，于是一次带 `--json` 的运行连 HTML 报告都不会产出；
  README 与 CI 的示例命令正是这个组合。已修正并加「五种格式同跑」回归测试。
- 修复：`voxhound gui` 缺少 PySide6 时退出码为 0（脚本无法判断失败），现为 3。
- 修复：`ruff` 中文对齐遗漏两处，`voxhound rules` 的级别/范围列与 `interfaces` 的状态列。
  网卡列表改为「状态 + 适配器名 + 设备路径 + 地址」四行，默认网卡带 `← 默认` 标记。
- 修复：发布工作流的 PyPI 步骤原本把 `secrets` 放进 step 级 `if`，而该上下文在 `if` 里不可用；
  改为作业级 `env` 承载 token，条件读 `env.PYPI_API_TOKEN`。
  issue 模板因未加引号的反引号是非法 YAML，GitHub 会拒绝渲染整张表单。
- 修复：`pyproject.toml` 的 package-data 指向不存在的 `plugins/`、`intel/data/`，构建告警；
  改为只声明真实存在的 `rules/*.json` 与 `py.typed`（补上 PEP 561 标记）。
- 持久化：会话导出一直缺少 JA3 列（引擎算了但没落库）。新增 `ja3` 列、schema 升至 2，
  并对旧库做增量迁移（`ALTER TABLE ADD COLUMN`），已有案件库不会被重建。
- 可维护性：删除 22 个未被任何代码或文档引用的模块级函数；`ruff format` 全量统一（49 个文件）。
- 测试：新增 `tests/test_crypto.py`（FIPS-197 / NIST GCM / RFC 5869 / RFC 9001 向量）、
  旧库迁移、MQTT 三处边界、STUN IPv4/IPv6、WebSocket 分片与音频判定，共 78 项；
  资源泄漏（未关闭的文件/数据库）现在直接判失败。

### 规则加载

- 修复：单个规则对象（最常见的手写形式）会被静默忽略。加载器把 dict 当列表遍历，
  取到的是键名，于是「载入 0 条」却毫无提示。现在三种结构（单条 / 数组 / `rules` 数组）都支持。
- 修复：结构无法识别时直接报错并返回 3，不再默默跳过；缺 `id` 或字段类型错误的规则
  逐条列在 stderr；一条都没解析出来时额外告警。
- 这条比崩溃更值得记：检测器静默失效很难被发现，写了规则却从不触发，等于没有规则。

### 已知限制

- 加密载荷保持加密（例外：QUIC Initial，其密钥按协议公开）。
- 不做 GeoIP/ASN/信誉丰富化，结论必须能离线复现。
- 不做 802.11 radiotap 解析。
- 纯 Python AES-GCM 有每流上限，它是握手读取器。
- TLS 1.3 的 `SSLKEYLOGFILE` 解密在路线图上。

[1.0.0]: https://github.com/nebula-eng/voxhound/releases/tag/v1.0.0
