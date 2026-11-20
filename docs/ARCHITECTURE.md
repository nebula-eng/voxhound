# 架构说明

这份文档解释代码为什么长成这样。评审补丁时，下面这些不变式就是检查清单。

英文版见 [`ARCHITECTURE.en.md`](ARCHITECTURE.en.md)，可能滞后于本文件。

## 1. 分层

```
voxhound/
├── core/          数据模型、工具、环形缓冲、事件总线     （不向上依赖）
├── capture/       数据源 + pcap/pcapng 读写 + BPF 子集
├── decode/        链路、IPv4/IPv6、TCP/UDP/ICMP、分片
├── app/           流式与数据报解析器（TLS、HTTP、DNS、QUIC、RTP…）
├── flows/         TCP 重组、会话表、行为分析
├── media/         WAV/G.711、RTP 通话重建、魔数还原
├── intel/         JA3/JA4/JA4S/JA4T、X.509、系统指纹
├── crypto/        纯 Python AES-GCM + HKDF（QUIC Initial）
├── rules/         声明式 JSON 规则 + 引擎
├── store/         SQLite 会话持久化
├── export/        HTML/Markdown 报告、过滤导出 pcap、NDJSON、CSV
├── engine.py      串联以上各层的管线
├── cli.py         命令行入口
└── ui/            PySide6 桌面壳（唯一可选部分）
```

依赖只向下：`core` 不 import 项目内任何模块；`ui` 可以 import 一切；没有模块 import `ui`。

硬性约束：`voxhound/` 中除 `ui/` 外，必须在裸解释器上跑通。CI 在只装了 pytest 的环境里跑测试，并用 AST 扫描 import 语句强制这一点，引擎多 import 一个包，构建就会红。

## 2. 数据流

```
RawPacket ──► 解码器 ──► 过滤器 ──► 流管理层 ──► 解析器
                 │                       │
                 │                       ├─► AppEvent   ──► 规则 ──► Alert
                 │                       ├─► Artifact   （有预算上限）
                 │                       └─► 行为检测 ──► Alert
                 └─ 畸形？继续跑，只做标注
```

一个包可能产生零到多个事件与产物。引擎默认只留计数器、会话、事件（环形）、产物（有预算），不留原始包，除非调用方明确要求。

## 3. 不变式

### 3.1 `Packet.payload` 是 `memoryview`，且不得逃逸

解码器对抓包缓冲做切片而不是拷贝，这是 4 GiB pcap 能常量内存跑完的原因。任何需要长期持有载荷的代码，都必须在边界处 `bytes(view)` 拷贝，重组器就是这么做的。

### 3.2 解析器崩溃不能拖垮抓包

`FlowManager._tcp` 用 `try/except` 包住解析器调用：崩溃时丢弃该会话的解析器、给会话打 `dissector-error` 标签、`dissector_errors` 计数加一。对取证工具来说，恶意输入才是常态。

### 3.3 内存处处有界

| 结构 | 上限 |
|---|---|
| 包环形缓冲（界面） | 20 000 行 |
| 会话表 | `max_flows`（默认 120 000），LRU 优先淘汰已关闭会话 |
| TCP 乱序缓冲 | 每方向 8 MiB，超压时从尾部丢弃最远的乱序段 |
| 流预览缓冲 | 每方向 64 KiB |
| 产物预算 | 引擎 256 MiB / 界面工作线程 512 MiB |
| 分片表 | 4 096 个数据报，30 秒过期，单报 64 KiB |
| HPACK 动态表 | 4 096 字节（协议规定） |
| 事件环 | 5 000 条 |

### 3.4 引擎不碰 Qt，界面不碰引擎状态

界面只接收不可变快照（`dict`、`list[tuple]`），经队列信号送达。抓包线程与 GUI 线程之间没有共享可变对象，因此热路径上没有锁。

## 4. TCP 重组

实现在 `flows/stream.py`。关键决策：

序号算术。绝对偏移取相对 ISN 的有符号 32 位差值：

```python
rel = ((seq - isn + 0x80000000) & 0xFFFFFFFF) - 0x80000000
```

±2 GiB 的无歧义窗口，且天然免疫 4 GiB 回绕。「上次序号 + 增量」的累加器会在回绕后出错。

重叠策略是先到先得。已交付的字节永不改写。这与 BSD 行为一致，更重要的是挡住了 IDS 规避的经典手法：重传一个重叠段来改写已经解析过的内容。

空洞。若某个洞在 `gap_timeout`（2 秒）内没补上，记录空洞并向前跳。一个丢包不能卡住整条会话。空洞会传给应用层，让产物被标注为截断，而不是悄悄产出坏数据。

没有 SYN 的抓包。从连接中途开始的捕获没有 ISN，首个载荷字节即偏移 0。向前回看是不可能的，代码如实说明，而不是猜。

## 5. 解析器选择

内容优先、端口兜底，见 `app/registry.py`。

端口会出错：TLS 跑在 8443、HTTP 跑在 8080、SIP 同时在 5060 和 5080、什么都能跑在 443 上。流的头几个字节则难伪装：

| 特征 | 解析器 |
|---|---|
| `0x16 0x03` | TLS |
| `PRI * HTTP/2.0` | HTTP/2（h2c） |
| `GET `/`POST`/`HEAD`… | HTTP/1.1 |
| `SSH-` | 横幅识别 |
| Content-Type / 魔数 | 载荷还原 |

UDP 侧有一个容易踩的次序问题：RTP 必须排在 QUIC 之前，因为两者首字节都带最高位。次序写反，所有语音通话都会被送进 QUIC 解析器。开发期真踩过，现在由演示里的 RTP 场景守着。

## 6. QUIC Initial 解密

`app/quic.py` 配合 `crypto/`：

1. 解析不变长头部（版本、DCID、SCID、token、length）。
2. 推导初始密钥：先用版本盐对 DCID 做 `HKDF-Extract`，再用 `HKDF-Expand-Label(…, "client in"/"server in")` 得到 key/iv/hp。
3. 随机数 = `iv XOR 包序号`；AAD = 从首字节到包序号（含）的头部。
4. `AES-128-GCM` 解密；先试客户端密钥，失败再试服务端。
5. 遍历帧，取 `CRYPTO`，按偏移拼回 TLS ClientHello。

正确性由 `tests/test_crypto.py` 的 FIPS-197 AES 向量、NIST GCM 向量、RFC 5869 HKDF 向量与 RFC 9001 初始密钥锚定；演示场景用 RFC 9001 的推导加密一个真实的 ClientHello，加密或分帧错一个字节，SNI 就不会出现，`tests/test_engine.py` 直接失败。

成本控制：每流最多解 6 个 Initial、8 KiB。纯 Python AES-GCM 够读握手，远不够处理批量流量。

## 7. HPACK

`app/http2.py` 实现了完整解码器：静态表（61 项）、带淘汰的动态表、整数/字符串原语、规范 Huffman 码。

Huffman 表是生成的，不是手抄的：`scripts/gen_hpack_huffman.py` 解析 RFC 7541 附录 B，写出 `app/_hpack_huffman.py`。257 项的表手抄必错；生成器、Kraft 等式测试与往返编解码测试，才是可信的表。

## 8. 指纹

- JA4（`intel/ja4.py`）：`t13d1516h2_…`。GREASE 处处排除；版本取 `supported_versions`；套件排序后哈希；扩展哈希去掉 SNI/ALPN，再按线上顺序追加签名算法。FoxIO 公布的 Chrome 套件哈希（`8daaf6152771`）是测试向量。
- JA4S：服务端侧，用协商出的套件。
- JA3：遗留 MD5，黑名单还在用，保留。
- JA4T：SYN 上的 `window_options_mss_wscale`。
- 系统提示（`intel/p0f.py`）：按选项顺序匹配并给出置信区间，不是 p0f 复刻；它输出「Windows（较可能）」，而不是假精确。

## 9. 行为分析

`flows/anomaly.py`。每个检测器都小、有状态、有上限：

- 扫描：只统计 SYN，窗口内同一（源，目的）组合的不同目的端口数。
- 回连：联系间隔的变异系数 ≤ 0.18，样本 ≥ 6。天然与尺度无关，5 秒和 5 小时的间隔同等对待。
- 隧道：同一父域下 ≥ 40 个不同子域。
- 外传：单向比值 ≥ 20 且超过 2 MiB 下限。

阈值是构造参数而非常量，因为它们属于策略选择。

## 10. 报告与持久化

`export/report.py` 产出单个自包含 HTML：内联 CSS、内联 SVG 图表（圆环、面积、条形）、零网络请求。分析师把它贴进工单、在隔离网内打开。

`store/sqlite.py` 只存元数据与哈希，不存载荷字节。多 GB 的语音转储不该躺在事务日志里。

## 11. 线程模型

```
主线程（Qt）                     工作线程
──────────────                   ─────────
MainWindow                       EngineWorker.run()
  ├─ 各页模型                      └─ Engine.run(source)
  ├─ 各页面                            ├─ on_packet  ─┐
  └─ CaptureController ◄── 队列信号（批量） ──────────┘
```

`CaptureController` 持有 `QThread` 与 `EngineWorker`。回调先缓冲再批量发信号（48 个包或 120 毫秒），界面永远不会收到「一包一信号」。停止是协作式的 `threading.Event`，退出时关闭数据源。

## 12. 测试策略

- 字节级夹具。数据包由 `voxhound.packets` 现场构造，解码器的 bug 藏不到手写期望值后面。
- 演示即夹具。`voxhound.simulate` 产出真实抓包：TLS、h2c、WebSocket、G.711 通话、QUIC Initial、端口扫描。端到端测试断言内容：加密 QUIC 里的 SNI、可播放的 WAV、回连发现。
- 要向量，不要手感。密码学用 FIPS-197 与 NIST GCM 向量；JA4 用 FoxIO 的 Chrome 套件哈希；Huffman 表用 Kraft 等式。
- 管线里不放 mock。界面按设计排除在覆盖率之外；引擎必须能脱离界面测试。
