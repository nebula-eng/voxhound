# 规则参考

规则就是 JSON。没有 DSL 解析器、没有 YAML 缩进陷阱、没有需要审计的正则引擎，只有一个扁平的 `match` 对象，便于评审、diff 与自动生成。

> 英文原文见 [`RULES.en.md`](RULES.en.md)。

## 文件结构

一个规则文件可以是单个规则对象、规则数组，或带 `rules` 数组的对象，三者等价，单条规则最省事：

```json
{
  "version": 1,
  "rules": [
    {
      "id": "tls-no-sni",
      "name": "TLS 握手未携带 SNI",
      "severity": 2,
      "scope": "event",
      "description": "客户端连接时没有给出服务器名。",
      "match": { "kind": "tls", "tag_any": ["no-sni"] },
      "tags": ["evasion"],
      "mitre": "T1090",
      "enabled": true
    }
  ]
}
```

| 字段 | 必填 | 含义 |
|---|---|---|
| `id` | 是 | 稳定标识，出现在告警与报告中 |
| `name` | 否 | 展示用名称（默认取 `id`） |
| `severity` | 否 | `0` 信息、`1` 较低、`2` 中、`3` 高、`4` 严重（默认 `2`） |
| `scope` | 否 | `event`（默认）或 `flow` |
| `description` | 否 | 界面与报告中展示的说明 |
| `match` | 是 | 条件集合，全部按「与」组合 |
| `tags` | 否 | 自由标签 |
| `mitre` | 否 | ATT&CK 技术编号 |
| `enabled` | 否 | 默认 `true` |

### 加载时会发生什么

```bash
voxhound rules --check ./my-rules
```

- 结构无法识别（例如裸的 `{"foo": 1}`）会直接报错并返回 3，不会静默跳过；
- 单条规则缺 `id`（或类型不对）会被跳过，并在 stderr 逐条列出文件名与原因；
- 一条都没解析出来时额外提示「没有解析出任何规则」。

这条设计是为了让「规则写了但从不触发」不可能悄悄发生，检测器的静默失效比崩溃更难发现。

## 关于语言

界面、规则名称、报告文字都是中文；但协议事件文本保留英文记法（`ClientHello`、`DNS query`、`ServerHello`），
因为它是协议术语、也便于与 Wireshark/Zeek 的说法对照。因此 `title_regex` / `title_contains` 匹配的是这些英文文本。

## 规则何时执行

* `scope: "event"`，解析器每发出一个事件（DNS 查询、TLS ClientHello、HTTP 响应…）时评估一次。评估时会带上所属会话上下文，因此事件字段与会话字段都可用。
* `scope: "flow"`，会话关闭时评估一次（抓包结束时补一次），可用累计值：字节数、时长、端口、应用、标签、备注。

## 条件参考

### 事件条件

| 键 | 类型 | 命中条件 |
|---|---|---|
| `kind` | 字符串或数组 | 事件类型属于其中之一（`dns`、`tls`、`http`、`h2`、`ws`、`quic`、`rtp`、`sip`、`stun`、`mqtt`、`banner`） |
| `title_contains` | 字符串 | 事件标题包含该子串（忽略大小写） |
| `title_regex` | 字符串 | 事件标题匹配该正则（忽略大小写） |
| `not_title_regex` | 字符串 | 事件标题不匹配该正则 |
| `severity_gte` | 整数 | 事件严重程度不低于该值 |
| `detail` | 对象 | `{键: 子串}`，每个键的值需包含对应子串（忽略大小写） |

### 会话条件（事件范围下若存在所属会话同样生效）

| 键 | 类型 | 命中条件 |
|---|---|---|
| `sni_regex` | 字符串 | 会话的 SNI 匹配（空 SNI 不会命中非空正则） |
| `ja4_regex` | 字符串 | 会话的 JA4 匹配 |
| `dns_regex` | 字符串 | 该会话出现过的任一 DNS 名匹配 |
| `ip_regex` | 字符串 | `"源 目的"` 拼接后匹配 |
| `port` | 整数 | 任一端端口等于该值 |
| `port_in` | 数组 | 任一端端口在列表中 |
| `proto` | 字符串 | `TCP`、`UDP`、`ICMP`… |
| `app_in` | 数组 | 会话应用属于其中之一（`TLS`、`HTTP`、`DNS`、`QUIC`、`RTP`…） |
| `tag_any` | 数组 | 会话带有其中任一标签 |
| `note_true` | 对象 | `{键: true}`，会话备注为真值 |

### 仅会话范围可用

| 键 | 类型 | 命中条件 |
|---|---|---|
| `bytes_gt` | 整数 | 会话载荷字节数大于该值 |
| `duration_gt` | 浮点 | 会话时长（秒）大于该值 |

## 可用的标签

由解析器与会话层设置：

`no-sni`、`ech`、`session-resumption`、`self-signed-cert`、`expired-cert`、`cert-expiring`、
`cert-hostname-mismatch`、`sni-rejected`、`tls-desync`、`http-4xx`、`http-5xx`、`websocket`、
`ws-closed`、`ws-opus`、`ws-silk?`、`ws-base64-audio?`、`dga?`、`nxdomain`、`dns-truncated`、
`quic`、`quic-handshake`、`rtp`、`voice-g711`、`webrtc`、`voip-signalling`、`call-ended`、
`ssh`、`mqtt`、`dissector-error`。

## 示例

明文 HTTP 传凭据，带 Authorization 头的请求：

```json
{
  "id": "http-cleartext-auth",
  "name": "明文 HTTP 传输凭据",
  "severity": 3,
  "match": { "kind": "http", "detail": { "auth": "true" } }
}
```

针对特定环境的异常证书：

```json
{
  "id": "corp-cert-allowlist",
  "name": "非预期证书签发者",
  "severity": 2,
  "scope": "event",
  "match": { "kind": "tls", "title_regex": "^certificate", "title_contains": "issuer=Evil CA" }
}
```

批量外发：

```json
{
  "id": "bulk-upload",
  "name": "加密或 HTTP 会话上的大批量外发",
  "severity": 3,
  "scope": "flow",
  "match": {
    "proto": "TCP",
    "bytes_gt": 10485760,
    "app_in": ["TLS", "HTTP"]
  }
}
```

受监管网络里的明文语音：

```json
{
  "id": "voip-cleartext-g711",
  "name": "未加密的 G.711 语音流",
  "severity": 2,
  "scope": "flow",
  "match": { "proto": "UDP", "tag_any": ["voice-g711"] }
}
```

## 加载方式

```bash
voxhound analyze capture.pcap --rules ./my-rules/     # 目录下的 *.json
voxhound analyze capture.pcap --rules ./rules.json    # 单个文件
voxhound analyze capture.pcap --no-rules               # 关闭内置规则
voxhound rules --check ./my-rules/                     # 校验并列出
```

规则是叠加的：自定义文件在内置规则之上追加。格式错误的规则会被跳过并告警，不会中断分析；但 `voxhound rules --check` 会报出来，CI 应该用它。

## 编写风格

1. 一条规则只表达一种行为。 一条规则因三种原因触发，对分析师等于没有信息。
2. 能用标签就别用标题正则。 解析器已经归类过的行为，标签是稳定契约，标题只是文案。
3. 不要把策略塞进 `severity`。 严重程度描述行为本身的危害；它在你的环境里是否要紧，是下游的过滤决策。
4. 体量与时长用 `scope: flow`，一次性信号用 `event`。
