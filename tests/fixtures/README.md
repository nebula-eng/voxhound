# 抓包夹具目录

只有这个目录允许提交 `.pcap` / `.pcapng` / `.cap`（其余位置被 `.gitignore` 屏蔽）。

## 允许提交什么

- 用 `voxhound demo --write` 生成的合成抓包——可以随时重建，审查成本最低。
- 已经在公开数据集/CTF 题目中发布的抓包，且许可允许再分发。
- 自己脱敏过的最小样本（见下）。

## 提交前必须做的脱敏

```bash
# 1. 剪到真正需要的那几秒
editcap -A "2026-01-01 10:00:00" -B "2026-01-01 10:00:05" in.pcap out.pcap

# 2. 截断载荷：只留头部，足够验证解析
editcap -s 96 out.pcap out-snap.pcap

# 3. 确认没有真实身份信息残留
tshark -r out-snap.pcap -T fields -e frame.protocols | sort -u
tshark -r out-snap.pcap -Y tls.handshake.extensions_server_name -T fields \
  -e tls.handshake.extensions_server_name | sort -u
```

IP、MAC、SNI、证书主体、Cookie、`Authorization`、SIP 号码、RTP 里的语音，任何一项都不该是真实生产数据。

## 写清来源

每个夹具在文件名或本文件中注明：来源、抓取时间、许可、脱敏方式。审查者需要判断它能不能长期留在仓库里。

> 一个真实通话录音进了 git 历史，就删不掉了。拿不准就不要提交。
