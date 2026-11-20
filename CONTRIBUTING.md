# 参与贡献

感谢愿意投入时间。这个项目有一组设计约束，请在提交 PR 前读完，它们就是评审清单。

## 环境准备

```bash
git clone https://github.com/nebula-eng/voxhound.git
cd voxhound
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check voxhound tests
```

桌面端可选：

```bash
python -m pip install -e ".[gui]"
voxhound-gui
```

## 设计约束

1. 引擎不新增运行时依赖。`voxhound/` 除 `voxhound/ui/` 外只能 import 标准库。CI 会在无第三方包的环境里跑测试并扫描 import，强制这条。
2. 内存必须有界。任何新缓冲、缓存、表都要有上限与淘汰策略，并在 docstring 里写清楚上限是多少。
3. `memoryview` 不得逃逸出 `decode()`。在边界处 `bytes(view)` 拷贝，否则整个抓包缓冲会被钉在内存里。
4. 解析器的 bug 不能中断抓包。捕获、标注、计数，不要让异常从解析器里逃出去。
5. 不猜。字段解析不出来就如实标注，宁可 `malformed="原因"`，也不要一个看起来合理的错值。
6. 指纹必须能离线复现。不查网络、不接厂商情报、不做「调接口丰富化」。
7. 每个新解析器都要有真实字节的测试。用 `voxhound.packets` 构造夹具，不要在测试里手写十六进制块。
8. 注释解释「为什么」，不解释「是什么」。如果需要注释才读得懂，先改命名。

## 代码在哪

| 你想做 | 改这里 |
|---|---|
| 支持新协议 | `voxhound/app/<协议>.py` + 在 `app/registry.py` 注册 |
| 支持新链路类型 | `decode/link.py` |
| 加一条检测 | `voxhound/rules/builtin.json`（行为类改 `flows/anomaly.py`） |
| 改界面 | `voxhound/ui/pages.py`、`widgets.py`、`theme.py` |
| 加导出格式 | `voxhound/export/` |
| 优化性能 | `core/ring.py`、`flows/stream.py`、`decode/` |

## 新增一个解析器

```python
from .base import AppSession, StreamDissector

class MyDissector(StreamDissector):
    name = "MyProto"

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._buffer = bytearray()

    def feed(self, direction: int, data: bytes) -> None:
        self._buffer += data
        while (message := self._pop_message()) is not None:
            self.s.emit("myproto", f"消息 {len(message)} 字节", size=len(message))

    def close(self) -> None:
        super().close()
        if self._buffer:
            self.s.tag("truncated-message")
```

然后在 `app/registry.py` 加内容特征判定，在 `voxhound/simulate.py` 加一个场景，并补测试。演示场景才是端到端证明，它在真实字节上跑通整条管线。

## 代码风格

- `ruff check` 必须通过（配置在 `pyproject.toml`）。
- 行长 110、四空格缩进、双引号。
- 公开函数写类型标注。
- 每包对象优先 `dataclass(slots=True)`；其余用普通类。
- 界面与报告文案用中文；代码注释与 docstring 可用中文或英文，与所在文件保持一致即可。

## 提交信息

约定式、祈使句、带范围：

```
decode: 处理 IPv6 超大包
app/tls: 在 ServerHello 上输出 JA4S
ui: 刷新时保持会话选中状态
docs: 修正 flow 范围规则的示例
```

## 测试

- 修 bug 先写一个会失败的测试。
- 端到端断言放 `tests/test_engine.py`，断言内容（某个 SNI、WAV 帧数、规则 ID），而不是「列表非空」。
- 影响到性能的改动：附上 `voxhound demo` 前后对比的简短数据。

## 在自己分支上发布之前

如果要 fork 出去做自己的发行版，MIT 许可证要求保留原始的版权声明与许可文本，不能直接删掉。改品牌的话，用 `python scripts/screenshot.py docs/screenshots` 重新生成截图，否则界面图和新的名字对不上。

## 报告问题

请附：`voxhound version` 输出、平台、完整命令行，以及（如果可以）最小抓包。分享抓包前务必脱敏，里面有别人的流量。用 `voxhound extract` 配合过滤器切出小样本是最省事的做法。

安全问题请走 [SECURITY.md](SECURITY.md)，不要开公开 issue。

## 抓包夹具

`tests/fixtures/` 是唯一允许提交抓包的目录（`.gitignore` 只对该目录放行）。提交前请：

1. 用 `editcap -A/-B` 裁到最小时间窗，`editcap -s 96` 截断载荷；
2. 删除或替换真实 IP、MAC、SNI、证书、Cookie、Authorization；
3. 在 `tests/fixtures/README.md` 里写清来源、许可与脱敏方式。

拿不准的抓包不要提交。一个真实通话录音进了 git 历史，是删不掉的。
