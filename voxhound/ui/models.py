"""Qt table models.

Rules followed here:

* **Never touch a model from the capture thread.** Everything arrives through a
  queued signal, which is what makes the UI single-threaded and race-free.
* **Bounded.** The packet list keeps the last 20 000 rows; a multi-hour capture
  must not turn the UI into a memory leak with a scrollbar.
* **Batch inserts.** ``beginInsertRows`` once per batch instead of once per row —
  the difference between a smooth 40k pkt/s UI and a frozen one.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

PACKET_COLUMNS = ("#", "时间", "源地址", "目的地址", "协议", "长度", "摘要", "应用")
FLOW_COLUMNS = ("客户端", "服务端", "协议", "应用", "SNI", "JA4", "包数", "字节", "时长", "状态")
ALERT_COLUMNS = ("时间", "级别", "结论", "规则", "端点")
ARTIFACT_COLUMNS = ("类型", "文件名", "大小", "来源", "SHA-256")
RULE_COLUMNS = ("ID", "名称", "说明", "级别", "范围", "命中", "MITRE")


class PacketModel(QAbstractTableModel):
    def __init__(self, capacity: int = 20_000) -> None:
        super().__init__()
        self._rows: deque[tuple[Any, ...]] = deque(maxlen=capacity)

    # ------------------------------------------------------------------ Qt API
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(PACKET_COLUMNS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,  # noqa: N802
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return PACKET_COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return str(row[column])
        if role == Qt.ItemDataRole.TextAlignmentRole and column in (0, 5):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role == Qt.ItemDataRole.ToolTipRole:
            return f"{row[6]}\n{row[1]}  {row[2]} -> {row[3]}"
        return None

    def add_batch(self, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        overflow = max(0, len(self._rows) + len(rows) - self._rows.maxlen)
        if overflow:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            for _ in range(overflow):
                self._rows.popleft()
            self.endRemoveRows()
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        self._rows.extend(rows)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def row_at(self, row: int) -> tuple[Any, ...] | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None


class _RowModel(QAbstractTableModel):
    columns: tuple[str, ...] = ()
    numeric_columns: tuple[int, ...] = ()
    right_columns: tuple[int, ...] = ()

    def __init__(self, capacity: int = 20_000) -> None:
        super().__init__()
        self._rows: list[dict[str, Any]] = []
        self._capacity = capacity
        self._key_fields: tuple[str, ...] = ()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.columns)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,  # noqa: N802
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            value = self.cell(row, column)
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role == Qt.ItemDataRole.ToolTipRole:
            # Descriptions live on alerts and rules; showing them on hover keeps
            # the table compact without hiding the "why".
            parts = [str(row.get("description") or ""), str(row.get("match") or "")]
            text = "\n\n".join(part for part in parts if part)
            return text or None
        if role == Qt.ItemDataRole.TextAlignmentRole and column in self.right_columns:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def cell(self, row: dict[str, Any], column: int) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def sort_value(self, row: dict[str, Any], column: int) -> Any:
        return self.cell(row, column)

    # ------------------------------------------------------------------ helpers
    def rows(self) -> list[dict[str, Any]]:
        return self._rows

    def row_at(self, row: int) -> dict[str, Any] | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def add_rows(self, rows: list[dict[str, Any]], *, newest_first: bool = True) -> None:
        if not rows:
            return
        if newest_first:
            self.beginInsertRows(QModelIndex(), 0, len(rows) - 1)
            self._rows[0:0] = rows
            self.endInsertRows()
            if len(self._rows) > self._capacity:
                drop = len(self._rows) - self._capacity
                self.beginRemoveRows(QModelIndex(), self._capacity, len(self._rows) - 1)
                del self._rows[self._capacity :]
                self.endRemoveRows()
                del drop
        else:
            start = len(self._rows)
            self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
            self._rows.extend(rows)
            self.endInsertRows()

    def reset_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._rows = rows[: self._capacity]
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()


class FlowModel(_RowModel):
    columns = FLOW_COLUMNS
    right_columns = (6, 7, 8)

    def cell(self, row: dict[str, Any], column: int) -> Any:
        from ..core.util import human_bytes, human_duration

        keys = ("client", "server", "proto", "app", "sni", "ja4", "packets", "bytes", "duration", "state")
        key = keys[column]
        if key == "bytes":
            return human_bytes(row.get("bytes", 0))
        if key == "duration":
            return human_duration(row.get("duration", 0))
        if key == "ja4":
            return (row.get("ja4") or "")[:26]
        if key == "state":
            return "已关闭" if row.get("state") == "closed" else "进行中"
        return row.get(key, "")

    def sort_value(self, row: dict[str, Any], column: int) -> Any:
        keys = ("client", "server", "proto", "app", "sni", "ja4", "packets", "bytes", "duration", "state")
        return row.get(keys[column], "")


class AlertModel(_RowModel):
    columns = ALERT_COLUMNS
    right_columns = ()

    def cell(self, row: dict[str, Any], column: int) -> Any:
        from .theme import severity_label

        if column == 0:
            return row.get("time", "")
        if column == 1:
            return severity_label(int(row.get("severity", 0))).upper()
        if column == 2:
            return row.get("title", "")
        if column == 3:
            return row.get("rule", "")
        return row.get("flow", "")

    def sort_value(self, row: dict[str, Any], column: int) -> Any:
        if column == 1:
            return int(row.get("severity", 0))
        return self.cell(row, column)


class ArtifactModel(_RowModel):
    columns = ARTIFACT_COLUMNS
    right_columns = (2,)

    def cell(self, row: dict[str, Any], column: int) -> Any:
        from ..core.util import human_bytes

        if column == 0:
            return row.get("kind", "")
        if column == 1:
            return row.get("name", "")
        if column == 2:
            return human_bytes(row.get("size", 0))
        if column == 3:
            return row.get("source", "")
        return (row.get("sha256") or "")[:16]

    def sort_value(self, row: dict[str, Any], column: int) -> Any:
        if column == 2:
            return int(row.get("size", 0))
        return self.cell(row, column)


class RuleModel(_RowModel):
    columns = RULE_COLUMNS
    right_columns = (5,)

    def cell(self, row: dict[str, Any], column: int) -> Any:
        keys = ("id", "name", "description", "severity", "scope", "hits", "mitre")
        value = row.get(keys[column], "")
        if column == 4:  # scope
            return {"event": "事件", "flow": "会话"}.get(str(value), value)
        return value

    def sort_value(self, row: dict[str, Any], column: int) -> Any:
        return self.cell(row, column)


class RowFilterProxy(QSortFilterProxyModel):
    """Search across every visible column plus an optional app filter."""

    def __init__(self) -> None:
        super().__init__()
        self._needle = ""
        self._app = ""
        self.setDynamicSortFilter(True)

    def set_needle(self, text: str) -> None:
        self._needle = text.strip().lower()
        self.invalidateFilter()

    def set_app(self, app: str) -> None:
        self._app = app.strip()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if model is None:
            return True
        row = model.row_at(source_row) if hasattr(model, "row_at") else None
        if row is None:
            return True
        if self._app and isinstance(row, dict) and row.get("app") != self._app:
            return False
        if not self._needle:
            return True
        if isinstance(row, dict):
            haystack = " ".join(str(value) for value in row.values())
        else:
            haystack = " ".join(str(part) for part in row[:7])
        return self._needle in haystack.lower()
