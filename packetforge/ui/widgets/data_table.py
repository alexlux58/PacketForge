from __future__ import annotations

import csv
import re
from collections.abc import Callable
from io import StringIO
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from packetforge.ui.widgets.empty_state import EmptyStateWidget


class DataTable(QWidget):
    """Dense read-only table with filter, sort, copy, and CSV export hooks."""

    row_activated = Signal(str)

    def __init__(
        self,
        columns: list[str],
        *,
        empty_message: str = "No rows yet.",
        empty_hint: str = "",
        sortable: bool = True,
    ) -> None:
        super().__init__()
        self._columns = list(columns)
        self._filter_text = ""
        self._sortable = sortable
        self._bulk_depth = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter rows (Ctrl+F)")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search, 1)

        self.copy_button = QPushButton("Copy")
        self.copy_button.setToolTip("Copy selected rows to the clipboard (Ctrl+C)")
        self.copy_button.clicked.connect(self.copy_selection)
        toolbar.addWidget(self.copy_button)

        self.export_button = QPushButton("CSV")
        self.export_button.setToolTip("Export visible rows to CSV")
        toolbar.addWidget(self.export_button)
        root.addLayout(toolbar)

        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(sortable)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.table.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self.table, 1)

        self.empty = EmptyStateWidget(empty_message, hint=empty_hint)
        root.addWidget(self.empty)
        self._sync_empty_state()

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def set_export_handler(self, handler: Callable[[], None]) -> None:
        self.export_button.clicked.connect(handler)

    def begin_bulk_update(self) -> None:
        """Disable sorting while rows are inserted one at a time."""
        self._bulk_depth += 1
        if self._bulk_depth == 1:
            self.table.setSortingEnabled(False)

    def end_bulk_update(self) -> None:
        if self._bulk_depth == 0:
            return
        self._bulk_depth -= 1
        if self._bulk_depth == 0 and self._sortable:
            self.table.setSortingEnabled(True)
            self.table.sortItems(0, Qt.SortOrder.AscendingOrder)

    def resize_columns_to_contents(self) -> None:
        self.table.resizeColumnsToContents()
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)

    def scroll_to_bottom(self) -> None:
        row_count = self.table.rowCount()
        if row_count == 0:
            return
        item = self.table.item(row_count - 1, 0)
        if item is None:
            return
        self.table.scrollToItem(item, QAbstractItemView.ScrollHint.PositionAtBottom)

    def save_csv(self, path: str | Path) -> None:
        rows = self.visible_rows()
        if not rows:
            return
        with Path(path).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(self._columns)
            writer.writerows(rows)

    def visible_rows(self) -> list[list[str]]:
        rows: list[list[str]] = []
        for row in range(self.table.rowCount()):
            if self.table.isRowHidden(row):
                continue
            rows.append(
                [
                    item.text() if (item := self.table.item(row, col)) else ""
                    for col in range(self.table.columnCount())
                ]
            )
        return rows

    def copy_selection(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            rows = self.visible_rows()
            if not rows:
                return
            text = self._rows_to_tsv(rows)
        else:
            lines: list[list[str]] = []
            for model_index in selected:
                row = model_index.row()
                lines.append(
                    [
                        item.text() if (item := self.table.item(row, col)) else ""
                        for col in range(self.table.columnCount())
                    ]
                )
            text = self._rows_to_tsv(lines)
        QGuiApplication.clipboard().setText(text)

    @staticmethod
    def _rows_to_tsv(rows: list[list[str]]) -> str:
        buffer = StringIO()
        writer = csv.writer(buffer, delimiter="\t")
        for row in rows:
            writer.writerow(row)
        return buffer.getvalue().rstrip("\n")

    def set_cell(self, row: int, column: int, value: str, *, user_data: str | None = None) -> None:
        item = QTableWidgetItem(value)
        _apply_sort_key(item, value)
        if user_data is not None and column == 0:
            item.setData(Qt.ItemDataRole.UserRole, user_data)
        self.table.setItem(row, column, item)
        self._sync_empty_state()

    def row_count(self) -> int:
        return self.table.rowCount()

    def insert_row(self) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._sync_empty_state()
        return row

    def clear_rows(self) -> None:
        self.table.setRowCount(0)
        self._sync_empty_state()

    def selected_key(self) -> str | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        if item is None:
            return None
        data = item.data(Qt.ItemDataRole.UserRole)
        return str(data) if data else item.text()

    def _apply_filter(self, text: str) -> None:
        self._filter_text = text.strip().lower()
        if not self._filter_text:
            for row in range(self.table.rowCount()):
                self.table.setRowHidden(row, False)
            return
        for row in range(self.table.rowCount()):
            haystack = " ".join(
                item.text().lower() if (item := self.table.item(row, col)) else ""
                for col in range(self.table.columnCount())
            )
            self.table.setRowHidden(row, self._filter_text not in haystack)

    def _on_double_click(self, item: QTableWidgetItem) -> None:
        row_item = self.table.item(item.row(), 0)
        if row_item is None:
            return
        data = row_item.data(Qt.ItemDataRole.UserRole)
        key = str(data) if data else row_item.text()
        if key:
            self.row_activated.emit(key)

    def _sync_empty_state(self) -> None:
        empty = self.table.rowCount() == 0
        self.empty.setVisible(empty)
        self.table.setVisible(not empty)


_NUMERIC_PREFIX = re.compile(r"^(-?\d+(?:\.\d+)?)")


def _apply_sort_key(item: QTableWidgetItem, value: str) -> None:
    stripped = value.strip()
    if not stripped:
        return
    if stripped.isdigit():
        item.setData(Qt.ItemDataRole.EditRole, int(stripped))
        return
    match = _NUMERIC_PREFIX.match(stripped.replace(",", ""))
    if match is not None:
        text = match.group(1)
        item.setData(
            Qt.ItemDataRole.EditRole,
            int(text) if "." not in text else float(text),
        )
