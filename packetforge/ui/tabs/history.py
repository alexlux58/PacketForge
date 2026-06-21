from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.history import DiscoveryHistory, compare_runs
from packetforge.models.discovery import DiscoveryRun
from packetforge.ui.state import DiscoveryState
from packetforge.ui.widgets.data_table import DataTable
from packetforge.ui.widgets.page_header import PageHeader

_COLUMNS = ["Started", "Profile", "Targets", "Hosts", "Run ID"]


class HistoryTab(QWidget):
    """Browse, load, compare, and delete locally saved discovery runs."""

    status_message = Signal(str)

    def __init__(self, state: DiscoveryState, history: DiscoveryHistory) -> None:
        super().__init__()
        self.state = state
        self.history = history
        self._runs: list[DiscoveryRun] = []
        self._row_for_id: dict[str, int] = {}

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Run History",
                "history",
                subtitle=(
                    "Saved discovery runs under ~/.packetforge/history. "
                    "Load a run into Discovery Center or compare with the current session."
                ),
            )
        )

        self.path_label = QLabel(f"Storage: {self.history.directory}")
        self.path_label.setObjectName("Muted")
        self.path_label.setWordWrap(True)
        root.addWidget(self.path_label)

        self.table = DataTable(
            _COLUMNS,
            empty_message="No saved runs yet.",
            empty_hint="Complete a Discovery Center scan — runs are saved automatically.",
        )
        self.table.row_activated.connect(self._load_selected)
        root.addWidget(self.table, 1)

        self.summary = QLabel("")
        self.summary.setObjectName("Muted")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        buttons = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(refresh)
        load = QPushButton("Load into Discovery")
        load.clicked.connect(self._load_selected)
        buttons.addWidget(load)
        compare = QPushButton("Compare with current")
        compare.clicked.connect(self._compare_with_current)
        buttons.addWidget(compare)
        delete = QPushButton("Delete...")
        delete.clicked.connect(self._delete_selected)
        buttons.addWidget(delete)
        buttons.addStretch(1)
        root.addLayout(buttons)

        self.refresh()

    def refresh(self) -> None:
        self._runs = self.history.list_runs()
        self.table.begin_bulk_update()
        self.table.clear_rows()
        self._row_for_id.clear()
        for run in self._runs:
            row = self.table.insert_row()
            self._row_for_id[run.id] = row
            values = [
                run.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                run.profile,
                run.targets,
                str(run.host_count),
                run.id,
            ]
            for column, value in enumerate(values):
                self.table.set_cell(
                    row, column, value, user_data=run.id if column == 4 else None
                )
        self.table.end_bulk_update()
        if self._runs:
            self.table.resize_columns_to_contents()
        self.summary.setText(f"{len(self._runs)} saved run(s).")

    def _selected_run(self) -> DiscoveryRun | None:
        run_id = self.table.selected_key()
        if not run_id:
            return None
        return next((run for run in self._runs if run.id == run_id), None)

    def _load_selected(self) -> None:
        run = self._selected_run()
        if run is None:
            QMessageBox.information(
                self, "No run selected", "Select a saved run to load into Discovery Center."
            )
            return
        self.state.set_run(run)
        self.summary.setText(
            f"Loaded {run.host_count} host(s) from {run.started_at:%Y-%m-%d %H:%M:%S}."
        )
        self.status_message.emit(f"Loaded history run ({run.host_count} hosts)")

    def _compare_with_current(self) -> None:
        baseline = self._selected_run()
        current = self.state.last_run
        if baseline is None:
            QMessageBox.information(
                self,
                "No run selected",
                "Select a saved run to compare against the current session.",
            )
            return
        if current is None or not self.state.hosts():
            QMessageBox.information(
                self,
                "No current session",
                "Run a discovery scan or load data before comparing with history.",
            )
            return
        comparison = compare_runs(baseline, current)
        self.summary.setText(comparison.summary)
        detail = [
            comparison.summary,
            f"Added: {', '.join(comparison.added_hosts) or 'none'}",
            f"Removed: {', '.join(comparison.removed_hosts) or 'none'}",
            f"Port changes: {len(comparison.changed_ports)} host(s)",
        ]
        QMessageBox.information(self, "Run comparison", "\n".join(detail))

    def _delete_selected(self) -> None:
        run = self._selected_run()
        if run is None:
            QMessageBox.information(self, "No run selected", "Select a run to delete.")
            return
        reply = QMessageBox.warning(
            self,
            "Delete saved run",
            f"Delete run {run.id} ({run.targets}, {run.host_count} hosts)?\n\n"
            "This removes the JSON file from disk.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if self.history.delete(run.id):
            self.status_message.emit(f"Deleted run {run.id}")
            self.refresh()
        else:
            QMessageBox.warning(self, "Delete failed", f"Could not delete run {run.id}.")
