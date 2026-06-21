from __future__ import annotations

from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.observability import confidence_distribution
from packetforge.engine.targets import validate_host_token
from packetforge.errors import ErrorEvent
from packetforge.models.discovery import FingerprintEvidence, HostRecord
from packetforge.security.privileges import detect_privileges
from packetforge.ui import charts
from packetforge.ui.state import DiscoveryState
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.widgets.interface_combo import defer_populate_interface_combo, tune_combo_box
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.workers import FingerprintWorker


class FingerprintingTab(QWidget):
    def __init__(self, state: DiscoveryState) -> None:
        super().__init__()
        self.state = state
        self.worker: FingerprintWorker | None = None
        self.privileges = detect_privileges()

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Fingerprinting",
                "fingerprinting",
                subtitle=(
                    "Likely OS family from TTL, TCP, ICMP, and banner evidence — never an "
                    "exact OS. Click i for interpretation help."
                ),
            )
        )

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        controls = QHBoxLayout()
        root.addLayout(controls)
        controls.addWidget(QLabel("Host:"))
        self.host_combo = QComboBox()
        self.host_combo.setEditable(True)
        self.host_combo.setMinimumWidth(220)
        self.host_combo.setToolTip(
            "Pick a discovered host or type an IP/hostname. Discovered hosts pre-fill "
            "automatically; their open ports are reused for banner probes."
        )
        if line_edit := self.host_combo.lineEdit():
            line_edit.setPlaceholderText("e.g. 192.168.4.1")
        controls.addWidget(self.host_combo)
        controls.addWidget(QLabel("Interface:"))
        self.interface = tune_combo_box(QComboBox())
        defer_populate_interface_combo(self.interface)
        controls.addWidget(self.interface)
        self.run_button = QPushButton("Fingerprint host")
        self.run_button.clicked.connect(self.run_fingerprint)
        controls.addWidget(self.run_button)
        controls.addStretch(1)

        self.headline = QLabel("Select a discovered host or type an IP to begin.")
        self.headline.setObjectName("Metric")
        root.addWidget(self.headline)

        body = QHBoxLayout()
        root.addLayout(body, 1)

        guesses_box = QGroupBox("Likely OS families")
        guesses_layout = QVBoxLayout(guesses_box)
        self.guesses = QTableWidget(0, 3)
        self.guesses.setHorizontalHeaderLabels(["Family", "Confidence", "Rationale"])
        self.guesses.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.guesses.verticalHeader().setVisible(False)
        guesses_layout.addWidget(self.guesses)
        body.addWidget(guesses_box, 1)

        signals_box = QGroupBox("Evidence (signals)")
        signals_layout = QVBoxLayout(signals_box)
        self.signals = QTableWidget(0, 4)
        self.signals.setHorizontalHeaderLabels(["Signal", "Value", "Interpretation", "Weight"])
        self.signals.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.signals.verticalHeader().setVisible(False)
        signals_layout.addWidget(self.signals)
        body.addWidget(signals_box, 2)

        self.privilege_hint = QLabel(self.privileges.headline)
        self.privilege_hint.setObjectName("Muted")
        self.privilege_hint.setWordWrap(True)
        root.addWidget(self.privilege_hint)

        if not self.privileges.raw_sockets:
            raw_note = QLabel(
                "Raw signals (TTL, TCP SYN options, ICMP) require elevation. "
                "Only banner grabbing and TCP connect are used here, so confidence "
                "stays low. The evidence table still lists every port probed."
            )
            raw_note.setObjectName("Muted")
            raw_note.setWordWrap(True)
            root.addWidget(raw_note)

        self.conf_caption = QLabel(
            "Fingerprint confidence across hosts (left-skew = weak evidence)"
        )
        self.conf_caption.setObjectName("Muted")
        root.addWidget(self.conf_caption)
        self.conf_holder = QVBoxLayout()
        root.addLayout(self.conf_holder)

        self.state.hosts_changed.connect(self._refresh_hosts)
        self._refresh_hosts()

    def _refresh_hosts(self) -> None:
        current = self.host_combo.currentText()
        hosts = self.state.hosts()
        self.host_combo.blockSignals(True)
        self.host_combo.clear()
        for host in hosts:
            self.host_combo.addItem(host.ip)
        if current:
            self.host_combo.setCurrentText(current)
        elif hosts:
            # Pre-fill from discovery so the user does not retype a known host.
            self.host_combo.setCurrentText(hosts[0].ip)
        self.host_combo.blockSignals(False)
        self._refresh_confidence()

    def _target_host(self) -> str:
        return self.host_combo.currentText().strip()

    def _ports_for(self, host: str) -> tuple[int, ...] | None:
        """Reuse a discovered host's open TCP ports for banner probes, if any."""
        record = self.state.get(host)
        if record is None:
            return None
        open_tcp = [s.port for s in record.services if s.protocol == "tcp" and s.state == "open"]
        return tuple(dict.fromkeys(open_tcp)) or None

    def _refresh_confidence(self) -> None:
        while self.conf_holder.count():
            item = self.conf_holder.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        hosts = self.state.hosts()
        if any(h.fingerprint is not None for h in hosts):
            chart = charts.bar_chart(confidence_distribution(hosts), height=140)
            self.conf_holder.addWidget(chart)
        else:
            placeholder = QLabel("No fingerprint evidence yet.")
            placeholder.setObjectName("Muted")
            self.conf_holder.addWidget(placeholder)

    def run_fingerprint(self) -> None:
        host = self._target_host()
        if not host:
            QMessageBox.information(self, "No host", "Choose or type a host to fingerprint.")
            return
        ok, message = validate_host_token(host)
        if not ok:
            self.error_banner.show_event(
                ErrorEvent(
                    severity="warning",
                    category="invalid_cidr",
                    source="Fingerprinting",
                    operation="validate",
                    message=message,
                    suggested_fix="Enter a valid IPv4/IPv6 address or hostname.",
                )
            )
            return
        if self.worker and self.worker.isRunning():
            return
        self.error_banner.clear()
        self.headline.setText(f"Fingerprinting {host}...")
        self.run_button.setEnabled(False)
        self.worker = FingerprintWorker(
            host,
            interface=self.interface.currentText() or None,
            raw_ok=self.privileges.raw_sockets,
            ports=self._ports_for(host),
        )
        self.worker.completed.connect(self._on_completed)
        self.worker.failed.connect(self._on_failed)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

    def _on_error(self, event: ErrorEvent) -> None:
        self.error_banner.show_event(event, on_retry=self.run_fingerprint)

    def _on_completed(self, evidence: FingerprintEvidence) -> None:
        self.run_button.setEnabled(True)
        ports_probed = sum(1 for s in evidence.signals if s.name.startswith("TCP "))
        headline = f"{evidence.host}: {evidence.summary}"
        if evidence.confidence < 0.2:
            extra = f"{ports_probed} port(s) probed"
            if not self.privileges.raw_sockets:
                extra += "; raw signals need elevation"
            headline += f" — {extra}. See the evidence table for what was attempted."
        self.headline.setText(headline)
        self.guesses.setRowCount(len(evidence.os_guesses))
        for row, guess in enumerate(evidence.os_guesses):
            self.guesses.setItem(row, 0, QTableWidgetItem(guess.family))
            self.guesses.setItem(row, 1, QTableWidgetItem(f"{guess.confidence * 100:.0f}%"))
            self.guesses.setItem(row, 2, QTableWidgetItem(guess.rationale))
        self.signals.setRowCount(len(evidence.signals))
        for row, signal in enumerate(evidence.signals):
            self.signals.setItem(row, 0, QTableWidgetItem(signal.name))
            self.signals.setItem(row, 1, QTableWidgetItem(signal.value))
            self.signals.setItem(row, 2, QTableWidgetItem(signal.interpretation))
            self.signals.setItem(row, 3, QTableWidgetItem(f"{signal.weight:.1f}"))
        self._store_evidence(evidence)

    def _store_evidence(self, evidence: FingerprintEvidence) -> None:
        existing = self.state.get(evidence.host)
        if existing is not None:
            updated = existing.model_copy(update={"fingerprint": evidence})
        else:
            updated = HostRecord(ip=evidence.host, fingerprint=evidence)
        self.state.upsert(updated)

    def _on_failed(self, message: str) -> None:
        self.run_button.setEnabled(True)
        self.headline.setText("Fingerprint failed.")
