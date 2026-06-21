from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.interfaces import list_interfaces
from packetforge.engine.protocols import bgp, dhcp, dns, ntp, ospf, smtp, snmp, stp
from packetforge.models.discovery import ProtocolProbeResult
from packetforge.ui.state import ObservabilityState
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.workers import ProtocolWorker

ProbeTask = Callable[[], ProtocolProbeResult]


class ProtocolTroubleshooterTab(QWidget):
    def __init__(self, obs_state: ObservabilityState | None = None) -> None:
        super().__init__()
        self.workers: list[ProtocolWorker] = []
        self.obs_state = obs_state

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Protocol Troubleshooter",
                "protocol_troubleshooter",
                subtitle=(
                    "Read-only probes by default. Lab mode enables disruptive traffic — "
                    "lab networks only. Click i for per-protocol safety notes."
                ),
            )
        )

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.tabs.addTab(self._dns_panel(), "DNS")
        self.tabs.addTab(self._dhcp_panel(), "DHCP")
        self.tabs.addTab(self._snmp_panel(), "SNMP")
        self.tabs.addTab(self._smtp_panel(), "SMTP")
        self.tabs.addTab(self._ntp_panel(), "NTP")
        self.tabs.addTab(self._bgp_panel(), "BGP")
        self.tabs.addTab(self._ospf_panel(), "OSPF")
        self.tabs.addTab(self._stp_panel(), "STP")

    # --- shared helpers -------------------------------------------------

    def _output(self) -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont("Menlo", 11))
        return view

    def _run(self, task: ProbeTask, output: QPlainTextEdit, button: QPushButton) -> None:
        button.setEnabled(False)
        self.error_banner.clear()
        output.setPlainText("Running...")
        worker = ProtocolWorker(task)
        worker.completed.connect(lambda result: self._render(result, output))
        worker.completed.connect(lambda _r: button.setEnabled(True))
        worker.failed.connect(lambda msg: self._failed(msg, output, button))
        worker.error_occurred.connect(
            lambda event: self.error_banner.show_event(
                event, on_retry=lambda: self._run(task, output, button)
            )
        )
        worker.finished.connect(lambda: self._forget(worker))
        self.workers.append(worker)
        worker.start()

    def _render(self, result: ProtocolProbeResult, output: QPlainTextEdit) -> None:
        if self.obs_state is not None:
            self.obs_state.add_probe(result)
        lines = [
            f"{result.protocol} -> {result.target}",
            f"status : {'OK' if result.success else 'no/negative result'}",
            f"summary: {result.summary}",
        ]
        if result.latency_ms is not None:
            lines.append(f"latency: {result.latency_ms:.1f} ms")
        if result.lab_mode:
            lines.append("mode   : LAB (active traffic was sent)")
        if result.detail:
            lines.append("")
            lines.append("details:")
            lines.extend(f"  {key}: {value}" for key, value in result.detail.items())
        if result.records:
            lines.append("")
            lines.append("records:")
            lines.extend(f"  {record}" for record in result.records)
        if result.warnings:
            lines.append("")
            lines.append("warnings:")
            lines.extend(f"  ! {warning}" for warning in result.warnings)
        output.setPlainText("\n".join(lines))

    def _failed(self, message: str, output: QPlainTextEdit, button: QPushButton) -> None:
        button.setEnabled(True)
        output.setPlainText(f"Probe error: {message}")

    def _forget(self, worker: ProtocolWorker) -> None:
        if worker in self.workers:
            self.workers.remove(worker)

    def _confirm(self, title: str, message: str) -> bool:
        reply = QMessageBox.warning(
            self,
            title,
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _interface_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem("")
        combo.addItems(list_interfaces())
        return combo

    # --- DNS ------------------------------------------------------------

    def _dns_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        name = QLineEdit("example.com")
        qtype = QComboBox()
        qtype.addItems(list(dns.QTYPES))
        resolver = QLineEdit("1.1.1.1")
        timeout = self._spin(1, 30, 3)
        form.addRow("Name / IP", name)
        form.addRow("Record type", qtype)
        form.addRow("Resolver", resolver)
        form.addRow("Timeout (s)", timeout)

        output = self._output()
        run = QPushButton("Query")
        axfr = QPushButton("Zone transfer (AXFR)...")
        buttons = QHBoxLayout()
        buttons.addWidget(run)
        buttons.addWidget(axfr)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(output, 1)

        def do_query() -> None:
            query = dns.DnsQuery(
                name=name.text().strip(),
                qtype=qtype.currentText(),
                resolver=resolver.text().strip(),
                timeout_s=float(timeout.value()),
            )
            self._run(lambda: dns.resolve(query), output, run)

        def do_axfr() -> None:
            if not self._confirm(
                "Authorized zone transfer",
                "AXFR can dump an entire DNS zone. Only run this against servers and "
                "zones you are explicitly authorized to test.\n\nProceed?",
            ):
                return
            target = name.text().strip()
            resolver_addr = resolver.text().strip()
            self._run(
                lambda: dns.zone_transfer(target, resolver_addr, confirmed=True),
                output,
                axfr,
            )

        run.clicked.connect(do_query)
        axfr.clicked.connect(do_axfr)
        return widget

    # --- DHCP -----------------------------------------------------------

    def _dhcp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        interface = self._interface_combo()
        seconds = self._spin(1, 600, 20)
        lab_mode = QCheckBox("Lab mode: allow active DHCP Discover broadcast")
        form.addRow("Interface", interface)
        form.addRow("Observe seconds", seconds)
        form.addRow(lab_mode)

        output = self._output()
        observe = QPushButton("Passive observe")
        discover = QPushButton("Lab discover")
        buttons = QHBoxLayout()
        buttons.addWidget(observe)
        buttons.addWidget(discover)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(output, 1)

        def do_observe() -> None:
            config = dhcp.DhcpPassiveProbe(
                interface=interface.currentText() or None, seconds=seconds.value()
            )
            self._run(lambda: dhcp.observe(config), output, observe)

        def do_discover() -> None:
            if not lab_mode.isChecked():
                QMessageBox.information(
                    self, "Lab mode required", "Enable Lab mode to broadcast a DHCP Discover."
                )
                return
            if not self._confirm(
                "Broadcast DHCP Discover",
                "This broadcasts a DHCP Discover to the whole segment and may interact with "
                "DHCP servers. Only do this on a network you own.\n\nProceed?",
            ):
                return
            config = dhcp.DhcpDiscoverProbe(
                interface=interface.currentText() or None, lab_mode=True
            )
            self._run(lambda: dhcp.discover(config), output, discover)

        observe.clicked.connect(do_observe)
        discover.clicked.connect(do_discover)
        return widget

    # --- SNMP -----------------------------------------------------------

    def _snmp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        host = QLineEdit("192.168.1.1")
        version = QComboBox()
        version.addItems(["v2c", "v3"])
        community = QLineEdit()
        community.setEchoMode(QLineEdit.EchoMode.Password)
        community.setPlaceholderText("read-only community (never guessed)")
        username = QLineEdit()
        username.setPlaceholderText("SNMPv3 username")
        timeout = self._spin(1, 30, 3)
        form.addRow("Host", host)
        form.addRow("Version", version)
        form.addRow("Community", community)
        form.addRow("v3 username", username)
        form.addRow("Timeout (s)", timeout)

        output = self._output()
        run = QPushButton("Read common OIDs")
        layout.addWidget(run)
        layout.addWidget(output, 1)

        def do_get() -> None:
            config = snmp.SnmpProbe(
                host=host.text().strip(),
                version=version.currentText(),
                community=community.text(),
                v3_username=username.text().strip(),
                timeout_s=float(timeout.value()),
            )
            self._run(lambda: snmp.get(config), output, run)

        run.clicked.connect(do_get)
        return widget

    # --- SMTP -----------------------------------------------------------

    def _smtp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        host = QLineEdit("mail.example.com")
        port = self._spin(1, 65535, 25)
        ehlo = QLineEdit("packetforge.local")
        timeout = self._spin(1, 30, 5)
        form.addRow("Host", host)
        form.addRow("Port", port)
        form.addRow("EHLO name", ehlo)
        form.addRow("Timeout (s)", timeout)

        output = self._output()
        run = QPushButton("Banner + EHLO + STARTTLS check")
        layout.addWidget(run)
        layout.addWidget(output, 1)

        def do_probe() -> None:
            config = smtp.SmtpProbe(
                host=host.text().strip(),
                port=port.value(),
                ehlo_name=ehlo.text().strip() or "packetforge.local",
                timeout_s=float(timeout.value()),
            )
            self._run(lambda: smtp.probe(config), output, run)

        run.clicked.connect(do_probe)
        return widget

    # --- NTP ------------------------------------------------------------

    def _ntp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        host = QLineEdit("pool.ntp.org")
        timeout = self._spin(1, 30, 3)
        form.addRow("Host", host)
        form.addRow("Timeout (s)", timeout)

        output = self._output()
        run = QPushButton("Client time query")
        layout.addWidget(run)
        layout.addWidget(output, 1)

        def do_probe() -> None:
            config = ntp.NtpProbe(host=host.text().strip(), timeout_s=float(timeout.value()))
            self._run(lambda: ntp.probe(config), output, run)

        run.clicked.connect(do_probe)
        return widget

    # --- BGP ------------------------------------------------------------

    def _bgp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        host = QLineEdit("192.0.2.1")
        local_as = self._spin(1, 65535, 65000)
        bgp_id = QLineEdit("10.255.255.1")
        lab_mode = QCheckBox("Lab mode: send a BGP OPEN capability probe")
        timeout = self._spin(1, 30, 4)
        form.addRow("Host", host)
        form.addRow("Local AS", local_as)
        form.addRow("BGP ID", bgp_id)
        form.addRow("Timeout (s)", timeout)
        form.addRow(lab_mode)

        output = self._output()
        run = QPushButton("Probe TCP/179")
        layout.addWidget(run)
        layout.addWidget(output, 1)

        def do_probe() -> None:
            if lab_mode.isChecked() and not self._confirm(
                "Send BGP OPEN",
                "Lab mode sends a BGP OPEN to the peer. Only do this on routers you own.\n\n"
                "Proceed?",
            ):
                return
            config = bgp.BgpProbe(
                host=host.text().strip(),
                local_as=local_as.value(),
                bgp_id=bgp_id.text().strip(),
                lab_mode=lab_mode.isChecked(),
                timeout_s=float(timeout.value()),
            )
            self._run(lambda: bgp.probe(config), output, run)

        run.clicked.connect(do_probe)
        return widget

    # --- OSPF -----------------------------------------------------------

    def _ospf_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        interface = self._interface_combo()
        seconds = self._spin(1, 600, 30)
        router_id = QLineEdit("10.255.255.1")
        area = QLineEdit("0.0.0.0")
        lab_mode = QCheckBox("Lab mode: allow active OSPF Hello")
        form.addRow("Interface", interface)
        form.addRow("Observe seconds", seconds)
        form.addRow("Router ID", router_id)
        form.addRow("Area", area)
        form.addRow(lab_mode)

        output = self._output()
        observe = QPushButton("Passive decode")
        send = QPushButton("Lab Hello")
        buttons = QHBoxLayout()
        buttons.addWidget(observe)
        buttons.addWidget(send)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(output, 1)

        def do_observe() -> None:
            config = ospf.OspfPassiveProbe(
                interface=interface.currentText() or None, seconds=seconds.value()
            )
            self._run(lambda: ospf.observe(config), output, observe)

        def do_send() -> None:
            if not lab_mode.isChecked():
                QMessageBox.information(
                    self, "Lab mode required", "Enable Lab mode to send an OSPF Hello."
                )
                return
            if not self._confirm(
                "Send OSPF Hello",
                "Active OSPF Hellos can form adjacencies and affect routing. Lab routers "
                "only.\n\nProceed?",
            ):
                return
            config = ospf.OspfActiveProbe(
                interface=interface.currentText() or None,
                router_id=router_id.text().strip(),
                area=area.text().strip(),
                lab_mode=True,
            )
            self._run(lambda: ospf.send_hello(config), output, send)

        observe.clicked.connect(do_observe)
        send.clicked.connect(do_send)
        return widget

    # --- STP ------------------------------------------------------------

    def _stp_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form = QFormLayout()
        layout.addLayout(form)
        interface = self._interface_combo()
        seconds = self._spin(1, 600, 30)
        lab_mode = QCheckBox("Lab mode: allow active BPDU")
        form.addRow("Interface", interface)
        form.addRow("Observe seconds", seconds)
        form.addRow(lab_mode)

        output = self._output()
        observe = QPushButton("Passive BPDU decode")
        send = QPushButton("Lab BPDU")
        buttons = QHBoxLayout()
        buttons.addWidget(observe)
        buttons.addWidget(send)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(output, 1)

        def do_observe() -> None:
            config = stp.StpPassiveProbe(
                interface=interface.currentText() or None, seconds=seconds.value()
            )
            self._run(lambda: stp.observe(config), output, observe)

        def do_send() -> None:
            if not lab_mode.isChecked():
                QMessageBox.information(
                    self, "Lab mode required", "Enable Lab mode to send a BPDU."
                )
                return
            if not self._confirm(
                "Send STP BPDU",
                "Active BPDUs can trigger topology changes or root takeover. Lab switches "
                "only.\n\nProceed?",
            ):
                return
            config = stp.StpActiveProbe(interface=interface.currentText() or None, lab_mode=True)
            self._run(lambda: stp.send_bpdu(config), output, send)

        observe.clicked.connect(do_observe)
        send.clicked.connect(do_send)
        return widget

    def _spin(self, minimum: int, maximum: int, value: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        return spin
