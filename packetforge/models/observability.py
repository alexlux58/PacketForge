from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ChartKind = Literal["line", "bar", "scatter", "histogram", "area", "step"]
Severity = Literal["info", "warning", "critical"]

_SEVERITY_RANK: dict[Severity, int] = {"critical": 0, "warning": 1, "info": 2}


class ChartSeries(BaseModel):
    """A chart-ready series. ``x``/``y`` are numeric; ``categories`` align with bars.

    Designed so the GUI can render it directly with PyQtGraph without further
    transformation. Every series is created to answer a specific question, which
    is captured in ``question``.
    """

    model_config = ConfigDict(validate_assignment=True)

    name: str
    x: list[float] = Field(default_factory=list)
    y: list[float] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    kind: ChartKind = "line"
    x_label: str = ""
    y_label: str = ""
    unit: str = ""
    color: str | None = None
    question: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.y


class HeatmapMatrix(BaseModel):
    """Dense matrix for heatmaps. ``values[r][c]`` corresponds to rows[r]/columns[c]."""

    model_config = ConfigDict(validate_assignment=True)

    rows: list[str] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    values: list[list[float]] = Field(default_factory=list)
    title: str = ""
    row_label: str = ""
    col_label: str = ""
    question: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.rows or not self.columns


class TopologyNode(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: str
    label: str
    kind: str  # "subnet" | "group" | "gateway" | "host"
    ip: str | None = None
    subnet: str | None = None
    group: str | None = None
    badges: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    is_gateway: bool = False
    confidence: float = 0.0


class TopologyEdge(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    source: str
    target: str
    kind: str = "subnet"  # "subnet" | "arp" | "passive" | "ttl" | "protocol"
    label: str = ""
    evidence: list[str] = Field(default_factory=list)


class TopologyGraph(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    grouped_by: str = "subnet"


class LatencySummary(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    samples: int = 0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float = 0.0


class AnomalyFinding(BaseModel):
    """A troubleshooting hint backed by explicit evidence.

    Findings deliberately use cautious language ("possible", "likely") and always
    carry the evidence that produced them so engineers can verify before acting.
    """

    model_config = ConfigDict(validate_assignment=True)

    id: str
    category: str
    severity: Severity = "info"
    title: str
    detail: str = ""
    evidence: list[str] = Field(default_factory=list)
    host: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.severity]


class HostInsight(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    subnet: str | None = None
    methods: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None
    is_gateway_candidate: bool = False
    services: list[str] = Field(default_factory=list)
    fingerprint_summary: str = "no fingerprint evidence"
    fingerprint_confidence: float = 0.0
    fingerprint_evidence: list[str] = Field(default_factory=list)
    latency: LatencySummary = Field(default_factory=LatencySummary)
    sparkline: list[float] = Field(default_factory=list)
    protocol_findings: list[str] = Field(default_factory=list)
    anomalies: list[AnomalyFinding] = Field(default_factory=list)


class PortChange(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    host: str
    opened: list[int] = Field(default_factory=list)
    closed: list[int] = Field(default_factory=list)


class LatencyDelta(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    host: str
    before_ms: float | None = None
    after_ms: float | None = None
    delta_ms: float | None = None


class ConfidenceChange(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    host: str
    before: float
    after: float
    delta: float


class RunComparison(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    baseline_label: str = ""
    candidate_label: str = ""
    added_hosts: list[str] = Field(default_factory=list)
    removed_hosts: list[str] = Field(default_factory=list)
    common_hosts: list[str] = Field(default_factory=list)
    port_changes: list[PortChange] = Field(default_factory=list)
    capability_changes: dict[str, list[str]] = Field(default_factory=dict)
    latency_deltas: list[LatencyDelta] = Field(default_factory=list)
    confidence_changes: list[ConfidenceChange] = Field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"+{len(self.added_hosts)} new, -{len(self.removed_hosts)} gone, "
            f"{len(self.common_hosts)} common, {len(self.port_changes)} host(s) with "
            f"port changes"
        )


class ProtocolHealthPanel(BaseModel):
    """Uniform container so the GUI can render any protocol's health the same way."""

    model_config = ConfigDict(validate_assignment=True)

    protocol: str
    headline: str = ""
    series: list[ChartSeries] = Field(default_factory=list)
    table_columns: list[str] = Field(default_factory=list)
    table_rows: list[list[str]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.series and not self.table_rows


class ObservabilityBundle(BaseModel):
    """Everything the Observability tab needs, computed off the GUI thread."""

    model_config = ConfigDict(validate_assignment=True)

    host_count: int = 0
    timeline: ChartSeries = Field(default_factory=lambda: ChartSeries(name="Hosts over time"))
    protocol_distribution: ChartSeries = Field(
        default_factory=lambda: ChartSeries(name="Services")
    )
    reachability: ChartSeries = Field(default_factory=lambda: ChartSeries(name="Reachability"))
    top_talkers: ChartSeries = Field(default_factory=lambda: ChartSeries(name="Most responsive"))
    subnet_coverage: list[ChartSeries] = Field(default_factory=list)
    port_heatmap: HeatmapMatrix = Field(default_factory=HeatmapMatrix)
    confidence_distribution: ChartSeries = Field(
        default_factory=lambda: ChartSeries(name="Fingerprint confidence")
    )
    latency_by_host: dict[str, ChartSeries] = Field(default_factory=dict)
    rolling_by_host: dict[str, ChartSeries] = Field(default_factory=dict)
    jitter_by_host: dict[str, ChartSeries] = Field(default_factory=dict)
    loss_by_host: dict[str, ChartSeries] = Field(default_factory=dict)
    latency_histogram_by_host: dict[str, ChartSeries] = Field(default_factory=dict)
    latency_summary_by_host: dict[str, LatencySummary] = Field(default_factory=dict)
    topology: TopologyGraph = Field(default_factory=TopologyGraph)
    protocol_panels: list[ProtocolHealthPanel] = Field(default_factory=list)
    host_insights: dict[str, HostInsight] = Field(default_factory=dict)
    anomalies: list[AnomalyFinding] = Field(default_factory=list)
