from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from packetforge.models.discovery import DiscoveryRun


def default_history_dir() -> Path:
    return Path.home() / ".packetforge" / "history"


class DiscoveryHistory:
    """Local, on-disk store of discovery runs (one JSON file per run)."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or default_history_dir()

    def save(self, run: DiscoveryRun) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{run.id}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(run.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(path)
        return path

    def list_runs(self) -> list[DiscoveryRun]:
        if not self.directory.exists():
            return []
        runs: list[DiscoveryRun] = []
        for path in self.directory.glob("*.json"):
            try:
                runs.append(DiscoveryRun.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        runs.sort(key=lambda run: run.started_at, reverse=True)
        return runs

    def load(self, run_id: str) -> DiscoveryRun | None:
        path = self.directory / f"{run_id}.json"
        if not path.exists():
            return None
        try:
            return DiscoveryRun.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def delete(self, run_id: str) -> bool:
        path = self.directory / f"{run_id}.json"
        if path.exists():
            path.unlink()
            return True
        return False


@dataclass(frozen=True)
class RunComparison:
    added_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    common_hosts: list[str] = field(default_factory=list)
    changed_ports: dict[str, dict[str, list[int]]] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        return (
            f"+{len(self.added_hosts)} new, -{len(self.removed_hosts)} gone, "
            f"{len(self.common_hosts)} common, {len(self.changed_ports)} with port changes"
        )


def compare_runs(baseline: DiscoveryRun, candidate: DiscoveryRun) -> RunComparison:
    base_hosts = {host.ip: host for host in baseline.hosts}
    cand_hosts = {host.ip: host for host in candidate.hosts}
    base_ips = set(base_hosts)
    cand_ips = set(cand_hosts)

    added = sorted(cand_ips - base_ips)
    removed = sorted(base_ips - cand_ips)
    common = sorted(base_ips & cand_ips)

    changed: dict[str, dict[str, list[int]]] = {}
    for ip in common:
        before = set(base_hosts[ip].open_ports)
        after = set(cand_hosts[ip].open_ports)
        opened = sorted(after - before)
        closed = sorted(before - after)
        if opened or closed:
            changed[ip] = {"opened": opened, "closed": closed}
    return RunComparison(
        added_hosts=added,
        removed_hosts=removed,
        common_hosts=common,
        changed_ports=changed,
    )
