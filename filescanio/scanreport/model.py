"""Domain readers over a decoded scan response.

Shared by every presentation of a report: SARIF and the readable renderer
both ask the same questions of the same loosely-typed payload.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from filescanio.scanreport._access import at, mapping, numeric, records


def reports_of(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The per-file reports, however the server chose to key them."""
    reports = value.get("reports")
    if isinstance(reports, Mapping):
        return records(list(reports.values()))
    return records(reports)


def signal_groups(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The report's signal groups, when it carries any."""
    return records(report.get("allSignalGroups"))


def strength(group: Mapping[str, Any]) -> float:
    """A group's strength; the API reports it as a string, parsed leniently."""
    try:
        return float(str(group.get("strength", "")))
    except ValueError:
        return 0.0


def verdict_of(report: Mapping[str, Any]) -> str:
    """The final verdict, lower-cased, or "unknown"."""
    verdict = at(report, "finalVerdict", "verdict")
    return str(verdict).lower() if verdict is not None else "unknown"


def threat_level(report: Mapping[str, Any]) -> float | None:
    """The threat level, when the server sent a usable number."""
    return numeric(at(report, "finalVerdict", "threatLevel"))


@dataclass(frozen=True, slots=True)
class ScanReport:
    """One per-file report together with the flow response that carried it."""

    flow: Mapping[str, Any]
    report: Mapping[str, Any]

    def resource(self, name: str) -> Mapping[str, Any]:
        """The first resource of the given kind, or an empty one."""
        for candidate in mapping(self.report.get("resources")).values():
            if at(candidate, "resourceReference", "name") == name:
                return mapping(candidate)
        return {}
