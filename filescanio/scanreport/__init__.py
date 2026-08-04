"""Readable rendering of a filescan.io scan report.

The report is a sequence of sections; each answers with its lines or with
nothing, and the driver drops silent sections — the single emptiness branch
in the whole package.
"""

from collections.abc import Callable, Mapping
from typing import Any

from filescanio.errors import Unrepresentable
from filescanio.scanreport._behaviour import (
    actions,
    disassembly,
    emulation_overview,
    strings,
)
from filescanio.scanreport._details import details
from filescanio.scanreport._findings import extracted_files, iocs, yara
from filescanio.scanreport._intel import geolocation, osint
from filescanio.scanreport._layout import heading
from filescanio.scanreport._verdict import overview, signals, tags
from filescanio.scanreport.model import ScanReport, reports_of

Section = Callable[[ScanReport], list[str]]

SECTIONS: tuple[tuple[str, Section], ...] = (
    ("Overview", overview),
    ("Tags", tags),
    ("Signal groups", signals),
    ("File details", details),
    ("Emulation overview", emulation_overview),
    ("Emulation actions", actions),
    ("IOCs", iocs),
    ("Disassembly", disassembly),
    ("YARA matches", yara),
    ("Interesting strings", strings),
    ("Extracted files", extracted_files),
    ("OSINT", osint),
    ("Geolocation", geolocation),
)


def render_report(value: Any) -> str:
    """Render a scan response as readable text."""
    if not isinstance(value, Mapping):
        raise Unrepresentable("the readable report needs a scan report object")
    reports = reports_of(value)
    if not reports:
        raise Unrepresentable("the response carries no scan reports")
    blocks: list[str] = []
    for report in reports:
        scan = ScanReport(flow=value, report=report)
        for title, section in SECTIONS:
            lines = section(scan)
            if lines:
                blocks.append("\n".join([*heading(title), *lines]))
    return "\n\n".join(blocks)
