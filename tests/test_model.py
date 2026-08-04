"""Tests for the shared scan-report readers."""

from typing import Any

import pytest

from filescanio.scanreport.model import (
    ScanReport,
    reports_of,
    signal_groups,
    strength,
    threat_level,
    verdict_label,
    verdict_of,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"reports": {"x": {"a": 1}, "y": "junk"}}, [{"a": 1}]),
        ({"reports": [{"a": 1}, "junk"]}, [{"a": 1}]),
        ({"reports": "junk"}, []),
        ({}, []),
    ],
)
def test_reports_of(value: dict[str, Any], expected: list[Any]) -> None:
    assert reports_of(value) == expected


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"allSignalGroups": [{"id": "g"}, 3]}, [{"id": "g"}]),
        ({"allSignalGroups": "junk"}, []),
        ({}, []),
    ],
)
def test_signal_groups(report: dict[str, Any], expected: list[Any]) -> None:
    assert signal_groups(report) == expected


@pytest.mark.parametrize(
    ("group", "expected"),
    [
        ({"strength": "0.75"}, 0.75),
        ({"strength": 1}, 1.0),
        ({"strength": "n/a"}, 0.0),
        ({}, 0.0),
    ],
)
def test_strength(group: dict[str, Any], expected: float) -> None:
    assert strength(group) == expected


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"finalVerdict": {"verdict": "Malicious"}}, "malicious"),
        ({"finalVerdict": {}}, "unknown"),
        ({"finalVerdict": "junk"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_verdict_of(report: dict[str, Any], expected: str) -> None:
    assert verdict_of(report) == expected


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"finalVerdict": {"threatLevel": 0.9}}, 0.9),
        ({"finalVerdict": {"threatLevel": True}}, None),
        ({"finalVerdict": {}}, None),
        ({}, None),
    ],
)
def test_threat_level(report: dict[str, Any], expected: float | None) -> None:
    assert threat_level(report) == expected


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        ({"verdict": {"verdict": "SUSPICIOUS"}}, "suspicious"),
        ({"verdict": {"verdict": "  Malicious "}}, "malicious"),
        ({"verdict": {"verdict": ""}}, "unknown"),
        ({"verdict": {"verdict": 7}}, "unknown"),
        ({"verdict": []}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_verdict_label(node: dict[str, Any], expected: str) -> None:
    assert verdict_label(node) == expected


FILE_RESOURCE = {"resourceReference": {"name": "file"}, "fileSize": 10}


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ({"resources": {"a": "junk", "b": FILE_RESOURCE}}, FILE_RESOURCE),
        ({"resources": {"a": {"resourceReference": {"name": "osint"}}}}, {}),
        ({"resources": "junk"}, {}),
        ({}, {}),
    ],
)
def test_resource_lookup(report: dict[str, Any], expected: dict[str, Any]) -> None:
    assert ScanReport(flow={}, report=report).resource("file") == expected
