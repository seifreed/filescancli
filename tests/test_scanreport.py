"""Tests for the readable report renderer."""

import re

import pytest

from filescanio.errors import Unrepresentable
from filescanio.scanreport import render_report
from tests.reportdata import BARE_REPORT, FULL_REPORT


def line(label: str, value: str) -> str:
    return rf"^{re.escape(label)} +{re.escape(value)}$"


def test_rejects_a_non_mapping() -> None:
    with pytest.raises(Unrepresentable):
        render_report([1, 2])


def test_rejects_a_response_without_reports() -> None:
    with pytest.raises(Unrepresentable):
        render_report({"reports": {}})


def test_bare_report_is_exactly_the_overview() -> None:
    assert render_report(BARE_REPORT) == "Overview\n========\nVerdict  unknown"


def test_overview_shows_the_verdict_and_submission_facts() -> None:
    rendered = render_report(FULL_REPORT)
    assert re.search(line("Verdict", "malicious"), rendered, re.MULTILINE)
    assert re.search(line("Confidence", "95%"), rendered, re.MULTILINE)
    assert re.search(line("File name", "dropper.exe"), rendered, re.MULTILINE)
    assert re.search(line("SHA-256", "a" * 64), rendered, re.MULTILINE)
    assert re.search(
        line("Media type", "application/x-msdownload"), rendered, re.MULTILINE
    )


def test_tags_are_joined_and_nameless_tags_dropped() -> None:
    rendered = render_report(FULL_REPORT)
    assert re.search(line("Tags", "peexe, trojan"), rendered, re.MULTILINE)


def test_headings_appear_in_report_order() -> None:
    rendered = render_report(FULL_REPORT)
    positions = [rendered.index(title) for title in ("Overview", "Tags")]
    assert positions == sorted(positions)


def test_no_trailing_whitespace() -> None:
    rendered = render_report(FULL_REPORT)
    assert all(row == row.rstrip() for row in rendered.splitlines())


def test_no_ansi_escapes() -> None:
    assert "\x1b" not in render_report(FULL_REPORT)
