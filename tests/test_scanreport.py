"""Tests for the readable report renderer."""

import re

import pytest

from filescanio.errors import Unrepresentable
from filescanio.scanreport import render_report
from tests.reportdata import BARE_REPORT, FULL_REPORT, TYPED_REPORTS


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
    assert re.search(line("Tags", "trojan, peexe"), rendered, re.MULTILINE)


def test_headings_appear_in_report_order() -> None:
    rendered = render_report(FULL_REPORT)
    titles = ("Overview", "Tags", "Signal groups", "File details")
    positions = [rendered.index(title) for title in titles]
    assert positions == sorted(positions)


def test_signal_groups_come_most_threatening_first() -> None:
    rendered = render_report(FULL_REPORT)
    strong = rendered.index("Writes to another process [malicious]")
    weak = rendered.index("Contains long flat data streams [informational]")
    assert strong < weak


def test_signal_group_facts_are_indented_under_it() -> None:
    rendered = render_report(FULL_REPORT)
    assert re.search(line("  Tags", "injection"), rendered, re.MULTILINE)
    assert re.search(
        line(
            "  MITRE",
            "Defense Evasion / Process Injection, Obfuscated Files or Information",
        ),
        rendered,
        re.MULTILINE,
    )
    assert re.search(
        line("  Signals", "Opens a remote process / Static Analysis"),
        rendered,
        re.MULTILINE,
    )


def test_file_details_cover_magic_size_digests_and_pe_facts() -> None:
    rendered = render_report(FULL_REPORT)
    assert re.search(
        line("Description", "PE32 executable (GUI) Intel 80386"), rendered, re.MULTILINE
    )
    assert re.search(line("Size", "4 KiB"), rendered, re.MULTILINE)
    assert re.search(line("MD5", "b" * 32), rendered, re.MULTILINE)
    assert re.search(line("Imphash", "c" * 32), rendered, re.MULTILINE)
    assert re.search(line("Packers", "UPX"), rendered, re.MULTILINE)
    assert re.search(line("Signed", "no"), rendered, re.MULTILINE)
    assert re.search(line("Packed", "yes"), rendered, re.MULTILINE)
    assert re.search(line("Compiled", "2020-01-01T00:00:00Z"), rendered, re.MULTILINE)


@pytest.mark.parametrize(
    ("kind", "label", "value"),
    [
        ("pe", "Architecture", "x86"),
        ("elf", "Size", "100 B"),
        ("pdf", "Author", "Mallory"),
        ("office", "VBA stomping", "yes"),
        ("lnk", "Size", "0 B"),
        ("mbox", "Subject", "invoice"),
    ],
)
def test_each_file_kind_shows_its_own_fields(kind: str, label: str, value: str) -> None:
    rendered = render_report(TYPED_REPORTS[kind])
    assert re.search(line(label, value), rendered, re.MULTILINE)


def test_no_trailing_whitespace() -> None:
    rendered = render_report(FULL_REPORT)
    assert all(row == row.rstrip() for row in rendered.splitlines())


def test_no_ansi_escapes() -> None:
    assert "\x1b" not in render_report(FULL_REPORT)
