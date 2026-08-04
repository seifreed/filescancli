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
    titles = (
        "Overview",
        "Tags",
        "Signal groups",
        "File details",
        "Emulation overview",
        "Emulation actions",
        "IOCs",
        "Disassembly",
        "YARA matches",
        "Interesting strings",
        "Extracted files",
    )
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


def test_emulation_overview_counts_calls_most_called_first() -> None:
    rendered = render_report(FULL_REPORT)
    assert re.search(line("WriteFile", "5"), rendered, re.MULTILINE)
    assert rendered.index("WriteFile") < rendered.index("CreateFileW")
    assert re.search(line("Duration", "3ms"), rendered, re.MULTILINE)


def test_emulation_actions_are_named_and_detailed() -> None:
    rendered = render_report(FULL_REPORT)
    assert "CallAPI (interesting) kernel32 CreateFileW" in rendered
    assert re.search(line("  Arguments", "path=C:\\evil.tmp"), rendered, re.MULTILINE)
    assert "WriteMemory 0x5000" in rendered
    assert "0xdeadbeef" not in rendered


def test_disassembly_summarises_each_region() -> None:
    rendered = render_report(FULL_REPORT)
    assert "RVA 0x1000: entry point, 2 instructions" in rendered


def test_strings_keep_only_the_interesting_ones() -> None:
    rendered = render_report(FULL_REPORT)
    assert "cmd.exe /c whoami (Static Analysis)" in rendered
    assert "hello" not in rendered


def test_iocs_list_only_populated_categories() -> None:
    rendered = render_report(FULL_REPORT)
    assert "URLs" in rendered
    assert "  http://evil.example/c2 (interesting)" in rendered
    assert "Domains" in rendered
    assert "  evil.example" in rendered
    assert "Registry paths" not in rendered
    assert "SHA-512 hashes" not in rendered


def test_yara_matches_show_verdict_matches_and_metadata() -> None:
    rendered = render_report(FULL_REPORT)
    assert "win_upx_packed [suspicious]" in rendered
    assert re.search(line("  Matches", "UPX0, UPX1"), rendered, re.MULTILINE)
    assert re.search(line("  author", "analyst"), rendered, re.MULTILINE)


def test_extracted_files_show_facts_digests_and_metadata() -> None:
    rendered = render_report(FULL_REPORT)
    assert "payload.bin" in rendered
    assert re.search(line("  Type", "application/octet-stream"), rendered, re.MULTILINE)
    assert re.search(line("  Size", "1 KiB"), rendered, re.MULTILINE)
    assert re.search(line("  Tags", "dropped"), rendered, re.MULTILINE)
    assert re.search(line("  SHA-256", "f" * 64), rendered, re.MULTILINE)
    assert re.search(line("  entropy", "7.9"), rendered, re.MULTILINE)


def test_no_trailing_whitespace() -> None:
    rendered = render_report(FULL_REPORT)
    assert all(row == row.rstrip() for row in rendered.splitlines())


def test_no_ansi_escapes() -> None:
    assert "\x1b" not in render_report(FULL_REPORT)
