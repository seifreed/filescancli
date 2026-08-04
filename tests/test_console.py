"""Tests for the terminal presentation helpers."""

import io
import time

from filescanio.console import Spinner, colorize_report


def test_colorize_report_paints_headings_verdicts_and_markers() -> None:
    text = "Overview\n========\nVerdict  malicious\nrule [suspicious]\nx (interesting)"
    painted = colorize_report(text)
    assert "\x1b[1mOverview\x1b[0m\n========" in painted
    assert "Verdict  \x1b[31mmalicious\x1b[0m" in painted
    assert "[\x1b[33msuspicious\x1b[0m]" in painted
    assert "\x1b[33m(interesting)\x1b[0m" in painted


def test_spinner_turns_and_cleans_its_line() -> None:
    stream = io.StringIO()
    spinner = Spinner(stream, "busy", interval=0.02)
    spinner.start()
    time.sleep(0.1)
    spinner.stop()
    out = stream.getvalue()
    assert "\r| busy" in out
    assert "\r/ busy" in out
    assert out.endswith("\r" + " " * 6 + "\r")
