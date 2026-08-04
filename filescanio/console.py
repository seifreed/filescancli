"""Terminal presentation: colour and activity indication.

Colour lives here, not in render(): rendering stays pure and pipes, files,
and -o output never see an escape code. NO_COLOR and FORCE_COLOR follow the
informal standard at https://no-color.org.
"""

import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"

VERDICT_COLOURS = {
    "malicious": ANSI_RED,
    "likely_malicious": ANSI_RED,
    "suspicious": ANSI_YELLOW,
    "benign": ANSI_GREEN,
    "informational": ANSI_GREEN,
    "no_threat": ANSI_GREEN,
    "unknown": ANSI_DIM,
}

_HEADING = re.compile(r"^(.+)\n(=+)$", flags=re.MULTILINE)
_MARKED_VERDICT = re.compile(r"\[([a-z_]+)\]")
_VERDICT_ROW = re.compile(r"^(Verdict +)([a-z_]+)$", flags=re.MULTILINE)
_INTERESTING = re.compile(r"\(interesting\)")


def _paint(word: str) -> str:
    return VERDICT_COLOURS.get(word, "") + word + ANSI_RESET


def colorize_report(text: str) -> str:
    """Bold the headings and colour the verdicts of a rendered report."""
    text = _HEADING.sub(rf"{ANSI_BOLD}\1{ANSI_RESET}\n\2", text)
    text = _MARKED_VERDICT.sub(lambda m: f"[{_paint(m.group(1))}]", text)
    text = _VERDICT_ROW.sub(lambda m: m.group(1) + _paint(m.group(2)), text)
    return _INTERESTING.sub(f"{ANSI_YELLOW}(interesting){ANSI_RESET}", text)


def wants_colour(stream: Any) -> bool:
    """Whether the stream should see colour; NO_COLOR outranks FORCE_COLOR."""
    if "NO_COLOR" in os.environ:
        return False
    if "FORCE_COLOR" in os.environ:
        return True
    return bool(stream.isatty())


SPINNER_FRAMES = "|/-\\"
SPINNER_INTERVAL = 0.1


class Spinner:
    """A one-line activity indicator on whatever stream it is handed."""

    def __init__(
        self, stream: Any, label: str, *, interval: float = SPINNER_INTERVAL
    ) -> None:
        self._stream = stream
        self._label = label
        self._interval = interval
        self._halt = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._turns = 0

    def _write_frame(self) -> None:
        frame = SPINNER_FRAMES[self._turns % len(SPINNER_FRAMES)]
        self._turns += 1
        self._stream.write(f"\r{frame} {self._label}")
        self._stream.flush()

    def _spin(self) -> None:
        while not self._halt.wait(self._interval):
            self._write_frame()

    def start(self) -> None:
        self._write_frame()
        self._thread.start()

    def stop(self) -> None:
        self._halt.set()
        self._thread.join()
        self._stream.write("\r" + " " * (len(self._label) + 2) + "\r")
        self._stream.flush()


@contextmanager
def spinning(stream: Any, label: str) -> Iterator[None]:
    """Spin on the stream while the body runs, only when a person is watching."""
    if not wants_colour(stream):
        yield
        return
    spinner = Spinner(stream, label)
    spinner.start()
    try:
        yield
    finally:
        spinner.stop()
