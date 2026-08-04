"""CLI tests that depend on POSIX process and pipe semantics.

A write to a pipe whose reader is gone raises BrokenPipeError on POSIX; on
Windows the shutdown path differs, so these cannot run there. Collected with
the suite but kept out of the coverage scope, like the rest of posix/.
"""

import contextlib
import os
import sys

import pytest

from filescanio.cli import main

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX pipe semantics")


def test_broken_pipe_exits_cleanly(api_server: str) -> None:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    old_stdout = sys.stdout
    sys.stdout = os.fdopen(write_fd, "w")
    try:
        exit_code = main(
            ["--api-key", "k" * 20000, "--base-url", api_server, "system", "info"]
        )
    finally:
        broken_stream = sys.stdout
        sys.stdout = old_stdout
        with contextlib.suppress(OSError):
            broken_stream.close()
    assert exit_code == 1


def test_help_on_a_broken_pipe_stays_quiet() -> None:
    """`filescan --help | head` must not leave the interpreter complaining."""
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    old_stdout = sys.stdout
    sys.stdout = os.fdopen(write_fd, "w")
    try:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
    finally:
        broken_stream = sys.stdout
        sys.stdout = old_stdout
        with contextlib.suppress(OSError):
            broken_stream.close()
    assert excinfo.value.code == 0
