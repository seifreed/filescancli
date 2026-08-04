"""The client — and the httpx it carries — is only imported when needed."""

import subprocess
import sys

import pytest

import filescanio

PROBE = (
    "import sys, filescanio.cli; "
    "print('httpx' in sys.modules); "
    "print('rich' in sys.modules)"
)


def test_the_cli_module_does_not_drag_in_httpx() -> None:
    """A regression guard: a top-level client import doubles CLI startup."""
    proc = subprocess.run(
        [sys.executable, "-c", PROBE], capture_output=True, text=True, check=True
    )
    assert proc.stdout.split() == ["False", "False"]


def test_client_still_resolves_from_the_package() -> None:
    assert filescanio.FileScanClient.__name__ == "FileScanClient"


def test_unknown_package_attribute_still_raises() -> None:
    with pytest.raises(AttributeError):
        _ = filescanio.NoSuchName
