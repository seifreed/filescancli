"""Config-file tests that depend on POSIX filesystem semantics.

Windows has no permission bits, no named pipes, and needs privileges for
symlinks, so these cannot run there. They are collected but kept out of the
coverage scope, because a test skipped on one platform counts as uncovered
and would put the coverage gate permanently in the red on Windows.
"""

import os
import sys
from pathlib import Path

import pytest

from filescanio.config import load_settings, write_config
from filescanio.errors import ConfigError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX filesystem semantics")


def test_write_config_replaces_a_symlink_instead_of_following_it(
    tmp_path: Path,
) -> None:
    """Writing through the link would chmod and clobber somebody else's file."""
    victim = tmp_path / "victim"
    victim.write_text("secret")
    victim.chmod(0o644)
    link = tmp_path / "cfg.toml"
    link.symlink_to(victim)

    write_config("planted", config_path=link)

    assert victim.read_text() == "secret"
    assert victim.stat().st_mode & 0o777 == 0o644
    assert not link.is_symlink()
    assert load_settings(config_path=link, env={}).api_key == "planted"


def test_write_config_narrows_an_existing_loose_file(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_text("api_key = 'old'")
    config.chmod(0o666)
    write_config("new", config_path=config)
    assert config.stat().st_mode & 0o777 == 0o600
    assert load_settings(config_path=config, env={}).api_key == "new"


def test_write_config_permissions(tmp_path: Path) -> None:
    config = write_config("secret", config_path=tmp_path / "cfg.toml")
    assert config.stat().st_mode & 0o777 == 0o600


def test_overwriting_a_permissive_file_never_exposes_the_key(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_text('api_key = "old"\n')
    config.chmod(0o666)
    write_config("brand-new-secret", config_path=config)
    assert config.stat().st_mode & 0o777 == 0o600
    assert "brand-new-secret" in config.read_text()


# Guarding the definition rather than the call: os.mkfifo does not exist on
# Windows, and this is the form that lets mypy check the file for that platform
# too instead of reporting the attribute as missing.
if sys.platform != "win32":

    def test_fifo_at_the_config_path_raises_instead_of_hanging(
        tmp_path: Path,
    ) -> None:
        fifo = tmp_path / "cfg.toml"
        os.mkfifo(fifo)
        with pytest.raises(ConfigError, match="not a regular file"):
            load_settings(config_path=fifo, env={})


def test_symlink_loop_at_the_config_path_raises(tmp_path: Path) -> None:
    looped = tmp_path / "cfg.toml"
    looped.symlink_to(looped)
    with pytest.raises(ConfigError, match="Cannot read config file"):
        load_settings(config_path=looped, env={})


def test_unreadable_config_path_raises(tmp_path: Path) -> None:
    """A path under a regular file: Windows reports it missing instead."""
    blocking_file = tmp_path / "afile"
    blocking_file.write_text("not a directory")
    unreadable = blocking_file / "cfg.toml"
    with pytest.raises(ConfigError, match="Cannot read config file"):
        load_settings(config_path=unreadable, env={})
