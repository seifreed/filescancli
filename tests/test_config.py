import re
from pathlib import Path

import pytest

from filescanio.config import (
    DEFAULT_BASE_URL,
    ENV_API_KEY,
    ENV_BASE_URL,
    Settings,
    default_config_path,
    load_settings,
    resolve_base_url,
    write_config,
)
from filescanio.errors import ConfigError
from tests.conftest import home_env, no_credentials, set_env


def test_env_var_wins_over_file(tmp_path: Path) -> None:
    config = write_config("file-key", config_path=tmp_path / "cfg.toml")
    with set_env(**{ENV_API_KEY: "env-key", ENV_BASE_URL: None}):
        settings = load_settings(config_path=config)
    assert settings == Settings(api_key="env-key", base_url=DEFAULT_BASE_URL)


def test_file_fallback(tmp_path: Path) -> None:
    config = write_config(
        "file-key", base_url="https://example.test", config_path=tmp_path / "cfg.toml"
    )
    with no_credentials():
        settings = load_settings(config_path=config)
    assert settings == Settings(api_key="file-key", base_url="https://example.test")


def test_env_base_url_override(tmp_path: Path) -> None:
    with set_env(**{ENV_API_KEY: "env-key", ENV_BASE_URL: "https://alt.test"}):
        settings = load_settings(config_path=tmp_path / "missing.toml")
    assert settings.base_url == "https://alt.test"


def test_env_base_url_wins_over_a_file_that_also_sets_one(tmp_path: Path) -> None:
    """Both sources populated is the case where precedence actually decides."""
    config = write_config(
        "file-key", base_url="https://from-file.test", config_path=tmp_path / "c.toml"
    )
    with set_env(**{ENV_API_KEY: "env-key", ENV_BASE_URL: "https://from-env.test"}):
        assert load_settings(config_path=config).base_url == "https://from-env.test"
        assert resolve_base_url(config_path=config) == "https://from-env.test"


def test_missing_key_raises(tmp_path: Path) -> None:
    with no_credentials(), pytest.raises(ConfigError):
        load_settings(config_path=tmp_path / "missing.toml")


def test_non_string_values_ignored(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_text('api_key = "k"\nnumber = 5\n')
    settings = load_settings(config_path=config, env={})
    assert settings.api_key == "k"


def test_write_config_escapes_special_characters(tmp_path: Path) -> None:
    tricky = 'ke"y\\with\nnewline'
    config = write_config(tricky, config_path=tmp_path / "cfg.toml")
    settings = load_settings(config_path=config, env={})
    assert settings.api_key == tricky


def test_corrupt_config_file_raises(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_text("api_key = not-valid-toml")
    with pytest.raises(ConfigError, match="Invalid config file"):
        load_settings(config_path=config, env={})


def test_deeply_nested_config_file_raises(tmp_path: Path) -> None:
    """tomllib recurses per bracket, so nesting alone can exhaust the stack."""
    config = tmp_path / "cfg.toml"
    config.write_bytes(b"api_key = " + b"[" * 20000 + b"]" * 20000)
    with pytest.raises(ConfigError, match="Invalid config file"):
        load_settings(config_path=config, env={})


def test_config_path_holding_a_null_byte_raises(tmp_path: Path) -> None:
    target = tmp_path / "bad\x00name.toml"
    with pytest.raises(ConfigError, match="Cannot read config file"):
        load_settings(config_path=target, env={})
    with pytest.raises(ConfigError, match="Cannot write config file"):
        write_config("k", config_path=target)


def test_default_config_path_is_in_home(tmp_path: Path) -> None:
    with set_env(**home_env(tmp_path)):
        assert default_config_path() == tmp_path / ".filescanio.toml"


def test_write_config_unwritable_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot write config file"):
        write_config("k", config_path=tmp_path / "missing-dir" / "cfg.toml")


@pytest.mark.parametrize(
    "base_url",
    [
        pytest.param("https://host/?x=1", id="query string"),
        pytest.param("https://host/#part", id="fragment"),
    ],
)
def test_write_config_refuses_a_base_url_the_client_would_reject(
    tmp_path: Path, base_url: str
) -> None:
    target = tmp_path / "cfg.toml"
    with pytest.raises(ConfigError, match="query string or fragment"):
        write_config("k", base_url=base_url, config_path=target)
    assert not target.exists()


@pytest.mark.parametrize(
    "key", ["key-\U0001f600-end", "a\x7fb\tc"], ids=["astral", "control"]
)
def test_awkward_keys_round_trip(tmp_path: Path, key: str) -> None:
    config = write_config(key, config_path=tmp_path / "cfg.toml")
    assert load_settings(config_path=config, env={}).api_key == key


def test_missing_key_error_names_the_config_path_used(tmp_path: Path) -> None:
    custom = tmp_path / "custom.toml"
    with pytest.raises(ConfigError, match=re.escape(str(custom))):
        load_settings(config_path=custom, env={})


def test_surrogate_key_does_not_destroy_existing_config(tmp_path: Path) -> None:
    config = write_config("goodkey", config_path=tmp_path / "cfg.toml")
    before = config.read_bytes()
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        write_config("bad-\udcff-key", config_path=config)
    assert config.read_bytes() == before


def test_directory_at_the_config_path_raises(tmp_path: Path) -> None:
    directory = tmp_path / "cfg.toml"
    directory.mkdir()
    with pytest.raises(ConfigError, match="not a regular file"):
        load_settings(config_path=directory, env={})


def test_non_utf8_config_file_raises(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_bytes('api_key = "café"'.encode("latin-1"))
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_settings(config_path=config, env={})


def test_config_file_with_bom_is_read(tmp_path: Path) -> None:
    config = tmp_path / "cfg.toml"
    config.write_bytes(b"\xef\xbb\xbf" + b'api_key = "bom-key"\n')
    assert load_settings(config_path=config, env={}).api_key == "bom-key"
