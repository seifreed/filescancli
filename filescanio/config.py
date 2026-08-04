"""Resolution of API credentials from the environment or a local config file."""

import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from filescanio.errors import ConfigError
from filescanio.transport import BAD_BASE_URL, is_usable_base_url

ENV_API_KEY = "FILESCANIO"
ENV_BASE_URL = "FILESCANIO_BASE_URL"
DEFAULT_BASE_URL = "https://www.filescan.io"
CONFIG_FILENAME = ".filescanio.toml"


@dataclass(frozen=True)
class Settings:
    """Resolved connection settings."""

    api_key: str
    base_url: str


def _toml_string(value: str) -> str:
    """Render a Python string as a TOML basic string."""
    escaped = json.dumps(value, ensure_ascii=False)
    return "".join(
        char if char >= " " and char != "\x7f" else f"\\u{ord(char):04x}"
        for char in escaped
    )


def default_config_path() -> Path:
    return Path.home() / CONFIG_FILENAME


def _read_config_file(path: Path) -> dict[str, str]:
    try:
        if path.exists() and not path.is_file():
            raise ConfigError(f"Config file {path} is not a regular file")
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid UTF-8: {exc}") from exc
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ConfigError(f"Invalid config file {path}: {exc}") from exc
    return {key: value for key, value in data.items() if isinstance(value, str)}


def _base_url(environ: Mapping[str, str], file_values: Mapping[str, str]) -> str:
    """Apply the base URL precedence: environment, then file, then default."""
    return environ.get(ENV_BASE_URL) or file_values.get("base_url") or DEFAULT_BASE_URL


def resolve_base_url(
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve the base URL from the environment or the config file."""
    environ = os.environ if env is None else env
    return _base_url(environ, _read_config_file(config_path or default_config_path()))


def load_settings(
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Resolve settings: environment variables win over the config file."""
    environ = os.environ if env is None else env
    path = config_path or default_config_path()
    file_values = _read_config_file(path)
    api_key = environ.get(ENV_API_KEY) or file_values.get("api_key")
    if not api_key:
        raise ConfigError(
            f"No API key found: set the {ENV_API_KEY} environment variable "
            f"or add 'api_key' to {path}"
        )
    return Settings(api_key=api_key, base_url=_base_url(environ, file_values))


def write_config(
    api_key: str,
    base_url: str = DEFAULT_BASE_URL,
    config_path: Path | None = None,
) -> Path:
    """Write the config file and return its path.

    Any existing file is removed and the replacement created exclusively, so
    a symlink planted at the path is refused rather than followed and the
    0600 creation mode can only be narrowed by the umask, never widened.
    Windows cannot express that mode, and the file relies there on the
    access control list it inherits from its directory.
    """
    if not is_usable_base_url(base_url):
        raise ConfigError(f"Base URL {base_url!r} {BAD_BASE_URL}")
    path = config_path or default_config_path()
    content = (
        f"api_key = {_toml_string(api_key)}\nbase_url = {_toml_string(base_url)}\n"
    )
    try:
        payload = content.encode()
    except UnicodeEncodeError as exc:
        raise ConfigError(f"Config values are not valid UTF-8: {exc}") from exc
    try:
        path.unlink(missing_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Cannot write config file {path}: {exc}") from exc
    return path
