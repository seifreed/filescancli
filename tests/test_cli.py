"""End-to-end tests for the CLI against real in-process HTTP servers."""

import io
import json
import runpy
import sys
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import parse_qs

import pytest

from filescanio import __version__
from filescanio.cli import SIMPLE_COMMANDS, _emit, main
from filescanio.config import DEFAULT_BASE_URL, write_config
from filescanio.errors import FileScanError
from filescanio.render import Format
from tests.conftest import (
    SIMPLE_CASES,
    Canned,
    home_env,
    json_server,
    no_credentials,
    send,
    serve,
    set_env,
)


class FlowHandler(BaseHTTPRequestHandler):
    """Serves a minimal scan flow and one endpoint that always fails."""

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        send(self, Canned(200, b'{"flow_id": "f1", "priority": {}}'))

    def do_GET(self) -> None:
        if self.path == "/api/scan/f1/report":
            send(self, Canned(200, b'{"allFinished": true}'))
        else:
            send(self, Canned(500, b'{"detail": "boom"}'))

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def flow_server() -> Iterator[str]:
    with serve(FlowHandler) as base_url:
        yield base_url


def run(base_url: str, *argv: str) -> int:
    return main(["--api-key", "k", "--base-url", base_url, *argv])


def run_echo(
    base_url: str, capsys: pytest.CaptureFixture[str], *argv: str
) -> dict[str, Any]:
    assert run(base_url, *argv) == 0
    echo: dict[str, Any] = json.loads(capsys.readouterr().out)
    return echo


def form_field(name: str, value: str) -> str:
    return f'name="{name}"\r\n\r\n{value}\r\n'


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_simple_cases_cover_every_simple_command() -> None:
    assert {argv for argv, _ in SIMPLE_CASES} == set(SIMPLE_COMMANDS)


@pytest.mark.parametrize(("argv", "expected_path"), SIMPLE_CASES)
def test_simple_commands(
    api_server: str,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, str],
    expected_path: str,
) -> None:
    echo = run_echo(api_server, capsys, *argv)
    assert echo["method"] == "GET"
    assert echo["path"] == expected_path
    assert echo["api_key"] == "k"


def test_scan_file_submits_multipart(
    api_server: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    echo = run_echo(
        api_server,
        capsys,
        "scan",
        "file",
        str(sample),
        "--description",
        "desc",
        "--tags",
        "anti-vm|macros",
        "--password",
        "pw",
        "--propagate-tags",
        "--private",
        "--no-private-report",
        "--skip-whitelisted",
        "--profile",
        "p1",
        "--engine",
        "e1",
    )
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/scan/file"
    assert echo["content_type"].startswith("multipart/form-data")
    body = echo["body"]
    assert 'filename="sample.bin"' in body
    assert "payload" in body
    assert form_field("description", "desc") in body
    assert form_field("tags", "anti-vm|macros") in body
    assert form_field("password", "pw") in body
    assert form_field("propagate_tags", "true") in body
    assert form_field("is_private", "true") in body
    assert form_field("is_private_report", "false") in body
    assert form_field("skip_whitelisted", "true") in body
    assert form_field("scan_profile", "p1") in body
    assert form_field("scan_engine", "e1") in body


class Request(TypedDict, total=False):
    """The HTTP request a CLI invocation is expected to produce."""

    method: str
    path: str
    query: dict[str, list[str]]
    json_body: Any
    form: dict[str, list[str]]


REQUEST_CASES = [
    pytest.param(
        ("scan", "url", "https://example.com"),
        {
            "method": "POST",
            "path": "/api/scan/url",
            "form": {"url": ["https://example.com"]},
        },
        id="scan url",
    ),
    pytest.param(
        ("scan", "report", "fid", "--filter", "f1", "--filter", "f2"),
        {
            "method": "GET",
            "path": "/api/scan/fid/report",
            "query": {"filter": ["f1", "f2"]},
        },
        id="scan report with filters",
    ),
    pytest.param(
        ("scan", "report", "fid"),
        {"method": "GET", "path": "/api/scan/fid/report"},
        id="scan report without filters",
    ),
    pytest.param(
        (
            "--timeout",
            "30",
            "scan",
            "report",
            "f1",
            "--filter",
            "general",
            "--sorting",
            "date",
            "--other",
            "x",
        ),
        {
            "method": "GET",
            "path": "/api/scan/f1/report",
            "query": {"filter": ["general"], "sorting": ["date"], "other": ["x"]},
        },
        id="scan report with sorting and other",
    ),
    pytest.param(
        ("report", "rid", "hash", "--filter", "f1"),
        {"method": "GET", "path": "/api/reports/rid/hash", "query": {"filter": ["f1"]}},
        id="report with filter",
    ),
    pytest.param(
        ("report", "rid", "hash"),
        {"method": "GET", "path": "/api/reports/rid/hash"},
        id="report without filter",
    ),
    pytest.param(
        ("report", "r1", "h1", "--sorting", "date", "--other", "x"),
        {
            "method": "GET",
            "path": "/api/reports/r1/h1",
            "query": {"sorting": ["date"], "other": ["x"]},
        },
        id="report with sorting and other",
    ),
    pytest.param(
        ("search", "trojan", "--page", "2", "--page-size", "10"),
        {
            "method": "GET",
            "path": "/api/reports/search",
            "query": {"query": ["trojan"], "page": ["2"], "page_size": ["10"]},
        },
        id="search with all options",
    ),
    pytest.param(
        ("search",),
        {"method": "GET", "path": "/api/reports/search"},
        id="search defaults",
    ),
    pytest.param(
        ("reports", "public", "--page", "1", "--page-size", "5"),
        {
            "method": "GET",
            "path": "/api/reports",
            "query": {"page": ["1"], "page_size": ["5"]},
        },
        id="reports public",
    ),
    pytest.param(
        (
            "reports",
            "matches",
            "r1",
            "r2",
            "--unique-files",
            "--method",
            "and",
            "--filter",
            "verdict=malicious",
        ),
        {
            "method": "POST",
            "path": "/api/reports/search/matches",
            "query": {
                "unique_files": ["true"],
                "method": ["and"],
                "verdict": ["malicious"],
            },
            "json_body": {"reports_ids": ["r1", "r2"]},
        },
        id="reports matches",
    ),
    pytest.param(
        ("reports", "matches", "r1", "--method", "or", "--filter", "method=and"),
        {
            "method": "POST",
            "path": "/api/reports/search/matches",
            "query": {"method": ["and"]},
            "json_body": {"reports_ids": ["r1"]},
        },
        id="a matches filter overrides the named option it collides with",
    ),
    pytest.param(
        ("files", "availability", "h1", "h2"),
        {
            "method": "POST",
            "path": "/api/files/availability",
            "json_body": ["h1", "h2"],
        },
        id="files availability",
    ),
    pytest.param(
        (
            "similarity",
            "h",
            "--min-similarity",
            "50",
            "--verdict",
            "malicious",
            "--tag",
            "t1",
            "--tag",
            "t2",
        ),
        {
            "method": "GET",
            "path": "/api/similarity-search/similarity",
            "query": {
                "hash": ["h"],
                "min_similarity": ["50"],
                "verdict": ["malicious"],
                "tags": ["t1", "t2"],
            },
        },
        id="similarity with all options",
    ),
    pytest.param(
        ("similarity", "h"),
        {
            "method": "GET",
            "path": "/api/similarity-search/similarity",
            "query": {"hash": ["h"]},
        },
        id="similarity defaults",
    ),
    pytest.param(
        ("reputation", "hash", "h1"),
        {"method": "POST", "path": "/api/reputation/hash", "json_body": ["h1"]},
        id="reputation hash, one value",
    ),
    pytest.param(
        ("reputation", "hash", "h1", "h2"),
        {"method": "POST", "path": "/api/reputation/hash", "json_body": ["h1", "h2"]},
        id="reputation hash, several values",
    ),
    pytest.param(
        ("reputation", "ioc", "domain", "example.com"),
        {
            "method": "POST",
            "path": "/api/reputation/domain",
            "json_body": ["example.com"],
        },
        id="reputation ioc, one value",
    ),
    pytest.param(
        ("reputation", "ioc", "ip", "1.1.1.1", "2.2.2.2"),
        {
            "method": "POST",
            "path": "/api/reputation/ip",
            "json_body": ["1.1.1.1", "2.2.2.2"],
        },
        id="reputation ioc, several values",
    ),
    pytest.param(
        (
            "threatintel",
            "prevalence",
            "--domain",
            "d1",
            "--domain",
            "d2",
            "--sha256",
            "s",
            "--days",
            "7",
            "--exclude-report-id",
            "r1",
        ),
        {
            "method": "POST",
            "path": "/api/threatintel/get-prevalence",
            "query": {"exclude_report_ids": ["r1"]},
            "json_body": {"domain": ["d1", "d2"], "sha256": ["s"], "days": 7},
        },
        id="threatintel prevalence",
    ),
    pytest.param(
        ("threatintel", "prevalence", "--revision-save-id", "r1"),
        {
            "method": "POST",
            "path": "/api/threatintel/get-prevalence",
            "json_body": {"revision_save_id": ["r1"]},
        },
        id="threatintel prevalence with a revision save id",
    ),
    pytest.param(
        (
            "threatintel",
            "similars",
            "--imphash",
            "i",
            "--ssdeep",
            "s",
            "--days",
            "3",
            "--exclude-report-id",
            "r1",
        ),
        {
            "method": "GET",
            "path": "/api/threatintel/get-similars",
            "query": {
                "imphash": ["i"],
                "ssdeep": ["s"],
                "days": ["3"],
                "exclude_report_ids": ["r1"],
            },
        },
        id="threatintel similars",
    ),
    pytest.param(
        ("system", "terms", "privacy-policy"),
        {"method": "GET", "path": "/api/system/get-terms/privacy-policy"},
        id="system terms",
    ),
    pytest.param(
        ("system", "translations", "en"),
        {"method": "GET", "path": "/api/system/translations/en"},
        id="system translations",
    ),
    pytest.param(
        ("system", "healthcheck", "--days", "1", "--days-from", "2"),
        {
            "method": "GET",
            "path": "/api/system/query-healthcheck",
            "query": {"days": ["1"], "days_from": ["2"]},
        },
        id="system healthcheck with options",
    ),
    pytest.param(
        ("system", "healthcheck"),
        {"method": "GET", "path": "/api/system/query-healthcheck"},
        id="system healthcheck defaults",
    ),
    pytest.param(
        ("system", "news-remove", "n1"),
        {"method": "DELETE", "path": "/api/system/news", "query": {"news_id": ["n1"]}},
        id="system news-remove",
    ),
    pytest.param(
        (
            "misc",
            "oauth-callback",
            "--state",
            "s",
            "--code",
            "c",
            "--error",
            "e",
            "--error-description",
            "d",
        ),
        {
            "method": "GET",
            "path": "/api/admin/scan-sources/oauth/callback",
            "query": {
                "state": ["s"],
                "code": ["c"],
                "error": ["e"],
                "error_description": ["d"],
            },
        },
        id="misc oauth-callback",
    ),
]


@pytest.mark.parametrize(("argv", "expected"), REQUEST_CASES)
def test_command_sends_the_expected_request(
    api_server: str,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    expected: Request,
) -> None:
    """Each command turns its arguments into one specific HTTP request."""
    echo = run_echo(api_server, capsys, *argv)
    assert echo["method"] == expected["method"]
    assert echo["path"] == expected["path"]
    assert echo["query"] == expected.get("query", {})
    if "json_body" in expected:
        assert json.loads(echo["body"]) == expected["json_body"]
    if "form" in expected:
        assert parse_qs(echo["body"]) == expected["form"]


def test_scan_file_wait_polls_until_finished(
    flow_server: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    assert run(flow_server, "scan", "file", str(sample), "--wait") == 0
    assert json.loads(capsys.readouterr().out) == {"allFinished": True}


def test_scan_url_wait_polls_until_finished(
    flow_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(flow_server, "scan", "url", "https://example.com", "--wait") == 0
    assert json.loads(capsys.readouterr().out) == {"allFinished": True}


@pytest.mark.parametrize("pair", ["badpair", "=value"])
def test_search_invalid_filter_exits_one(
    api_server: str, capsys: pytest.CaptureFixture[str], pair: str
) -> None:
    assert run(api_server, "reports", "matches", "r1", "--filter", pair) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"error: Invalid filter '{pair}', expected key=value" in captured.err


def test_system_yara_writes_output_file(
    api_server: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    out = tmp_path / "rules.bin"
    args = ("-o", str(out), "system", "yara", "--name", "n1", "--name", "n2")
    assert run(api_server, *args) == 0
    assert capsys.readouterr().out == ""
    echo: dict[str, Any] = json.loads(out.read_bytes())
    assert echo["path"] == "/api/system/yara"
    assert echo["query"] == {"name": ["n1", "n2"]}


@pytest.mark.parametrize(
    ("argv", "path", "query"),
    [
        pytest.param(("system", "yara"), "/api/system/yara", {}, id="yara rules"),
        pytest.param(
            ("users", "avatar", "acct1"),
            "/api/users/acct1/avatar",
            {},
            id="account avatar",
        ),
        pytest.param(
            ("system", "logo", "--type", "main", "--theme", "dark", "--name", "logo"),
            "/api/system/logo",
            {"type": ["main"], "theme": ["dark"], "name": ["logo"]},
            id="site logo",
        ),
    ],
)
def test_binary_responses_go_to_stdout(
    api_server: str,
    capsysbinary: pytest.CaptureFixture[bytes],
    argv: tuple[str, ...],
    path: str,
    query: dict[str, list[str]],
) -> None:
    assert run(api_server, *argv) == 0
    echo: dict[str, Any] = json.loads(capsysbinary.readouterr().out)
    assert echo["method"] == "GET"
    assert echo["path"] == path
    assert echo["query"] == query


def test_system_news_save_from_file(
    api_server: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    payload = tmp_path / "news.json"
    payload.write_text('{"title": "hello"}')
    echo = run_echo(api_server, capsys, "system", "news-save", "--file", str(payload))
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/system/news"
    assert json.loads(echo["body"]) == {"title": "hello"}


def test_system_log_error_reads_stdin(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO('{"message": "café"}'.encode()))
    try:
        code = run(api_server, "system", "log-error", "--file", "-")
    finally:
        sys.stdin = original
    assert code == 0
    echo: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/system/errors/log"
    assert json.loads(echo["body"]) == {"message": "café"}


def test_config_init_with_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    target = tmp_path / "cfg.toml"
    argv = [
        "config",
        "init",
        "--api-key",
        "secret",
        "--base-url",
        "https://alt.test",
        "--path",
        str(target),
    ]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out) == {"written": str(target)}
    assert target.read_text() == 'api_key = "secret"\nbase_url = "https://alt.test"\n'


def test_config_init_default_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with set_env(**home_env(tmp_path)):
        assert main(["config", "init", "--api-key", "secret"]) == 0
    expected = tmp_path / ".filescanio.toml"
    assert json.loads(capsys.readouterr().out) == {"written": str(expected)}
    assert f'base_url = "{DEFAULT_BASE_URL}"' in expected.read_text()


def test_config_show_with_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    target = tmp_path / "cfg.toml"
    target.write_text('api_key = "secret-key"\nbase_url = "https://alt.test"\n')
    with no_credentials():
        assert main(["config", "show", "--path", str(target)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "api_key": "secr***",
        "base_url": "https://alt.test",
    }


def test_config_show_default_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with no_credentials(tmp_path):
        assert main(["config", "init", "--api-key", "home-key-long"]) == 0
        capsys.readouterr()
        assert main(["config", "show"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "api_key": "home***",
        "base_url": DEFAULT_BASE_URL,
    }


def test_api_error_exits_with_the_server_error_code(
    flow_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(flow_server, "system", "info") == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error: HTTP 500: boom" in captured.err


def test_raw_output_is_compact(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "--raw", "system", "info") == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    echo: dict[str, Any] = json.loads(out)
    assert echo["path"] == "/api/system/info"


def test_pretty_output_is_indented(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "system", "info") == 0
    assert capsys.readouterr().out.startswith('{\n  "method"')


@pytest.mark.parametrize(
    ("content", "message"),
    [
        pytest.param(b"{not json", "Invalid JSON", id="not json at all"),
        pytest.param(
            '{"message": "café"}'.encode("latin-1"),
            "not valid UTF-8",
            id="not utf-8",
        ),
    ],
)
def test_unreadable_json_input_exits_one(
    api_server: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    content: bytes,
    message: str,
) -> None:
    payload = tmp_path / "payload.json"
    payload.write_bytes(content)
    assert run(api_server, "system", "news-save", "--file", str(payload)) == 1
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("filename", "command", "path"),
    [
        pytest.param("out.json", "info", "/api/system/info", id="json response"),
        pytest.param("logo.svg", "logo", "/api/system/logo", id="binary response"),
    ],
)
def test_output_is_written_to_the_file_instead_of_stdout(
    api_server: str,
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    filename: str,
    command: str,
    path: str,
) -> None:
    target = tmp_path / filename
    assert run(api_server, "-o", str(target), "system", command) == 0
    assert capsysbinary.readouterr().out == b""
    assert json.loads(target.read_bytes())["path"] == path


def test_network_failure_exits_with_the_transport_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        ["--api-key", "k", "--base-url", "http://127.0.0.1:1", "system", "info"]
    )
    assert exit_code == 6
    assert "Network error" in capsys.readouterr().err


def test_missing_json_file_exits_one(
    api_server: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run(
        api_server, "system", "news-save", "--file", str(tmp_path / "missing.json")
    )
    assert exit_code == 1
    assert "Cannot read" in capsys.readouterr().err


def test_scan_missing_file_exits_one(
    api_server: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run(api_server, "scan", "file", str(tmp_path / "missing.bin"))
    assert exit_code == 1
    assert "Cannot read" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("filename", "command"), [("out.json", "info"), ("logo.svg", "logo")]
)
def test_output_to_unwritable_path_exits_one(
    api_server: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    filename: str,
    command: str,
) -> None:
    """A JSON response and a binary one report the same failure."""
    target = tmp_path / "missing-dir" / filename
    exit_code = run(api_server, "-o", str(target), "system", command)
    assert exit_code == 1
    assert "Cannot write" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["-1", "0", "nan", "inf"])
def test_invalid_timeout_rejected(api_server: str, value: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run(api_server, "--timeout", value, "system", "info")
    assert excinfo.value.code == 2


def test_empty_output_path_reports_error(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run(api_server, "-o", "", "system", "info")
    assert exit_code == 1
    assert "Cannot write" in capsys.readouterr().err


def test_wait_without_flow_id_reports_error(
    api_server: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    exit_code = run(api_server, "scan", "file", str(sample), "--wait")
    assert exit_code == 1
    assert "no flow_id" in capsys.readouterr().err


def test_config_show_honours_global_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "cfg.toml"
    write_config("file-key-long", base_url="http://file.example", config_path=config)
    exit_code = main(
        [
            "--api-key",
            "cli-key-long",
            "--base-url",
            "http://cli.example",
            "config",
            "show",
            "--path",
            str(config),
        ]
    )
    assert exit_code == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown == {"api_key": "cli-***", "base_url": "http://cli.example"}


def test_config_show_masks_short_keys_entirely(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "cfg.toml"
    write_config("ab", config_path=config)
    with no_credentials():
        exit_code = main(["config", "show", "--path", str(config)])
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["api_key"] == "***"


def test_module_entry_point(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = sys.argv
    sys.argv = [
        "filescan",
        "--api-key",
        "k",
        "--base-url",
        api_server,
        "system",
        "info",
    ]
    try:
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_module("filescanio", run_name="__main__")
    finally:
        sys.argv = saved
    assert excinfo.value.code == 0
    assert json.loads(capsys.readouterr().out)["path"] == "/api/system/info"


def test_global_options_are_accepted_after_the_subcommand(
    api_server: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "logo.svg"
    exit_code = main(
        [
            "system",
            "logo",
            "--theme",
            "dark",
            "--api-key",
            "k",
            "--base-url",
            api_server,
            "-o",
            str(target),
        ]
    )
    assert exit_code == 0
    assert json.loads(target.read_bytes())["path"] == "/api/system/logo"


def test_trailing_raw_flag_produces_compact_output(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["system", "info", "--api-key", "k", "--base-url", api_server, "--raw"]
    )
    assert exit_code == 0
    assert "\n" not in capsys.readouterr().out.rstrip("\n")


def test_leading_globals_still_work(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run(api_server, "--raw", "system", "info")
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["path"] == "/api/system/info"


def test_config_init_uses_the_global_base_url(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "cfg.toml"
    exit_code = main(
        [
            "--base-url",
            "http://custom.example",
            "config",
            "init",
            "--api-key",
            "key-value",
            "--path",
            str(target),
        ]
    )
    assert exit_code == 0
    capsys.readouterr()
    assert 'base_url = "http://custom.example"' in target.read_text()


def test_config_init_without_api_key_reports_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with no_credentials():
        exit_code = main(["config", "init", "--path", str(tmp_path / "cfg.toml")])
    assert exit_code == 1
    assert "requires --api-key" in capsys.readouterr().err


def test_text_response_is_written_as_utf8(
    api_server: str, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    exit_code = run(api_server, "feed", "reports")
    assert exit_code == 0
    captured = capsysbinary.readouterr().out
    assert json.loads(captured.decode())["path"] == "/api/feed/reports"


def test_json_input_accepts_a_utf8_bom(
    api_server: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = tmp_path / "bom.json"
    payload.write_bytes(b"\xef\xbb\xbf" + b'{"message": "bom"}')
    exit_code = run(api_server, "system", "log-error", "--file", str(payload))
    assert exit_code == 0
    echo = json.loads(capsys.readouterr().out)
    assert json.loads(echo["body"]) == {"message": "bom"}


def test_closed_stdout_reports_error(api_server: str) -> None:
    saved = sys.stdout
    sys.stdout = None
    try:
        exit_code = run(api_server, "system", "info")
    finally:
        sys.stdout = saved
    assert exit_code == 1


def test_closed_stdin_reports_error(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = sys.stdin
    sys.stdin = None
    try:
        exit_code = run(api_server, "system", "log-error", "--file", "-")
    finally:
        sys.stdin = saved
    assert exit_code == 1
    assert "stdin is closed" in capsys.readouterr().err


def test_surrogate_argument_reports_a_clean_error(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run(api_server, "reputation", "hash", "\udcff\udcfeabc")
    assert exit_code == 6
    assert capsys.readouterr().err.startswith("error:")


@pytest.mark.parametrize("fmt", list(Format))
def test_unrenderable_response_reports_a_clean_error(fmt: Format) -> None:
    """A cycle defeats every renderer without exhausting the C stack.

    Nesting deeply would do it too, but the depth that suffices differs per
    platform and overshooting kills the interpreter rather than raising.
    """
    circular: dict[str, Any] = {}
    circular["self"] = circular
    with pytest.raises(FileScanError, match="Cannot render the response"):
        _emit(circular, fmt=fmt, output=None)


def test_missing_credentials_exit_code(tmp_path: Path) -> None:
    with no_credentials(tmp_path):
        assert main(["system", "info"]) == 3


def test_client_error_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    with json_server(lambda _: (404, b'{"detail": "Report not found"}')) as base_url:
        assert run(base_url, "system", "info") == 4
    assert "Report not found" in capsys.readouterr().err


def test_json_input_works_without_a_binary_stdin_buffer(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    original = sys.stdin
    sys.stdin = io.StringIO('{"message": "café"}')
    try:
        code = run(api_server, "system", "log-error", "--file", "-")
    finally:
        sys.stdin = original
    assert code == 0
    echo: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert json.loads(echo["body"]) == {"message": "café"}


def test_output_works_without_a_binary_stdout_buffer(api_server: str) -> None:
    captured = io.StringIO()
    saved = sys.stdout
    sys.stdout = captured
    try:
        exit_code = run(api_server, "system", "info")
    finally:
        sys.stdout = saved
    assert exit_code == 0
    assert json.loads(captured.getvalue())["path"] == "/api/system/info"


def test_format_table_renders_rows(capsys: pytest.CaptureFixture[str]) -> None:
    rows = b'[{"id": 1, "text": "hello"}]'
    with json_server(lambda _: (200, rows)) as base_url:
        assert run(base_url, "--format", "table", "system", "news") == 0
    out = capsys.readouterr().out
    assert "| id | text  |" in out
    assert "| 1  | hello |" in out


def test_format_toon_renders_toon(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "--format", "toon", "system", "info") == 0
    assert "method: GET" in capsys.readouterr().out


def test_format_flag_is_accepted_after_the_subcommand(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "system", "info", "--format", "toon") == 0
    assert "path: /api/system/info" in capsys.readouterr().out


def test_an_unrepresentable_response_falls_back_to_json(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "--format", "sarif", "system", "info") == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["path"] == "/api/system/info"
    assert captured.err.startswith("note: ")


def test_piped_output_stays_json_without_an_explicit_format(
    api_server: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(api_server, "system", "info") == 0
    assert json.loads(capsys.readouterr().out)["path"] == "/api/system/info"


def test_a_terminal_gets_a_table_when_no_format_is_given() -> None:
    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    terminal = Terminal()
    saved = sys.stdout
    sys.stdout = terminal
    try:
        _emit({"a": 1}, output=None)
    finally:
        sys.stdout = saved
    assert "| field | value |" in terminal.getvalue()


def test_output_to_a_file_stays_json_by_default(
    api_server: str, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    target = tmp_path / "out.json"
    assert run(api_server, "-o", str(target), "system", "info") == 0
    assert capsysbinary.readouterr().out == b""
    assert json.loads(target.read_text())["path"] == "/api/system/info"


def test_a_format_still_applies_when_writing_to_a_file(
    api_server: str, tmp_path: Path
) -> None:
    target = tmp_path / "out.toon"
    assert run(api_server, "--format", "toon", "-o", str(target), "system", "info") == 0
    assert "method: GET" in target.read_text()


def test_binary_responses_ignore_the_format(
    api_server: str, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert run(api_server, "--format", "table", "users", "avatar", "acct1") == 0
    echo: dict[str, Any] = json.loads(capsysbinary.readouterr().out)
    assert echo["path"] == "/api/users/acct1/avatar"


def test_a_text_response_ignores_the_format(
    api_server: str, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert run(api_server, "--format", "table", "feed", "reports") == 0
    echo: dict[str, Any] = json.loads(capsysbinary.readouterr().out)
    assert echo["path"] == "/api/feed/reports"


def test_max_retries_flag_reaches_the_client(api_server: str) -> None:
    assert run(api_server, "--max-retries", "0", "system", "info") == 0


@pytest.mark.parametrize("value", ["-1", "abc", "2.5"])
def test_invalid_max_retries_rejected(api_server: str, value: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run(api_server, "--max-retries", value, "system", "info")
    assert excinfo.value.code == 2
