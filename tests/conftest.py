"""Shared fixtures: real in-process HTTP servers that echo or replay requests."""

import json
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, NamedTuple
from urllib.parse import parse_qs, urlsplit

import pytest

from filescanio.client import FileScanClient
from filescanio.config import ENV_API_KEY, ENV_BASE_URL


class Canned(NamedTuple):
    """A fixed response an in-process server can send."""

    status: int
    body: bytes
    content_type: str = "application/json"
    headers: tuple[tuple[str, str], ...] = ()


def send(handler: BaseHTTPRequestHandler, response: Canned) -> None:
    """Write a complete response, headers included, to the client."""
    handler.send_response(response.status)
    handler.send_header("Content-Type", response.content_type)
    handler.send_header("Content-Length", str(len(response.body)))
    for name, value in response.headers:
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(response.body)


@contextmanager
def serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    """Run the handler on a background thread and yield its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


Responder = Callable[[BaseHTTPRequestHandler], tuple[int, bytes]]


@contextmanager
def json_server(respond: Responder) -> Iterator[str]:
    """Serve every GET with the status and JSON body that `respond` returns."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, body = respond(self)
            send(self, Canned(status, body))

        def log_message(self, format: str, *args: object) -> None:
            pass

    with serve(Handler) as base_url:
        yield base_url


def _redirect(location: str | None = None) -> Canned:
    headers = () if location is None else (("Location", location),)
    return Canned(302, b"", "text/plain", headers)


CANNED_RESPONSES = {
    "/redirect": _redirect("/api/redirected"),
    "/redirect-external": _redirect("https://elsewhere.invalid/steal"),
    "/redirect-loop": _redirect("/redirect-loop"),
    "/redirect-no-location": _redirect(),
    "/redirect-bad-location": _redirect("http:\\\\evil.example\\x"),
    "/plaintext": Canned(200, b"not json", "text/plain"),
    "/notjson": Canned(500, b"plain error", "text/plain"),
    "/bytes": Canned(200, b"\x89BINARY", "application/octet-stream"),
    "/jsonlist": Canned(500, b'["not a dict"]'),
    "/badcharset": Canned(200, b"<rss/>", "text/xml; charset=base64"),
    "/badcharset-error": Canned(500, b'{"other": 1}', "application/json; charset=hex"),
    "/surrogate-text": Canned(
        200, b"<rss>\\ud800</rss>", "text/xml; charset=unicode_escape"
    ),
    "/deepjson": Canned(200, b"[" * 200000 + b"]" * 200000),
    "/deep-detail": Canned(
        500, b'{"detail": ' + b"[" * 70000 + b"1" + b"]" * 70000 + b"}"
    ),
    "/ratelimited": Canned(
        429, b'{"detail": "slow down"}', headers=(("Retry-After", "120"),)
    ),
}


class EchoHandler(BaseHTTPRequestHandler):
    """Echoes request details back as JSON.

    Paths listed in CANNED_RESPONSES answer with a fixed response instead:
    redirects (same origin, cross origin, looping, without a Location header,
    and with a malformed one), non-JSON and binary bodies, bodies declaring a
    charset that cannot decode text, payloads too deeply nested to parse or
    render, and a rate-limited answer carrying Retry-After. Additionally,
    /status/<code> responds with that HTTP status and a JSON detail.
    """

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        return raw.decode("utf-8", errors="replace")

    def _echo(self, path: str, query: str) -> Canned:
        echo = {
            "method": self.command,
            "path": path,
            "query": parse_qs(query),
            "api_key": self.headers.get("X-Api-Key"),
            "content_type": self.headers.get("Content-Type", ""),
            "body": self._read_body(),
        }
        return Canned(200, json.dumps(echo).encode())

    def _respond(self) -> None:
        parts = urlsplit(self.path)
        response = CANNED_RESPONSES.get(parts.path)
        if response is None and parts.path.startswith("/status/"):
            code = int(parts.path.rsplit("/", 1)[1])
            response = Canned(code, b'{"detail": "boom"}')
        send(self, response or self._echo(parts.path, parts.query))

    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        self._respond()

    def do_DELETE(self) -> None:
        self._respond()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="session")
def api_server() -> Iterator[str]:
    with serve(EchoHandler) as base_url:
        yield base_url


@pytest.fixture
def client(api_server: str) -> Iterator[FileScanClient]:
    with FileScanClient(api_key="k", base_url=api_server) as bound:
        yield bound


SIMPLE_CASES = [
    (("system", "info"), "/api/system/info"),
    (("system", "version"), "/api/system/version"),
    (("system", "config"), "/api/system/config"),
    (("system", "features"), "/api/system/product-features"),
    (("system", "languages"), "/api/system/languages"),
    (("system", "countries"), "/api/system/countries"),
    (("system", "mitre"), "/api/system/mitre"),
    (("system", "mbc"), "/api/system/mbc"),
    (("system", "reputation-config"), "/api/system/reputation/check-config"),
    (("system", "news"), "/api/system/news"),
    (("users", "ioc-stats"), "/api/users/stat/iocs"),
    (("users", "tags"), "/api/users/get-frequent-tags"),
    (("users", "interesting"), "/api/users/most-interesting"),
    (("feed", "reports"), "/api/feed/reports"),
    (("feed", "info"), "/api/feed/reports/info"),
    (("misc", "openapi"), "/openapi.json"),
    (("misc", "sitemap"), "/api/docs/sitemap"),
]


def assert_get(echo: Any, path: str, query: dict[str, list[str]]) -> None:
    """Assert the echoed request was a GET for this path with exactly this query."""
    __tracebackhide__ = True
    assert echo["method"] == "GET"
    assert echo["path"] == path
    assert echo["query"] == query


def home_env(home: object) -> dict[str, str]:
    """Pin the home directory on every platform.

    POSIX resolves ~ through HOME, Windows through USERPROFILE, so a test
    that sets only HOME still reads the real user profile on Windows.
    """
    return {"HOME": str(home), "USERPROFILE": str(home)}


@contextmanager
def set_env(**values: str | None) -> Iterator[None]:
    """Temporarily set (or unset with None) environment variables."""
    saved = {name: os.environ.get(name) for name in values}
    for name, value in values.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def no_credentials(home: object | None = None) -> Iterator[None]:
    """Run with neither the API key nor the base URL set in the environment.

    Pass a directory to pin the home directory too, so a test that reads or
    writes the default config file never touches the real one.
    """
    pinned = {} if home is None else home_env(home)
    with set_env(**pinned, **{ENV_API_KEY: None, ENV_BASE_URL: None}):
        yield
