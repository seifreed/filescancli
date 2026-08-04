import gc
import pickle
import socket
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from typing import Any

import httpx
import pytest

from filescanio.errors import (
    ApiError,
    ConfigError,
    RequestTimeout,
    TransportError,
)
from filescanio.http import Transport, clean_params
from tests.conftest import serve, set_env


def test_clean_params_drops_none() -> None:
    assert clean_params({"a": 1, "b": None, "c": False}) == {"a": 1, "c": False}


def test_get_with_params(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        echo = transport.request_json(
            "GET", "/api/thing", params={"q": "x", "skip": None, "flag": True}
        )
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/thing"
    assert echo["query"] == {"q": ["x"], "flag": ["true"]}
    assert echo["api_key"] == "k"


def test_post_json_body(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        echo = transport.request_json("POST", "/api/thing", json_body=["a", "b"])
    assert echo["body"] == '["a","b"]'
    assert echo["content_type"] == "application/json"


def test_post_form_data(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        echo = transport.request_json("POST", "/api/thing", data={"url": "https://e"})
    assert "url=https%3A%2F%2Fe" in echo["body"]


def test_request_bytes(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        assert transport.request_bytes("GET", "/bytes") == b"\x89BINARY"


API_ERRORS = [
    ("/status/422", 422, "boom"),
    ("/jsonlist", 500, '["not a dict"]'),
    ("/notjson", 500, "plain error"),
    ("/badcharset-error", 500, '{"other": 1}'),
]


@pytest.mark.parametrize(
    ("path", "status", "detail"),
    API_ERRORS,
    ids=["json detail", "non-dict json body", "plain body", "undecodable charset"],
)
def test_error_responses_carry_the_status_and_detail(
    api_server: str, path: str, status: int, detail: str
) -> None:
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(ApiError) as excinfo,
    ):
        transport.request_json("GET", path)
    assert excinfo.value.status_code == status
    assert excinfo.value.detail == detail


UNUSABLE_RESPONSES = [
    ("/redirect-external", "cross-origin"),
    ("/redirect-loop", "Too many redirects"),
    ("/redirect-bad-location", "Network error"),
    ("/redirect-no-location", "Unusable redirect response"),
    ("/plaintext", "not valid JSON"),
    ("/deepjson", "not valid JSON"),
]


@pytest.mark.parametrize(
    ("path", "message"),
    UNUSABLE_RESPONSES,
    ids=[
        "cross-origin redirect",
        "redirect loop",
        "malformed Location",
        "redirect without Location",
        "non-JSON success body",
        "unparseable JSON body",
    ],
)
def test_unusable_responses_raise_a_transport_error(
    api_server: str, path: str, message: str
) -> None:
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(TransportError, match=message),
    ):
        transport.request_json("GET", path)


def test_a_redirect_loop_stops_at_the_declared_ceiling() -> None:
    """The ceiling is what bounds the work a looping server can extract."""
    hits = 0

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            nonlocal hits
            hits += 1
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            """Keep the test output free of per-request server logging."""

    with (
        serve(Handler) as base_url,
        Transport(api_key="k", base_url=base_url) as transport,
        pytest.raises(TransportError, match="Too many redirects"),
    ):
        transport.request_json("GET", "/loop")
    # The opening request plus the five follow-ups MAX_REDIRECTS allows. Spelt
    # out rather than derived, so raising the ceiling has to fail here.
    assert hits == 6


def test_same_origin_redirect_is_followed(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        echo = transport.request_json("GET", "/redirect")
    assert echo["path"] == "/api/redirected"
    assert echo["api_key"] == "k"


def test_network_failure_raises_transport_error() -> None:
    with (
        Transport(api_key="k", base_url="http://127.0.0.1:1") as transport,
        pytest.raises(TransportError, match="Network error"),
    ):
        transport.request_json("GET", "/api/system/info")


def test_use_after_close_raises(api_server: str) -> None:
    transport = Transport(api_key="k", base_url=api_server)
    transport.close()
    with pytest.raises(TransportError, match="Transport is closed"):
        transport.request_json("GET", "/api/system/info")


@pytest.mark.parametrize("api_key", ["", "   ", "clave-号"])
def test_unusable_api_keys_rejected(api_server: str, api_key: str) -> None:
    with pytest.raises(ConfigError):
        Transport(api_key=api_key, base_url=api_server)


def test_malformed_base_url_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="Invalid base URL"):
        Transport(api_key="k", base_url="http://[::1")


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_unusable_timeouts_rejected(api_server: str, timeout: float) -> None:
    with pytest.raises(ConfigError, match="positive finite"):
        Transport(api_key="k", base_url=api_server, timeout=timeout)


def test_unclosed_transport_closes_itself(api_server: str) -> None:
    transport = Transport(api_key="k", base_url=api_server)
    transport.request_json("GET", "/api/system/info")
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        del transport
        gc.collect()


def test_api_error_survives_pickling() -> None:
    restored = pickle.loads(pickle.dumps(ApiError(404, "not found")))
    assert (restored.status_code, restored.detail) == (404, "not found")
    assert str(restored) == "HTTP 404: not found"


def test_unusable_proxy_configuration_raises(api_server: str) -> None:
    with (
        set_env(ALL_PROXY="ftp://proxy.invalid"),
        pytest.raises(ConfigError, match="Cannot create the HTTP client"),
    ):
        Transport(api_key="k", base_url=api_server)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://host/api/v2?tenant=acme",
        "http://host?k=v",
        "http://host/api#frag",
        "http://host/?",
        "http://host/api/v2?",
        "http://host#",
    ],
)
def test_base_url_with_query_or_fragment_rejected(base_url: str) -> None:
    """An empty query or fragment is rejected just like a populated one."""
    with pytest.raises(ConfigError, match="query string or fragment"):
        Transport(api_key="k", base_url=base_url)


def test_surrogate_in_a_query_parameter_is_wrapped(api_server: str) -> None:
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(TransportError),
    ):
        transport.request_json("GET", "/api/thing", params={"q": "\udcff"})


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"x": float("nan")}, id="not a number"),
        pytest.param({"x": float("inf")}, id="infinity"),
        pytest.param({"x": b"bytes"}, id="not serialisable"),
    ],
)
def test_unsendable_body_raises_transport_error(api_server: str, body: Any) -> None:
    """json.loads accepts NaN, so a parsed payload can still be unsendable."""
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(TransportError, match="Cannot encode the request body"),
    ):
        transport.request_json("POST", "/api/thing", json_body=body)


def test_url_object_base_url_is_accepted(api_server: str) -> None:
    with Transport(api_key="k", base_url=httpx.URL(api_server)) as transport:
        assert transport.request_json("GET", "/api/ping")["path"] == "/api/ping"


def test_url_object_with_query_is_rejected() -> None:
    with pytest.raises(ConfigError, match="query string or fragment"):
        Transport(api_key="k", base_url=httpx.URL("http://host/?x=1"))


def test_non_text_charset_is_decoded_as_utf8(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        assert transport.request_text("GET", "/badcharset") == "<rss/>"


def test_text_response_is_always_encodable(api_server: str) -> None:
    with Transport(api_key="k", base_url=api_server) as transport:
        text = transport.request_text("GET", "/surrogate-text")
    assert text.encode("utf-8")
    assert "\ud800" not in text


def test_deeply_nested_error_detail_still_raises_api_error(api_server: str) -> None:
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(ApiError) as excinfo,
    ):
        transport.request_json("GET", "/deep-detail")
    assert excinfo.value.status_code == 500


@contextmanager
def silent_server() -> Iterator[str]:
    """Listen without ever answering, so a read timeout always fires.

    Nothing has to accept: the backlog completes the handshake by itself, so
    the client connects, sends, and then waits for a reply that never comes.
    Closing a listener does not wake a blocked accept() on Linux, so having
    no accepting thread is what keeps this identical across platforms.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        listener.close()


def test_timeout_raises_a_branchable_error() -> None:
    with (
        silent_server() as base_url,
        Transport(api_key="k", base_url=base_url, timeout=0.2) as t,
        pytest.raises(RequestTimeout, match="timed out"),
    ):
        t.request_json("GET", "/api/system/info")


def test_rate_limit_exposes_retry_after(api_server: str) -> None:
    with (
        Transport(api_key="k", base_url=api_server) as transport,
        pytest.raises(ApiError) as excinfo,
    ):
        transport.request_json("GET", "/ratelimited")
    assert excinfo.value.status_code == 429
    assert excinfo.value.retry_after == "120"
