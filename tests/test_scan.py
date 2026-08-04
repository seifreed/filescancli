"""Tests for ScanGroup against real in-process HTTP servers."""

import itertools
import json
import time
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import pytest

from filescanio.client import FileScanClient
from filescanio.errors import DESCRIBE_LIMIT, FileScanError, describe
from filescanio.groups.scan import ScanGroup
from filescanio.http import Transport
from tests.conftest import json_server


def test_file_upload_with_options(client: FileScanClient, tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("file-payload")
    echo = client.scan.file(
        sample,
        description="a scan",
        tags="tag1,tag2",
        propagate_tags=True,
        password="secret",
        is_private=False,
        is_private_report=True,
        skip_whitelisted=False,
        scan_profile="default",
        scan_engine="engine1",
    )
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/scan/file"
    assert echo["content_type"].startswith("multipart/form-data")
    assert 'filename="sample.txt"' in echo["body"]
    assert "file-payload" in echo["body"]
    fields = _multipart_fields(echo["body"])
    assert fields["description"] == "a scan"
    assert fields["propagate_tags"] == "true"
    assert fields["is_private"] == "false"
    assert fields["skip_whitelisted"] == "false"
    assert fields["scan_engine"] == "engine1"


def test_file_upload_minimal(client: FileScanClient, tmp_path: Path) -> None:
    sample = tmp_path / "bare.bin"
    sample.write_text("bare-content")
    echo = client.scan.file(str(sample))
    assert echo["path"] == "/api/scan/file"
    assert 'filename="bare.bin"' in echo["body"]
    assert "bare-content" in echo["body"]
    assert "description" not in echo["body"]
    assert "is_private" not in echo["body"]


def test_url_scan_with_options(client: FileScanClient) -> None:
    echo = client.scan.url(
        "https://example.com",
        description="a url",
        is_private=True,
        skip_whitelisted=False,
    )
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/scan/url"
    assert echo["content_type"] == "application/x-www-form-urlencoded"
    assert "url=https%3A%2F%2Fexample.com" in echo["body"]
    assert "description=a+url" in echo["body"]
    assert "is_private=true" in echo["body"]
    assert "skip_whitelisted=false" in echo["body"]


def test_url_scan_minimal(client: FileScanClient) -> None:
    echo = client.scan.url("https://example.com")
    assert echo["body"] == "url=https%3A%2F%2Fexample.com"


@pytest.mark.parametrize(
    ("view", "query"),
    [
        pytest.param({}, {}, id="without a view"),
        pytest.param(
            {
                "filters": ["general", "overview"],
                "sorting": ["date"],
                "other": ["extra"],
            },
            {
                "filter": ["general", "overview"],
                "sorting": ["date"],
                "other": ["extra"],
            },
            id="with a view",
        ),
    ],
)
def test_report_sends_only_the_requested_sections(
    client: FileScanClient, view: dict[str, list[str]], query: dict[str, list[str]]
) -> None:
    echo = client.scan.report("flow-1", **view)
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/scan/flow-1/report"
    assert echo["query"] == query


def _multipart_fields(body: str) -> dict[str, str]:
    """Map each multipart field name to its value."""
    fields = {}
    for part in body.split("--")[1:]:
        if 'name="' not in part:
            continue
        name = part.split('name="', 1)[1].split('"', 1)[0]
        _, _, value = part.partition("\r\n\r\n")
        fields[name] = value.strip()
    return fields


@contextmanager
def scanning(server: AbstractContextManager[str]) -> Iterator[ScanGroup]:
    """Point a ScanGroup at the in-process report server the test set up."""
    with server as base_url, Transport(api_key="k", base_url=base_url) as transport:
        yield ScanGroup(transport)


def report_server(*stages: Mapping[str, object]) -> AbstractContextManager[str]:
    """Serve one report payload per request, repeating the last one forever."""
    hits = itertools.count()
    return json_server(
        lambda _: (200, json.dumps(stages[min(next(hits), len(stages) - 1)]).encode())
    )


def polling_server(finish_on_request: int) -> AbstractContextManager[str]:
    """Report the flow as finished only from the given request number on."""
    hits = itertools.count(1)
    return json_server(
        lambda _: (
            200,
            json.dumps({"allFinished": next(hits) >= finish_on_request}).encode(),
        )
    )


def test_wait_for_report_finishes() -> None:
    with scanning(polling_server(finish_on_request=2)) as scan:
        report = scan.wait_for_report("flow-3", interval=0.01)
    assert report == {"allFinished": True}


def test_wait_for_report_times_out() -> None:
    with (
        scanning(polling_server(finish_on_request=1_000_000)) as scan,
        pytest.raises(FileScanError, match="Timed out after 0.05 seconds"),
    ):
        scan.wait_for_report("flow-4", interval=0.01, timeout=0.05)


def test_wait_for_report_rejects_non_dict_payload() -> None:
    with (
        scanning(json_server(lambda _: (200, b'["not a report object"]'))) as scan,
        pytest.raises(FileScanError, match="Unexpected report payload"),
    ):
        scan.wait_for_report("flow-5", interval=0.01, timeout=0.05)


def test_wait_for_report_rejects_negative_interval(client: FileScanClient) -> None:
    with pytest.raises(FileScanError, match="interval must be positive"):
        client.scan.wait_for_report("flow-6", interval=-1)


def test_scan_file_rejects_non_regular_files(
    client: FileScanClient, tmp_path: Path
) -> None:
    fifo = tmp_path / "pipe"
    fifo.mkdir()
    with pytest.raises(FileScanError, match="not a regular file"):
        client.scan.file(fifo)


def test_scan_file_rejects_a_path_holding_a_null_byte(client: FileScanClient) -> None:
    """Path.exists() hides the null byte, so open() is what refuses the path."""
    with pytest.raises(FileScanError, match="Cannot read"):
        client.scan.file("reports\x00.exe")


@pytest.mark.parametrize(
    ("interval", "timeout"),
    [(float("nan"), 1.0), (0.01, float("nan")), (float("inf"), 1.0)],
)
def test_wait_for_report_rejects_non_finite_values(
    client: FileScanClient, interval: float, timeout: float
) -> None:
    with pytest.raises(FileScanError, match="must be finite"):
        client.scan.wait_for_report("f", interval=interval, timeout=timeout)


def test_wait_for_report_waits_until_every_stage_is_done() -> None:
    """Mimic the API: allFinished flips before downloads and steps finish."""
    with scanning(
        report_server(
            {"allFinished": False},
            {"allFinished": True, "allFilesDownloadFinished": False},
            {
                "allFinished": True,
                "allFilesDownloadFinished": True,
                "allAdditionalStepsDone": True,
                "allSignalGroups": ["signals"],
            },
        )
    ) as scan:
        report = scan.wait_for_report("flow-8", interval=0.01)
    assert report["allFilesDownloadFinished"] is True
    assert report["allAdditionalStepsDone"] is True
    assert "allSignalGroups" in report


def test_describe_bounds_a_payload_no_matter_how_deep() -> None:
    """Nested past any stack: a plain repr here would abort the interpreter."""
    nested: Any = []
    for _ in range(500_000):
        nested = [nested]
    rendered = describe(nested)
    assert rendered.startswith("[[[")
    assert "..." in rendered
    assert len(rendered) <= DESCRIBE_LIMIT


def test_describe_leaves_a_small_payload_readable() -> None:
    assert describe({"flow": 1}) == "{'flow': 1}"


def test_describe_shortens_a_long_payload() -> None:
    assert len(describe("x" * 5000)) <= DESCRIBE_LIMIT


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            {
                "allFinished": True,
                "allFilesDownloadFinished": None,
                "allAdditionalStepsDone": None,
                "reports": {"r": {"finalVerdict": "benign"}},
            },
            id="stage flags left null",
        ),
        pytest.param(
            {
                "allFinished": True,
                "rejected_files": [{"name": "bad", "rejected_reason": "too large"}],
                "reports": {"r": {"finalVerdict": "benign"}},
            },
            id="some files rejected, but reports came back",
        ),
    ],
)
def test_a_settled_flow_returns_its_reports(payload: Mapping[str, object]) -> None:
    with scanning(report_server(payload)) as scan:
        report = scan.wait_for_report("flow", interval=0.01, timeout=1.0)
    assert report["reports"]["r"]["finalVerdict"] == "benign"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        pytest.param(
            {
                "allFinished": True,
                "allAdditionalStepsDone": False,
                "job": {"error": True, "reason": "Scan job crashed: OOM"},
            },
            "Scan job crashed: OOM",
            id="the job reports its own error",
        ),
        pytest.param(
            {
                "allFinished": True,
                "allAdditionalStepsDone": False,
                "rejected_files": [{"name": "x", "rejected_reason": "quota exceeded"}],
            },
            "quota exceeded",
            id="every file was rejected, with a reason",
        ),
    ],
)
def test_a_failed_flow_aborts_the_wait(
    payload: Mapping[str, object], message: str
) -> None:
    """The long poll must not be waited out once the server reports failure."""
    with (
        scanning(report_server(payload)) as scan,
        pytest.raises(FileScanError, match=message),
    ):
        scan.wait_for_report("flow", interval=5.0, timeout=600.0)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            {
                "allFinished": True,
                "allAdditionalStepsDone": False,
                "rejected_files": ["not-an-object"],
            },
            id="rejections the server gives no reason for",
        ),
        pytest.param(
            {
                "allFinished": False,
                "state": "created",
                "reports": {},
                "rejected_files": [{"name": "bad", "rejected_reason": "too large"}],
            },
            id="rejections that arrive before the flow finishes",
        ),
    ],
)
def test_an_inconclusive_rejection_keeps_polling(
    payload: Mapping[str, object],
) -> None:
    """These are not failures, so the wait runs to its timeout instead of aborting."""
    with (
        scanning(report_server(payload)) as scan,
        pytest.raises(FileScanError, match="Timed out"),
    ):
        scan.wait_for_report("flow", interval=0.01, timeout=0.2)


def test_sleep_never_overshoots_the_deadline() -> None:
    with scanning(report_server({"allFinished": False})) as scan:
        started = time.monotonic()
        with pytest.raises(FileScanError, match="Timed out"):
            scan.wait_for_report("flow-12", interval=30.0, timeout=0.2)
        assert time.monotonic() - started < 5.0


def filter_aware_server(
    settled: Mapping[str, object], on_filter: tuple[int, bytes]
) -> AbstractContextManager[str]:
    """Serve a settled report, answering filtered requests with `on_filter`."""
    return json_server(
        lambda handler: (
            on_filter
            if "filter=" in handler.path
            else (200, json.dumps(settled).encode())
        )
    )


def test_waiting_with_filters_terminates_and_returns_the_filtered_report() -> None:
    """Mimic the API: a filtered report omits the top-level stage flags."""
    settled = {
        "allFinished": True,
        "allFilesDownloadFinished": True,
        "allAdditionalStepsDone": True,
        "reports": {"r": {"finalVerdict": "benign"}},
    }
    with scanning(
        filter_aware_server(settled, (200, b'{"reports": {"r": ["signal"]}}'))
    ) as scan:
        report = scan.wait_for_report(
            "flow-14", interval=0.01, timeout=2.0, filters=["allSignalGroups"]
        )
    assert report == {"reports": {"r": ["signal"]}}


def test_a_failed_final_fetch_keeps_the_settled_report() -> None:
    """Settle normally, but fail whenever a filtered report is requested."""
    settled = {"allFinished": True, "reports": {"r": {"finalVerdict": "benign"}}}
    with scanning(
        filter_aware_server(settled, (502, b'{"detail": "upstream hiccup"}'))
    ) as scan:
        report = scan.wait_for_report(
            "flow-16", interval=0.01, timeout=1.0, filters=["general"]
        )
    assert report["reports"]["r"]["finalVerdict"] == "benign"


def test_rejections_before_the_flow_finishes_do_not_abort_it() -> None:
    payload = {
        "allFinished": False,
        "state": "created",
        "reports": {},
        "rejected_files": [{"name": "bad", "rejected_reason": "too large"}],
    }
    with (
        scanning(report_server(payload)) as scan,
        pytest.raises(FileScanError, match="Timed out"),
    ):
        scan.wait_for_report("flow-17", interval=0.01, timeout=0.2)


def test_files_submits_the_whole_batch_in_order(
    client: FileScanClient, tmp_path: Path
) -> None:
    samples = []
    for index in range(3):
        sample = tmp_path / f"s{index}.bin"
        sample.write_text(f"payload-{index}")
        samples.append(sample)
    echoes = client.scan.files(samples, max_workers=3)
    assert [f'filename="s{i}.bin"' in echoes[i]["body"] for i in range(3)] == [True] * 3


def test_a_failing_sample_does_not_lose_the_rest(
    client: FileScanClient, tmp_path: Path
) -> None:
    good = tmp_path / "good.bin"
    good.write_text("fine")
    results = client.scan.files([good, tmp_path / "missing.bin"], max_workers=2)
    assert results[0]["path"] == "/api/scan/file"
    assert isinstance(results[1], FileScanError)


def test_wait_for_reports_waits_on_every_flow() -> None:
    with scanning(report_server({"allFinished": True})) as scan:
        reports = scan.wait_for_reports(["a", "b"], interval=0.01, max_workers=2)
    assert reports == [{"allFinished": True}, {"allFinished": True}]


def test_an_empty_batch_is_not_an_error(client: FileScanClient) -> None:
    assert client.scan.files([]) == []


@pytest.mark.parametrize("workers", [0, -1, 33])
def test_unusable_worker_counts_rejected(
    client: FileScanClient, tmp_path: Path, workers: int
) -> None:
    with pytest.raises(FileScanError, match="max_workers"):
        client.scan.files([tmp_path / "x.bin"], max_workers=workers)
