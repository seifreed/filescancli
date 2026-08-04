"""Scan endpoints: submit files or URLs and retrieve scan reports."""

import math
import time
from collections.abc import Callable, Sequence
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict, Unpack

from filescanio.errors import FileScanError, describe
from filescanio.groups._base import ApiGroup, ReportView, segment, view_params

if TYPE_CHECKING:
    from concurrent.futures import Future


class ScanOptions(TypedDict, total=False):
    """Options accepted by every scan submission, whatever the source."""

    description: str | None
    tags: str | None
    propagate_tags: bool | None
    password: str | None
    is_private: bool | None
    is_private_report: bool | None
    skip_whitelisted: bool | None
    scan_profile: str | None
    scan_engine: str | None


def _encode_field(value: object) -> str:
    """Render a form field the way the API spells booleans."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _form_fields(options: ScanOptions) -> dict[str, str]:
    """Drop the options left unset and encode the rest as form fields."""
    return {
        name: _encode_field(value)
        for name, value in options.items()
        if value is not None
    }


SETTLED_FLAGS = ("allFilesDownloadFinished", "allAdditionalStepsDone")


def _is_settled(report: dict[str, Any]) -> bool:
    """Report every stage of the flow as done, not just the scan itself.

    The schema types the stage flags as boolean or null, so only an explicit
    false means a stage is still running.
    """
    if not report.get("allFinished"):
        return False
    return all(report.get(flag) is not False for flag in SETTLED_FLAGS)


def _failure_reason(report: dict[str, Any]) -> str | None:
    """Return the server's own reason when it reports the flow as failed."""
    job = report.get("job")
    if isinstance(job, dict) and job.get("error"):
        return str(job.get("reason") or "the scan job failed")
    rejected = report.get("rejected_files")
    if (
        isinstance(rejected, list)
        and rejected
        and report.get("allFinished")
        and not report.get("reports")
    ):
        reasons = [
            str(entry.get("rejected_reason") or "rejected")
            for entry in rejected
            if isinstance(entry, dict)
        ]
        if reasons:
            return "; ".join(reasons)
    return None


DEFAULT_WORKERS = 4
MAX_WORKERS = 32


def _fan_out(calls: Sequence[Callable[[], Any]], max_workers: int) -> list[Any]:
    """Run the calls concurrently, keeping order and every outcome."""
    if max_workers < 1 or max_workers > MAX_WORKERS:
        raise FileScanError(f"max_workers must be between 1 and {MAX_WORKERS}")
    if not calls:
        return []
    # Imported here: concurrent.futures drags in logging, and only a batch
    # of more than one sample ever needs a pool.
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(max_workers, len(calls))) as pool:
        futures = [pool.submit(call) for call in calls]
        return [_outcome(future) for future in futures]


def _outcome(future: Future[Any]) -> Any:
    """The result, or the failure itself so one bad sample keeps the batch."""
    try:
        return future.result()
    except FileScanError as exc:
        return exc


class ScanGroup(ApiGroup):
    """Submit files or URLs for scanning and poll for the resulting reports."""

    def file(self, path: str | Path, **options: Unpack[ScanOptions]) -> Any:
        """Submit a local file for scanning."""
        file_path = Path(path)
        data = _form_fields(options)
        if file_path.exists() and not file_path.is_file():
            raise FileScanError(f"Cannot read {file_path}: not a regular file")
        try:
            handle = file_path.open("rb")
        except (OSError, ValueError) as exc:
            raise FileScanError(f"Cannot read {file_path}: {exc}") from exc
        with handle:
            return self._transport.request_json(
                "POST",
                "/api/scan/file",
                data=data,
                files={"file": (file_path.name, handle)},
            )

    def files(
        self,
        paths: Sequence[str | Path],
        *,
        max_workers: int = DEFAULT_WORKERS,
        **options: Unpack[ScanOptions],
    ) -> list[Any]:
        """Submit several files at once, in the order they were given.

        One sample failing must not lose the rest of the batch, so a failure
        is returned in its slot as the exception rather than raised.
        """
        return _fan_out(
            [partial(self.file, path, **options) for path in paths],
            max_workers,
        )

    def wait_for_reports(
        self,
        flow_ids: Sequence[str],
        *,
        max_workers: int = DEFAULT_WORKERS,
        interval: float = 5.0,
        timeout: float = 600.0,
        **view: Unpack[ReportView],
    ) -> list[Any]:
        """Wait on several flows at once, in the order they were given."""
        return _fan_out(
            [
                partial(
                    self.wait_for_report,
                    flow,
                    interval=interval,
                    timeout=timeout,
                    **view,
                )
                for flow in flow_ids
            ],
            max_workers,
        )

    def url(self, url: str, **options: Unpack[ScanOptions]) -> Any:
        """Submit a URL for scanning."""
        data = {"url": url, **_form_fields(options)}
        return self._transport.request_json("POST", "/api/scan/url", data=data)

    def report(self, flow_id: str, **view: Unpack[ReportView]) -> Any:
        """Return all reports related to a scan flow."""
        return self._transport.request_json(
            "GET",
            f"/api/scan/{segment(flow_id)}/report",
            params=view_params(view),
        )

    def _settled_view(self, flow_id: str, settled: Any, view: ReportView) -> Any:
        """Re-fetch the finished report with the caller's sections applied."""
        try:
            return self.report(flow_id, **view)
        except FileScanError:
            return settled

    def wait_for_report(
        self,
        flow_id: str,
        *,
        interval: float = 5.0,
        timeout: float = 600.0,
        **view: Unpack[ReportView],
    ) -> Any:
        """Poll until the scan flow is fully settled.

        ``allFinished`` turns true while downloads and post-processing are
        still running, and a report fetched at that moment is missing whole
        sections such as ``allSignalGroups``. Raises FileScanError on timeout.
        """
        if not (math.isfinite(interval) and math.isfinite(timeout)):
            raise FileScanError("interval and timeout must be finite")
        if interval <= 0 or timeout < 0:
            raise FileScanError("interval must be positive and timeout non-negative")
        deadline = time.monotonic() + timeout
        while True:
            report = self.report(flow_id)
            if not isinstance(report, dict):
                raise FileScanError(
                    f"Unexpected report payload for scan flow {flow_id}: "
                    f"{describe(report)}"
                )
            if _is_settled(report):
                if any(view.values()):
                    return self._settled_view(flow_id, report, view)
                return report
            reason = _failure_reason(report)
            if reason is not None:
                raise FileScanError(f"Scan flow {flow_id} failed: {reason}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FileScanError(
                    f"Timed out after {timeout} seconds waiting for "
                    f"scan flow {flow_id} to finish"
                )
            time.sleep(min(interval, remaining))
