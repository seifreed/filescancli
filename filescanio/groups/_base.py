"""Shared base for endpoint groups."""

from typing import TypedDict
from urllib.parse import quote

from filescanio.errors import FileScanError
from filescanio.transport import ApiTransport, QueryValue


class ReportView(TypedDict, total=False):
    """Which parts of a report to return, however the report is reached."""

    filters: list[str] | None
    sorting: list[str] | None
    other: list[str] | None


def view_params(view: ReportView) -> dict[str, QueryValue]:
    """Map the section selectors onto the query parameters the API expects."""
    return {
        "filter": view.get("filters"),
        "sorting": view.get("sorting"),
        "other": view.get("other"),
    }


def segment(value: str) -> str:
    """Escape a value so it cannot leave its path segment.

    Dot-only segments are encoded as well: httpx resolves ``.`` and ``..``
    against the base URL before sending, which would retarget the request.
    """
    try:
        escaped = quote(value, safe="")
    except UnicodeEncodeError as exc:
        raise FileScanError(f"Invalid identifier {value!r}: {exc}") from exc
    if escaped and set(escaped) == {"."}:
        return escaped.replace(".", "%2E")
    return escaped


class ApiGroup:
    """Endpoint group bound to a transport."""

    def __init__(self, transport: ApiTransport) -> None:
        self._transport = transport
