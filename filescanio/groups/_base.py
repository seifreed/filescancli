"""Shared base for endpoint groups."""

from collections.abc import Callable, Iterator, Mapping
from typing import Any, TypedDict
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


PAGE_CEILING = 1000


def walk_pages(
    fetch: Callable[[int], Any], page_size: int, first_page: int = 1
) -> Iterator[Any]:
    """Yield the items of every page, stopping when the server runs out.

    A short page is the last one. The ceiling stops a server that keeps
    answering with a full page from looping forever.
    """
    for page in range(first_page, first_page + PAGE_CEILING):
        payload = fetch(page)
        items = payload.get("items") if isinstance(payload, Mapping) else None
        if not isinstance(items, list) or not items:
            return
        yield from items
        if len(items) < page_size:
            return


class ApiGroup:
    """Endpoint group bound to a transport."""

    def __init__(self, transport: ApiTransport) -> None:
        self._transport = transport
