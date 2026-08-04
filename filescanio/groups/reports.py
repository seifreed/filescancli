"""Report endpoints: fetch, search, and list scan reports."""

from collections.abc import Iterator, Mapping
from typing import Any, TypedDict, Unpack

from filescanio.groups._base import (
    ApiGroup,
    ReportView,
    segment,
    view_params,
    walk_pages,
)
from filescanio.transport import QueryValue


class SearchFields(TypedDict, total=False):
    """Field filters for report search.

    The published spec documents only the query and pagination; these are
    undocumented, but the official client sends them and the server honours
    them. The keys are the wire names.
    """

    filename: str | None
    filetype: str | None
    media_type: str | None
    verdict: str | None
    tag: str | None
    date_from: str | None
    date_to: str | None
    domain: str | None
    ip: str | None
    url: str | None
    uuid: str | None
    email: str | None
    reg_path: str | None
    rev_id: str | None
    sha1: str | None
    sha256: str | None
    sha512: str | None
    md5: str | None
    imphash: str | None
    ssdeep: str | None
    fuzzyfsiohash: str | None
    authentihash: str | None
    yara_rule: str | None
    age: int | None


def _field_params(fields: SearchFields) -> dict[str, QueryValue]:
    """Drop the fields left unset; the rest go on the query string as-is."""
    return {
        name: value for name, value in fields.items() if isinstance(value, str | int)
    }


class ReportsGroup(ApiGroup):
    """Retrieve individual reports and search across existing reports."""

    def get(self, report_id: str, file_hash: str, **view: Unpack[ReportView]) -> Any:
        """Return a specific report for a report ID and file hash."""
        return self._transport.request_json(
            "GET",
            f"/api/reports/{segment(report_id)}/{segment(file_hash)}",
            params=view_params(view),
        )

    def search(
        self,
        query: str | None = None,
        *,
        page: int | None = None,
        page_size: int | None = None,
        **fields: Unpack[SearchFields],
    ) -> Any:
        """Search existing reports with a free-text query and field filters."""
        params: dict[str, QueryValue] = {
            "query": query,
            "page": page,
            "page_size": page_size,
        }
        params.update(_field_params(fields))
        return self._transport.request_json("GET", "/api/reports/search", params=params)

    def search_pages(
        self,
        query: str | None = None,
        *,
        page_size: int = 20,
        **fields: Unpack[SearchFields],
    ) -> Iterator[Any]:
        """Yield every matching report, walking the pages as it goes."""
        return walk_pages(
            lambda page: self.search(query, page=page, page_size=page_size, **fields),
            page_size,
        )

    def public_pages(self, *, page_size: int = 20) -> Iterator[Any]:
        """Yield every public report, walking the pages as it goes."""
        return walk_pages(
            lambda page: self.public(page=page, page_size=page_size), page_size
        )

    def search_matches(
        self,
        reports_ids: list[str],
        *,
        unique_files: bool | None = None,
        method: str | None = None,
        filters: Mapping[str, QueryValue] | None = None,
    ) -> Any:
        """Return the matches for reports obtained by a search.

        Entries in ``filters`` override the named parameters they collide with.
        """
        params: dict[str, QueryValue] = {
            "unique_files": unique_files,
            "method": method,
        }
        params.update(filters or {})
        return self._transport.request_json(
            "POST",
            "/api/reports/search/matches",
            params=params,
            json_body={"reports_ids": reports_ids},
        )

    def download(self, report_id: str, *, export_format: str | None = None) -> bytes:
        """Return the full report, optionally as misp, stix, html, or pdf.

        Absent from openapi.json: the official client uses it, so the
        endpoint is real but undocumented. Do not delete it as unreachable.
        """
        return self._transport.request_bytes(
            "GET",
            f"/api/reports/{segment(report_id)}/download",
            params={"format": export_format},
        )

    def public(
        self,
        *,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        """Return the paginated list of public reports."""
        return self._transport.request_json(
            "GET",
            "/api/reports",
            params={"page": page, "page_size": page_size},
        )
