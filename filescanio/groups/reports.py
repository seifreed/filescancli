"""Report endpoints: fetch, search, and list scan reports."""

from collections.abc import Mapping
from typing import Any, Unpack

from filescanio.groups._base import ApiGroup, ReportView, segment, view_params
from filescanio.transport import QueryValue


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
    ) -> Any:
        """Search existing reports with a free-text query.

        The endpoint honours only the query and pagination; field filters are
        supported by :meth:`search_matches`.
        """
        params: dict[str, QueryValue] = {
            "query": query,
            "page": page,
            "page_size": page_size,
        }
        return self._transport.request_json("GET", "/api/reports/search", params=params)

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
