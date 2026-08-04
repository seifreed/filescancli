"""Feed endpoints: public report feeds."""

from typing import Any

from filescanio.groups._base import ApiGroup


class FeedGroup(ApiGroup):
    """Public feeds of recently published reports."""

    def reports(self) -> str:
        """Return the reports feed (XML document)."""
        return self._transport.request_text("GET", "/api/feed/reports")

    def reports_info(self) -> Any:
        """Return metadata about the reports feed."""
        return self._transport.request_json("GET", "/api/feed/reports/info")
