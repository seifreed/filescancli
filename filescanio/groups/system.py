"""System endpoints: platform info, configuration, and reference data."""

from typing import Any

from filescanio.groups._base import ApiGroup, segment
from filescanio.transport import QueryValue


class SystemGroup(ApiGroup):
    """Platform information, configuration, and reference data."""

    def info(self) -> Any:
        """Return general platform information."""
        return self._transport.request_json("GET", "/api/system/info")

    def version(self) -> Any:
        """Return the platform version."""
        return self._transport.request_json("GET", "/api/system/version")

    def config(self) -> Any:
        """Return the platform configuration."""
        return self._transport.request_json("GET", "/api/system/config")

    def product_features(self) -> Any:
        """Return the licensed product features."""
        return self._transport.request_json("GET", "/api/system/product-features")

    def terms(self, terms_type: str) -> Any:
        """Return the terms document of the given type."""
        return self._transport.request_json(
            "GET", f"/api/system/get-terms/{segment(terms_type)}"
        )

    def yara(self, names: list[str] | None = None) -> Any:
        """Return the YARA rule metadata, optionally filtered by rule name."""
        params: dict[str, QueryValue] = {"name": names}
        return self._transport.request_json("GET", "/api/system/yara", params=params)

    def translations(self, lang: str) -> Any:
        """Return the UI translations for the given language."""
        return self._transport.request_json(
            "GET", f"/api/system/translations/{segment(lang)}"
        )

    def languages(self) -> Any:
        """Return the supported languages."""
        return self._transport.request_json("GET", "/api/system/languages")

    def countries(self) -> Any:
        """Return the list of known countries."""
        return self._transport.request_json("GET", "/api/system/countries")

    def mitre(self) -> Any:
        """Return the MITRE ATT&CK reference data."""
        return self._transport.request_json("GET", "/api/system/mitre")

    def mbc(self) -> Any:
        """Return the Malware Behavior Catalog reference data."""
        return self._transport.request_json("GET", "/api/system/mbc")

    def log_error(self, payload: Any) -> Any:
        """Log a client-side error on the server."""
        return self._transport.request_json(
            "POST", "/api/system/errors/log", json_body=payload
        )

    def logo(
        self,
        *,
        logo_type: str | None = None,
        theme: str | None = None,
        name: str | None = None,
    ) -> bytes:
        """Return the site logo image (raw bytes)."""
        params: dict[str, QueryValue] = {
            "type": logo_type,
            "theme": theme,
            "name": name,
        }
        return self._transport.request_bytes("GET", "/api/system/logo", params=params)

    def query_healthcheck(
        self, *, days: int | None = None, days_from: int | None = None
    ) -> Any:
        """Return query health-check statistics for the given period."""
        params: dict[str, QueryValue] = {"days": days, "days_from": days_from}
        return self._transport.request_json(
            "GET", "/api/system/query-healthcheck", params=params
        )

    def reputation_check_config(self) -> Any:
        """Return the reputation check configuration."""
        return self._transport.request_json(
            "GET", "/api/system/reputation/check-config"
        )

    def news(self) -> Any:
        """Return the news items."""
        return self._transport.request_json("GET", "/api/system/news")

    def save_news(self, item: dict[str, Any]) -> Any:
        """Save a news item."""
        return self._transport.request_json("POST", "/api/system/news", json_body=item)

    def remove_news(self, news_id: str) -> Any:
        """Remove a news item by its identifier."""
        return self._transport.request_json(
            "DELETE", "/api/system/news", params={"news_id": news_id}
        )
