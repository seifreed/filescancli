"""Threat intelligence endpoints: IOC prevalence and similar reports."""

from typing import Any

from filescanio.groups._base import ApiGroup
from filescanio.transport import QueryValue


class ThreatIntelGroup(ApiGroup):
    """Threat intelligence: IOC prevalence and special-hash similarity."""

    def prevalence(
        self,
        *,
        domain: list[str] | None = None,
        ip: list[str] | None = None,
        url: list[str] | None = None,
        uuid: list[str] | None = None,
        email: list[str] | None = None,
        registry_path: list[str] | None = None,
        revision_save_id: list[str] | None = None,
        sha1: list[str] | None = None,
        sha256: list[str] | None = None,
        sha512: list[str] | None = None,
        md5: list[str] | None = None,
        imphash: list[str] | None = None,
        ssdeep: list[str] | None = None,
        authentihash: list[str] | None = None,
        fuzzyfsiohash: list[str] | None = None,
        unc_path: list[str] | None = None,
        days: int | None = None,
        exclude_report_ids: list[str] | None = None,
    ) -> Any:
        """Return the prevalence of the given IOCs across existing reports."""
        ioc_fields: dict[str, list[str] | None] = {
            "domain": domain,
            "ip": ip,
            "url": url,
            "uuid": uuid,
            "email": email,
            "registry_path": registry_path,
            "revision_save_id": revision_save_id,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512,
            "md5": md5,
            "imphash": imphash,
            "ssdeep": ssdeep,
            "authentihash": authentihash,
            "fuzzyfsiohash": fuzzyfsiohash,
            "unc_path": unc_path,
        }
        body: dict[str, list[str] | int] = {
            name: values for name, values in ioc_fields.items() if values is not None
        }
        if days is not None:
            body["days"] = days
        params: dict[str, QueryValue] = {"exclude_report_ids": exclude_report_ids}
        return self._transport.request_json(
            "POST", "/api/threatintel/get-prevalence", params=params, json_body=body
        )

    def similars(
        self,
        *,
        imphash: str | None = None,
        ssdeep: str | None = None,
        fuzzyfsiohash: str | None = None,
        authentihash: str | None = None,
        days: int | None = None,
        exclude_report_ids: list[str] | None = None,
    ) -> Any:
        """Return reports that share the given special hashes."""
        params: dict[str, QueryValue] = {
            "imphash": imphash,
            "ssdeep": ssdeep,
            "fuzzyfsiohash": fuzzyfsiohash,
            "authentihash": authentihash,
            "days": days,
            "exclude_report_ids": exclude_report_ids,
        }
        return self._transport.request_json(
            "GET", "/api/threatintel/get-similars", params=params
        )
