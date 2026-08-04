"""The intelligence sections: OSINT lookups and resolved-address geolocation."""

from typing import Any

from filescanio.scanreport._access import mapping, records
from filescanio.scanreport._layout import (
    Field,
    identifier,
    indent,
    pairs,
    rows,
    scalar_items,
    tag_names,
    text,
)
from filescanio.scanreport.model import ScanReport

RESOURCE_TYPES = {
    "file_hash_md5": "MD5",
    "file_hash_sha1": "SHA-1",
    "file_hash_sha256": "SHA-256",
    "file_hash_sha512": "SHA-512",
    "url": "URL",
    "ip": "IP address",
    "domain": "domain",
    "email": "email",
    "uuid": "UUID",
    "registry_path": "registry path",
    "revision_save_id": "revision save id",
}


def resource_type(value: Any) -> str | None:
    """An OSINT resource type spelled out, or None."""
    shown = text(value)
    return None if shown is None else RESOURCE_TYPES.get(shown.lower(), shown)


OSINT_FIELDS: tuple[Field, ...] = (
    Field("Type", ("type",), resource_type),
    Field("Origin", ("origin", "type"), identifier),
    Field("Provider", ("osintProvider",), identifier),
    Field("Verdict", ("verdict",)),
    Field("Tags", ("tags",), tag_names),
)

# Echoes of the query itself, not intelligence about it.
SKIPPED_DATA = frozenset({"resource", "response_code", "sha256", "scans"})


def provider_facts(data: Any) -> list[tuple[str, str]]:
    """What the provider reported, minus the echo of the question."""
    shown = {
        key: value for key, value in mapping(data).items() if key not in SKIPPED_DATA
    }
    return scalar_items(shown)


def osint(scan: ScanReport) -> list[str]:
    """Every OSINT lookup with its verdict and provider data."""
    lines: list[str] = []
    for item in records(scan.resource("osint").get("results")):
        facts = rows(item, OSINT_FIELDS) + provider_facts(item.get("data"))
        lines += [text(item.get("resource")) or "osint result", *indent(pairs(facts))]
    return lines


GEO_FIELDS: tuple[Field, ...] = (
    Field("Domain", ("resource", "data")),
    Field("Country", ("geoData", "country_name")),
    Field("City", ("geoData", "city")),
    Field("Country code", ("geoData", "country_code")),
    Field("Latitude", ("geoData", "latitude")),
    Field("Longitude", ("geoData", "longitude")),
    Field("ASN", ("geoData", "connection", "asn")),
    Field("ISP", ("geoData", "connection", "isp")),
)


def geolocation(scan: ScanReport) -> list[str]:
    """Every resolved address with where it lives."""
    lines: list[str] = []
    for item in records(scan.resource("domain-resolve").get("domainResolveResults")):
        header = text(item.get("inetAddr")) or "address"
        lines += [header, *indent(pairs(rows(item, GEO_FIELDS)))]
    return lines
