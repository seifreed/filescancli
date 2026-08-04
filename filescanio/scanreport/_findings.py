"""The findings sections: extracted IOCs and matched YARA rules."""

from collections.abc import Mapping
from typing import Any

from filescanio.scanreport._access import at, records
from filescanio.scanreport._layout import (
    Field,
    indent,
    joined,
    pairs,
    rows,
    scalar_items,
    size,
    tag_names,
    text,
)
from filescanio.scanreport.model import ScanReport

IOC_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("URLs", "extractedUrls"),
    ("Domains", "extractedDomains"),
    ("IPs", "extractedIPs"),
    ("Emails", "extractedEmails"),
    ("MD5 hashes", "extractedHashesMD5"),
    ("SHA-1 hashes", "extractedHashesSHA1"),
    ("SHA-256 hashes", "extractedHashesSHA256"),
    ("SHA-512 hashes", "extractedHashesSHA512"),
    ("UUIDs", "extractedUUIDs"),
    ("Registry paths", "extractedRegistryPathways"),
    ("Revision save ids", "extractedRevisionSaveIDs"),
)


def references(value: Any) -> list[str]:
    """Every datum in a category, marked when the analysis found it notable."""
    return [
        shown + (" (interesting)" if ref.get("interesting") else "")
        for entry in records(value)
        for ref in records(entry.get("references"))
        if (shown := text(ref.get("data")))
    ]


def iocs(scan: ScanReport) -> list[str]:
    """Each IOC category that has entries; silent categories stay silent."""
    resource = scan.resource("file")
    lines: list[str] = []
    for label, key in IOC_CATEGORIES:
        found = references(resource.get(key))
        lines += [label, *indent(found)] if found else []
    return lines


YARA_FIELDS: tuple[Field, ...] = (Field("Matches", ("matchedStrings",), joined),)


def yara_lines(rule: Mapping[str, Any]) -> list[str]:
    """One matched rule with its verdict, matches, and metadata."""
    name = text(rule.get("ruleName")) or "rule"
    verdict = (text(at(rule, "verdict", "verdict")) or "unknown").lower()
    facts = rows(rule, YARA_FIELDS) + scalar_items(rule.get("metaData"))
    return [f"{name} [{verdict}]", *indent(pairs(facts))]


def yara(scan: ScanReport) -> list[str]:
    """Every YARA rule the sample matched."""
    matches = records(scan.resource("file").get("yaraMatches"))
    return [row for rule in matches for row in yara_lines(rule)]


EXTRACTED_FIELDS: tuple[Field, ...] = (
    Field("Description", ("extendedData", "fileMagicDescription")),
    Field("Size", ("fileSize",), size),
    Field("Type", ("mediaType", "string")),
    Field("Tags", ("allTags",), tag_names),
)


def extracted_lines(file: Mapping[str, Any]) -> list[str]:
    """One extracted file with its facts, digests, and metadata."""
    name = text(file.get("submitName")) or "extracted file"
    facts = rows(file, EXTRACTED_FIELDS)
    facts += scalar_items(file.get("digests")) + scalar_items(file.get("metaData"))
    return [name, *indent(pairs(facts))]


def extracted_files(scan: ScanReport) -> list[str]:
    """Every file the analysis pulled out of the sample."""
    files = records(scan.resource("file").get("extractedFiles"))
    return [row for file in files for row in extracted_lines(file)]
