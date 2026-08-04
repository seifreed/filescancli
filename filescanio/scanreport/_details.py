"""The file-details section, laid out per file family.

Dispatch is two dict lookups — tag to kind, kind to fields — so a new family
costs a table entry, never a branch.
"""

from filescanio.scanreport._access import at, records
from filescanio.scanreport._layout import (
    Field,
    flag,
    joined,
    pairs,
    rows,
    scalar_items,
    size,
)
from filescanio.scanreport.model import FileKind, ScanReport

KIND_BY_TAG: dict[str, FileKind] = {
    "peexe": FileKind.PE,
    "pedll": FileKind.PE,
    "64bits": FileKind.PE,
    "elf": FileKind.ELF,
    "pdf": FileKind.PDF,
    "lnk": FileKind.LNK,
    "mbox": FileKind.MBOX,
    **dict.fromkeys(
        (
            "doc",
            "docm",
            "docx",
            "dot",
            "dotm",
            "dotx",
            "ole",
            "ppt",
            "pptm",
            "pptx",
            "pot",
            "potm",
            "potx",
            "rtf",
            "xls",
            "xlsb",
            "xlsm",
            "xlsx",
            "xlt",
            "xltm",
            "xltx",
            "xsl",
            "csv",
        ),
        FileKind.OFFICE,
    ),
}

OVERVIEW_FIELDS: tuple[Field, ...] = (
    Field("Description", ("extendedData", "fileMagicDescription")),
    Field("Size", ("fileSize",), size),
)

HASH_FIELDS: tuple[Field, ...] = (
    Field("Imphash", ("extendedData", "imphash")),
    Field("SSDeep", ("extendedData", "ssdeep")),
    Field("Authentihash", ("extendedData", "authentihash")),
    Field("SDhash", ("extendedData", "sdhash")),
    Field("TLSH", ("extendedData", "tlsh")),
)

PE_FIELDS: tuple[Field, ...] = (
    Field("Architecture", ("extendedData", "architecture")),
    Field("Subsystem", ("extendedData", "subsystemReadable")),
    Field("Language", ("extendedData", "language")),
    Field("Packers", ("extendedData", "packers"), joined),
    Field("Signed", ("extendedData", "isDigitallySigned"), flag),
    Field(".NET", ("extendedData", "isDotNet"), flag),
    Field("Packed", ("extendedData", "isPacked"), flag),
    Field("Compiled", ("extendedData", "dates", "dateUtc")),
)

PDF_FIELDS: tuple[Field, ...] = (
    Field("Author", ("extendedData", "author")),
    Field("Creator", ("extendedData", "creator")),
    Field("Producer", ("extendedData", "producer")),
    Field("Encrypted", ("extendedData", "isEncrypted"), flag),
)

OFFICE_FIELDS: tuple[Field, ...] = (
    Field("VBA stomping", ("extendedData", "vbaStomping"), flag),
)

# Mail metadata lives under metaData, not extendedData: a different path,
# never a per-kind callback.
MBOX_FIELDS: tuple[Field, ...] = (
    Field("Subject", ("metaData", "Subject")),
    Field("From", ("metaData", "From")),
    Field("To", ("metaData", "To")),
    Field("Date", ("metaData", "Date")),
    Field("In-Reply-To", ("metaData", "In-Reply-To")),
)

DETAIL_FIELDS: dict[FileKind, tuple[Field, ...]] = {
    FileKind.PE: PE_FIELDS,
    FileKind.ELF: (),
    FileKind.PDF: PDF_FIELDS,
    FileKind.OFFICE: OFFICE_FIELDS,
    FileKind.LNK: (),
    FileKind.MBOX: MBOX_FIELDS,
    FileKind.OTHER: (),
}


def kind_of(scan: ScanReport) -> FileKind:
    """The file family named by the report's root media-type tag."""
    for tag in records(scan.report.get("allTags")):
        rooted = bool(tag.get("isRootTag")) and tag.get("source") == "MEDIA_TYPE"
        kind = KIND_BY_TAG.get(str(at(tag, "tag", "name")), FileKind.OTHER)
        if rooted and kind is not FileKind.OTHER:
            return kind
    return FileKind.OTHER


def details(scan: ScanReport) -> list[str]:
    """What the file is: magic, size, digests, and family-specific facts."""
    resource = scan.resource("file")
    found = rows(resource, OVERVIEW_FIELDS)
    found += scalar_items(resource.get("digests"))
    found += rows(resource, HASH_FIELDS + DETAIL_FIELDS[kind_of(scan)])
    return pairs(found)
