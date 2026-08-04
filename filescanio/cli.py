"""Command-line interface for the filescan.io API."""

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from filescanio import __version__
from filescanio.client import FileScanClient
from filescanio.config import (
    DEFAULT_BASE_URL,
    load_settings,
    resolve_base_url,
    write_config,
)
from filescanio.errors import (
    ApiError,
    ConfigError,
    FileScanError,
    TransportError,
    Unrepresentable,
    describe,
)
from filescanio.groups._base import ReportView
from filescanio.groups.scan import DEFAULT_WORKERS, ScanOptions
from filescanio.render import Format, render, render_json
from filescanio.transport import (
    BAD_RETRIES,
    BAD_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    QueryValue,
    is_usable_retries,
    is_usable_timeout,
)

ClientHandler = Callable[[FileScanClient, argparse.Namespace], Any]
LocalHandler = Callable[[argparse.Namespace], Any]


def _parse_filters(pairs: list[str] | None) -> dict[str, QueryValue]:
    filters: dict[str, QueryValue] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise FileScanError(f"Invalid filter '{pair}', expected key=value")
        filters[key] = value
    return filters


def _positive_timeout(value: str) -> float:
    seconds = float(value)
    if not is_usable_timeout(seconds):
        raise argparse.ArgumentTypeError(BAD_TIMEOUT)
    return seconds


def _read_stdin_bytes() -> bytes:
    """Read stdin as bytes, tolerating a stream that only carries text."""
    stream = _stream("stdin")
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        return bytes(buffer.read())
    return str(stream.read()).encode("utf-8", "surrogateescape")


def _retry_count(value: str) -> int:
    count = int(value)
    if not is_usable_retries(count):
        raise argparse.ArgumentTypeError(BAD_RETRIES)
    return count


def _read_json_argument(source: str) -> Any:
    """Read UTF-8 JSON from a file or, when source is '-', from stdin."""
    try:
        raw = _read_stdin_bytes() if source == "-" else Path(source).read_bytes()
    except OSError as exc:
        raise FileScanError(f"Cannot read {source}: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise FileScanError(f"Input is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FileScanError(f"Invalid JSON input: {exc}") from exc


REPORT_FILTERS = (
    "general, finalVerdict, allTags, allSignalGroups, taskReference, "
    "subtaskReferences, opcount, processTime, f:all, fd:all, dr:all"
)


def _add_report_view_options(parser: argparse.ArgumentParser) -> None:
    """Add the options that select how much of a report is returned."""
    parser.add_argument(
        "--filter",
        action="append",
        metavar="SECTION",
        help=(
            "Restrict the report to this section; repeatable. Without any "
            "filter the whole report is returned, and an unknown name "
            f"yields an empty report. Known values: {REPORT_FILTERS}"
        ),
    )
    parser.add_argument(
        "--sorting",
        action="append",
        metavar="EXPR",
        help="Sort expression, e.g. field(subfield:asc); repeatable",
    )
    parser.add_argument(
        "--other",
        action="append",
        metavar="EXTRA",
        help="Extra section, e.g. emulationGraph; repeatable",
    )


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--description")
    parser.add_argument("--tags", help="Tags separated by | (e.g. anti-vm|macros)")
    parser.add_argument("--password", help="Password for protected archives")
    parser.add_argument(
        "--propagate-tags", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument(
        "--private", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument(
        "--private-report", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument(
        "--skip-whitelisted", action=argparse.BooleanOptionalAction, default=None
    )
    parser.add_argument("--profile", dest="scan_profile")
    parser.add_argument("--engine", dest="scan_engine")
    parser.add_argument(
        "--wait", action="store_true", help="Poll until the report is finished"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Samples submitted at once (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--wait-timeout",
        type=_positive_timeout,
        default=600.0,
        help="Seconds to keep polling with --wait (default: 600)",
    )
    parser.add_argument(
        "--wait-interval",
        type=_positive_timeout,
        default=5.0,
        help="Seconds between polls with --wait (default: 5)",
    )
    _add_report_view_options(parser)


def _scan_kwargs(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(
        description=args.description,
        tags=args.tags,
        password=args.password,
        propagate_tags=args.propagate_tags,
        is_private=args.private,
        is_private_report=args.private_report,
        skip_whitelisted=args.skip_whitelisted,
        scan_profile=args.scan_profile,
        scan_engine=args.scan_engine,
    )


def _report_view(args: argparse.Namespace) -> ReportView:
    return ReportView(
        filters=args.filter or None,
        sorting=args.sorting or None,
        other=args.other or None,
    )


def _finish_scan(
    client: FileScanClient, args: argparse.Namespace, response: Any
) -> Any:
    if not args.wait:
        return response
    flow_id = response.get("flow_id") if isinstance(response, dict) else None
    if not flow_id:
        raise FileScanError(f"Scan response contained no flow_id: {describe(response)}")
    return client.scan.wait_for_report(
        flow_id,
        interval=args.wait_interval,
        timeout=args.wait_timeout,
        **_report_view(args),
    )


def _batch_entry(
    client: FileScanClient, args: argparse.Namespace, response: Any
) -> Any:
    """Render one sample's outcome, so a failure cannot break the report."""
    if isinstance(response, FileScanError):
        return {"error": str(response)}
    return _finish_scan(client, args, response)


def _handle_scan_file(client: FileScanClient, args: argparse.Namespace) -> Any:
    """One path keeps the single-response shape; several return a list."""
    options = _scan_kwargs(args)
    if len(args.path) == 1:
        return _finish_scan(client, args, client.scan.file(args.path[0], **options))
    responses = client.scan.files(args.path, max_workers=args.max_workers, **options)
    return [_batch_entry(client, args, response) for response in responses]


def _handle_scan_url(client: FileScanClient, args: argparse.Namespace) -> Any:
    return _finish_scan(client, args, client.scan.url(args.url, **_scan_kwargs(args)))


def _handle_scan_report(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.scan.report(args.flow_id, **_report_view(args))


def _handle_report(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reports.get(args.report_id, args.file_hash, **_report_view(args))


def _handle_search(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reports.search(args.query, page=args.page, page_size=args.page_size)


def _handle_matches(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reports.search_matches(
        args.report_ids,
        unique_files=args.unique_files,
        method=args.method,
        filters=_parse_filters(args.filter),
    )


def _handle_public_reports(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reports.public(page=args.page, page_size=args.page_size)


def _handle_availability(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.files.availability(args.hashes)


def _handle_similarity(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.similarity.similar(
        args.hash,
        min_similarity=args.min_similarity,
        verdict=args.verdict,
        tags=args.tag or None,
    )


def _handle_reputation_hash(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reputation.file_hash_bulk(args.hashes)


def _handle_reputation_ioc(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reputation.ioc_bulk(args.ioc_type, args.values)


def _handle_prevalence(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.threatintel.prevalence(
        domain=args.domain,
        ip=args.ip,
        url=args.url,
        uuid=args.uuid,
        email=args.email,
        registry_path=args.registry_path,
        revision_save_id=args.revision_save_id,
        sha1=args.sha1,
        sha256=args.sha256,
        sha512=args.sha512,
        md5=args.md5,
        imphash=args.imphash,
        ssdeep=args.ssdeep,
        authentihash=args.authentihash,
        fuzzyfsiohash=args.fuzzyfsiohash,
        unc_path=args.unc_path,
        days=args.days,
        exclude_report_ids=args.exclude_report_id,
    )


def _handle_similars(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.threatintel.similars(
        imphash=args.imphash,
        ssdeep=args.ssdeep,
        fuzzyfsiohash=args.fuzzyfsiohash,
        authentihash=args.authentihash,
        days=args.days,
        exclude_report_ids=args.exclude_report_id,
    )


def _handle_terms(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.terms(args.terms_type)


def _handle_translations(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.translations(args.lang)


def _handle_healthcheck(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.query_healthcheck(days=args.days, days_from=args.days_from)


def _handle_yara(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.yara(names=args.name or None)


def _handle_logo(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.logo(logo_type=args.type, theme=args.theme, name=args.name)


def _handle_news_save(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.save_news(_read_json_argument(args.file))


def _handle_news_remove(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.remove_news(args.news_id)


def _handle_log_error(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.system.log_error(_read_json_argument(args.file))


def _handle_report_download(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.reports.download(args.report_id, export_format=args.export_format)


def _handle_avatar(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.users.avatar(args.account_id)


def _handle_oauth_callback(client: FileScanClient, args: argparse.Namespace) -> Any:
    return client.misc.oauth_callback(
        state=args.state,
        code=args.code,
        error=args.error,
        error_description=args.error_description,
    )


def _handle_config_init(args: argparse.Namespace) -> Any:
    if not args.api_key:
        raise FileScanError("config init requires --api-key")
    path = write_config(
        args.api_key,
        base_url=args.base_url or DEFAULT_BASE_URL,
        config_path=Path(args.path) if args.path else None,
    )
    return {"written": str(path)}


def _mask(secret: str) -> str:
    return f"{secret[:4]}***" if len(secret) > 8 else "***"


def _handle_config_show(args: argparse.Namespace) -> Any:
    """Show the settings the client would use, honouring the global flags."""
    config_path = Path(args.path) if args.path else None
    api_key = args.api_key or load_settings(config_path=config_path).api_key
    return {
        "api_key": _mask(api_key),
        "base_url": args.base_url or resolve_base_url(config_path=config_path),
    }


def _simple(handler: Callable[[FileScanClient], Any]) -> ClientHandler:
    return lambda client, args: handler(client)


SIMPLE_COMMANDS: dict[tuple[str, str], tuple[Callable[[FileScanClient], Any], str]] = {
    ("system", "info"): (lambda c: c.system.info(), "Get system info"),
    ("system", "version"): (lambda c: c.system.version(), "Get backend versions"),
    ("system", "config"): (lambda c: c.system.config(), "Get system config"),
    ("system", "features"): (
        lambda c: c.system.product_features(),
        "Get license product features",
    ),
    ("system", "languages"): (lambda c: c.system.languages(), "List languages"),
    ("system", "countries"): (lambda c: c.system.countries(), "List countries"),
    ("system", "mitre"): (lambda c: c.system.mitre(), "Get MITRE ATT&CK data"),
    ("system", "mbc"): (lambda c: c.system.mbc(), "Get MBC data"),
    ("system", "reputation-config"): (
        lambda c: c.system.reputation_check_config(),
        "Get reputation check config",
    ),
    ("system", "news"): (lambda c: c.system.news(), "Get news items"),
    ("users", "uploads"): (lambda c: c.users.uploads(), "List your own uploads"),
    ("users", "ioc-stats"): (lambda c: c.users.ioc_stats(), "Get IOC statistics"),
    ("users", "tags"): (lambda c: c.users.frequent_tags(), "Get frequent tags"),
    ("users", "interesting"): (
        lambda c: c.users.most_interesting(),
        "Get most interesting reports",
    ),
    ("feed", "reports"): (lambda c: c.feed.reports(), "Get reports feed"),
    ("feed", "info"): (lambda c: c.feed.reports_info(), "Get reports feed info"),
    ("misc", "openapi"): (lambda c: c.misc.openapi(), "Get the OpenAPI spec"),
    ("misc", "sitemap"): (lambda c: c.misc.sitemap(), "Get the sitemap"),
}


def _add_repeatable(parser: argparse.ArgumentParser, *names: str) -> None:
    for name in names:
        parser.add_argument(f"--{name}", action="append", dest=name.replace("-", "_"))


def _add_config_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", help="Config file path (default: home dir)")


def _add_json_input(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", required=True, help="JSON file or - for stdin")


def _add_global_options(
    parser: argparse.ArgumentParser, *, inherited: bool = False
) -> None:
    """Define the options accepted before or after any subcommand."""
    suppress = argparse.SUPPRESS
    parser.add_argument(
        "--api-key",
        default=suppress if inherited else None,
        help="API key (overrides FILESCANIO/config file)",
    )
    parser.add_argument(
        "--base-url", default=suppress if inherited else None, help="API base URL"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        default=suppress if inherited else False,
        help="Compact JSON output (one line)",
    )
    parser.add_argument(
        "--format",
        type=Format,
        choices=list(Format),
        default=suppress if inherited else None,
        help="Output format (default: table on a terminal, json when piped)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=suppress if inherited else None,
        help="Write the response to this file",
    )
    parser.add_argument(
        "--max-retries",
        type=_retry_count,
        default=suppress if inherited else DEFAULT_MAX_RETRIES,
        help="Times to retry a rate-limited request (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=suppress if inherited else DEFAULT_TIMEOUT,
        help="HTTP timeout in seconds",
    )


def _inheritable_globals() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    _add_global_options(parent, inherited=True)
    return parent


GLOBAL_OPTIONS = _inheritable_globals()


def _subparser(commands: Any, name: str, **kwargs: Any) -> argparse.ArgumentParser:
    """Add a subparser that also accepts the global options."""
    subparser: argparse.ArgumentParser = commands.add_parser(
        name, parents=[GLOBAL_OPTIONS], **kwargs
    )
    return subparser


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser covering every API command."""
    parser = argparse.ArgumentParser(
        prog="filescan", description="CLI for the filescan.io API"
    )
    parser.add_argument("--version", action="version", version=__version__)
    _add_global_options(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    config = _subparser(commands, "config", help="Manage local configuration")
    config_sub = config.add_subparsers(dest="subcommand", required=True)
    config_init = _subparser(config_sub, "init", help="Write the config file")
    _add_config_path(config_init)
    config_init.set_defaults(local_handler=_handle_config_init)
    config_show = _subparser(config_sub, "show", help="Show resolved configuration")
    _add_config_path(config_show)
    config_show.set_defaults(local_handler=_handle_config_show)

    scan = _subparser(commands, "scan", help="Submit files or URLs for scanning")
    scan_sub = scan.add_subparsers(dest="subcommand", required=True)
    scan_file = _subparser(scan_sub, "file", help="Scan a local file")
    scan_file.add_argument("path", nargs="+")
    _add_scan_options(scan_file)
    scan_file.set_defaults(handler=_handle_scan_file)
    scan_url = _subparser(scan_sub, "url", help="Scan a URL")
    scan_url.add_argument("url")
    _add_scan_options(scan_url)
    scan_url.set_defaults(handler=_handle_scan_url)
    scan_report = _subparser(scan_sub, "report", help="Get reports for a scan flow")
    scan_report.add_argument("flow_id")
    _add_report_view_options(scan_report)
    scan_report.set_defaults(handler=_handle_scan_report)

    report_download = _subparser(
        commands, "report-download", help="Download a full report (undocumented API)"
    )
    report_download.add_argument("report_id")
    report_download.add_argument(
        "--as",
        dest="export_format",
        choices=("misp", "stix", "html", "pdf"),
        help="Server-side export format; omitted, the default serialisation",
    )
    report_download.set_defaults(handler=_handle_report_download)

    report = _subparser(commands, "report", help="Get a specific report")
    report.add_argument("report_id")
    report.add_argument("file_hash")
    _add_report_view_options(report)
    report.set_defaults(handler=_handle_report)

    search = _subparser(commands, "search", help="Search reports")
    search.add_argument("query", nargs="?")
    search.add_argument("--page", type=int)
    search.add_argument("--page-size", type=int, choices=(5, 10, 20))
    search.set_defaults(handler=_handle_search)

    reports = _subparser(commands, "reports", help="Report collections")
    reports_sub = reports.add_subparsers(dest="subcommand", required=True)
    reports_public = _subparser(reports_sub, "public", help="Get public reports")
    reports_public.add_argument("--page", type=int)
    reports_public.add_argument("--page-size", type=int, choices=(5, 10, 20))
    reports_public.set_defaults(handler=_handle_public_reports)
    reports_matches = _subparser(
        reports_sub, "matches", help="Get matches for searched reports"
    )
    reports_matches.add_argument("report_ids", nargs="+")
    reports_matches.add_argument(
        "--unique-files", action=argparse.BooleanOptionalAction, default=None
    )
    reports_matches.add_argument("--method", choices=("or", "and"))
    reports_matches.add_argument("--filter", action="append")
    reports_matches.set_defaults(handler=_handle_matches)

    files = _subparser(commands, "files", help="File operations")
    files_sub = files.add_subparsers(dest="subcommand", required=True)
    availability = _subparser(
        files_sub, "availability", help="Check availability of file hashes"
    )
    availability.add_argument("hashes", nargs="+")
    availability.set_defaults(handler=_handle_availability)

    similarity = _subparser(
        commands,
        "similarity",
        help="Find similar reports (deprecated upstream; see threatintel similars)",
    )
    similarity.add_argument("hash", help="SHA256 hash")
    similarity.add_argument("--min-similarity", type=int, help="Percentage 0-100")
    similarity.add_argument("--verdict")
    similarity.add_argument("--tag", action="append")
    similarity.set_defaults(handler=_handle_similarity)

    reputation = _subparser(commands, "reputation", help="IOC reputation lookups")
    reputation_sub = reputation.add_subparsers(dest="subcommand", required=True)
    reputation_hash = _subparser(
        reputation_sub,
        "hash",
        help="Hash reputation (bulk when several hashes are given)",
    )
    reputation_hash.add_argument("hashes", nargs="+", help="SHA256 hash(es)")
    reputation_hash.set_defaults(handler=_handle_reputation_hash)
    reputation_ioc = _subparser(
        reputation_sub,
        "ioc",
        help="IOC reputation (bulk when several values are given)",
    )
    reputation_ioc.add_argument("ioc_type", choices=("domain", "ip", "url"))
    reputation_ioc.add_argument("values", nargs="+")
    reputation_ioc.set_defaults(handler=_handle_reputation_ioc)

    threatintel = _subparser(commands, "threatintel", help="Threat intelligence")
    threatintel_sub = threatintel.add_subparsers(dest="subcommand", required=True)
    prevalence = _subparser(threatintel_sub, "prevalence", help="Get IOC prevalence")
    _add_repeatable(
        prevalence,
        "domain",
        "ip",
        "url",
        "uuid",
        "email",
        "registry-path",
        "revision-save-id",
        "sha1",
        "sha256",
        "sha512",
        "md5",
        "imphash",
        "ssdeep",
        "authentihash",
        "fuzzyfsiohash",
        "unc-path",
        "exclude-report-id",
    )
    prevalence.add_argument("--days", type=int)
    prevalence.set_defaults(handler=_handle_prevalence)
    similars = _subparser(
        threatintel_sub, "similars", help="Reports sharing special hashes"
    )
    similars.add_argument("--imphash")
    similars.add_argument("--ssdeep")
    similars.add_argument("--fuzzyfsiohash")
    similars.add_argument("--authentihash")
    similars.add_argument("--days", type=int)
    similars.add_argument("--exclude-report-id", action="append")
    similars.set_defaults(handler=_handle_similars)

    system = _subparser(commands, "system", help="System information")
    system_sub = system.add_subparsers(dest="subcommand", required=True)
    terms = _subparser(system_sub, "terms", help="Get terms documents")
    terms.add_argument(
        "terms_type", choices=("privacy-policy", "terms-condition", "cookie-policy")
    )
    terms.set_defaults(handler=_handle_terms)
    translations = _subparser(system_sub, "translations", help="Get UI translations")
    translations.add_argument("lang")
    translations.set_defaults(handler=_handle_translations)
    healthcheck = _subparser(system_sub, "healthcheck", help="Query healthcheck")
    healthcheck.add_argument("--days", type=int)
    healthcheck.add_argument("--days-from", type=int)
    healthcheck.set_defaults(handler=_handle_healthcheck)
    yara = _subparser(system_sub, "yara", help="Download YARA rules")
    yara.add_argument("--name", action="append")
    yara.set_defaults(handler=_handle_yara)
    logo = _subparser(system_sub, "logo", help="Download the site logo")
    logo.add_argument("--type", choices=("main", "top_menu", "footer"))
    logo.add_argument("--theme", choices=("light", "dark"))
    logo.add_argument("--name")
    logo.set_defaults(handler=_handle_logo)
    news_save = _subparser(system_sub, "news-save", help="Save a news item (admin)")
    _add_json_input(news_save)
    news_save.set_defaults(handler=_handle_news_save)
    news_remove = _subparser(
        system_sub, "news-remove", help="Remove a news item (admin)"
    )
    news_remove.add_argument("news_id")
    news_remove.set_defaults(handler=_handle_news_remove)
    log_error = _subparser(system_sub, "log-error", help="Log a client error")
    _add_json_input(log_error)
    log_error.set_defaults(handler=_handle_log_error)

    users = _subparser(commands, "users", help="User data")
    users_sub = users.add_subparsers(dest="subcommand", required=True)
    avatar = _subparser(users_sub, "avatar", help="Download an account avatar")
    avatar.add_argument("account_id")
    avatar.set_defaults(handler=_handle_avatar)

    misc = _subparser(commands, "misc", help="Miscellaneous endpoints")
    misc_sub = misc.add_subparsers(dest="subcommand", required=True)
    oauth = _subparser(
        misc_sub, "oauth-callback", help="Scan source OAuth callback (admin)"
    )
    oauth.add_argument("--state")
    oauth.add_argument("--code")
    oauth.add_argument("--error")
    oauth.add_argument("--error-description")
    oauth.set_defaults(handler=_handle_oauth_callback)

    subparser_groups = {
        "system": system_sub,
        "users": users_sub,
        "feed": _subparser(commands, "feed", help="Reports feed").add_subparsers(
            dest="subcommand", required=True
        ),
        "misc": misc_sub,
    }
    for (group_name, command_name), (func, help_text) in SIMPLE_COMMANDS.items():
        simple = _subparser(subparser_groups[group_name], command_name, help=help_text)
        simple.set_defaults(handler=_simple(func))

    return parser


def _exit_code(error: FileScanError) -> int:
    """Map a failure to a code a calling script can branch on."""
    if isinstance(error, ConfigError):
        return 3
    if isinstance(error, ApiError):
        return 4 if error.status_code < 500 else 5
    if isinstance(error, TransportError):
        return 6
    return 1


def _stream(name: str) -> Any:
    """Return a standard stream, or fail cleanly when it is closed."""
    stream = getattr(sys, name)
    if stream is None:
        raise FileScanError(f"{name} is closed")
    return stream


def _resolve_format(fmt: Format | None, stream: Any) -> Format:
    """Show a table only when a person is looking; pipes and files get JSON."""
    if fmt is not None:
        return fmt
    return Format.TABLE if stream.isatty() else Format.JSON


def _payload(result: Any, fmt: Format, *, compact: bool) -> bytes:
    """Render the result, falling back to JSON when the format cannot hold it."""
    if isinstance(result, str):
        return result.encode() + b"\n"
    try:
        try:
            text = render(result, fmt, compact=compact)
        except Unrepresentable as exc:
            print(f"note: {exc}; showing JSON instead", file=sys.stderr)
            text = render_json(result, compact=compact)
    except (ValueError, RecursionError) as exc:
        raise FileScanError(f"Cannot render the response: {exc}") from exc
    return text.encode() + b"\n"


def _emit(
    result: Any, *, fmt: Format | None = None, raw: bool = False, output: str | None
) -> None:
    if output is not None:
        payload = (
            result
            if isinstance(result, bytes)
            else _payload(result, fmt or Format.JSON, compact=raw)
        )
        _write_output(output, payload)
        return
    stdout = _stream("stdout")
    payload = (
        result
        if isinstance(result, bytes)
        else _payload(result, _resolve_format(fmt, stdout), compact=raw)
    )
    buffer = getattr(stdout, "buffer", None)
    if buffer is None:
        stdout.write(payload.decode("utf-8", errors="replace"))
    else:
        buffer.write(payload)
    stdout.flush()


def _write_output(destination: str, payload: bytes) -> None:
    try:
        Path(destination).write_bytes(payload)
    except OSError as exc:
        raise FileScanError(f"Cannot write {destination}: {exc}") from exc


def _discard_stdout() -> None:
    """Point stdout at the void so the final flush cannot fail on a dead pipe."""
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def _settle_stdout() -> None:
    """Push out what argparse wrote, tolerating a reader that has gone away."""
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        _discard_stdout()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit:
        # argparse writes help and usage errors itself, so flush them here:
        # left to the interpreter's own exit, a closed pipe becomes noise.
        _settle_stdout()
        raise
    try:
        local_handler: LocalHandler | None = getattr(args, "local_handler", None)
        if local_handler is not None:
            _emit(
                local_handler(args), fmt=args.format, raw=args.raw, output=args.output
            )
            return 0
        with FileScanClient(
            api_key=args.api_key,
            base_url=args.base_url,
            timeout=args.timeout,
            max_retries=args.max_retries,
        ) as client:
            result = args.handler(client, args)
        _emit(result, fmt=args.format, raw=args.raw, output=args.output)
        return 0
    except FileScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _exit_code(exc)
    except BrokenPipeError:
        _discard_stdout()
        return 1
