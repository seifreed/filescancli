<p align="center">
  <img src="https://img.shields.io/badge/filescancli-Malware%20Analysis%20API-blue?style=for-the-badge" alt="filescancli">
</p>

<h1 align="center">filescancli</h1>

<p align="center">
  <strong>Complete Python client and CLI for the filescan.io malware analysis API</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.14%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/filescancli/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/filescancli/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/filescancli/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/SARIF-2.1.0%20output-brightgreen?style=flat-square" alt="SARIF">
</p>

<p align="center">
  <a href="https://github.com/seifreed/filescancli/stargazers"><img src="https://img.shields.io/github/stars/seifreed/filescancli?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/filescancli/issues"><img src="https://img.shields.io/github/issues/seifreed/filescancli?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**filescancli** is a Python toolkit to submit samples and URLs to
[filescan.io](https://www.filescan.io/api/docs), poll for reports, and query
reputation and threat intelligence. It covers **every endpoint** the published
OpenAPI document declares, as a typed library and as a CLI, with
machine-readable output including JSON, TOON, and SARIF 2.1.0.

### Key Features

| Feature | Description |
|---------|-------------|
| **Full API coverage** | One method per endpoint, verified against the published OpenAPI document |
| **Library + CLI** | `filescanio` package and the `filescan` command, same capabilities |
| **Namespaced groups** | `scan`, `reports`, `reputation`, `threatintel`, `system`, and five more |
| **Settled-report polling** | `--wait` waits for post-processing, not just the `allFinished` flag |
| **SARIF 2.1.0** | Scan reports as code-scanning findings, validated against the schema |
| **TOON** | Compact, token-efficient encoding for LLM prompts |
| **Typed errors** | `ApiError` with status and detail, `ConfigError`, `TransportError` |
| **Cross-platform** | Windows, Linux and macOS, x64 and ARM, all covered by CI |

### Supported Outputs

```text
Structured data   JSON (pretty or one-line), TOON
Findings          SARIF 2.1.0 from scan reports
Terminal          Column tables, automatic when stdout is a terminal
Raw passthrough   Binary (logos, avatars) and text (feeds, sitemap)
```

---

## Installation

### From Source

```bash
git clone https://github.com/seifreed/filescancli.git
cd filescancli
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

Installing the package pulls in `httpx` and `prettytable` only.

---

## Quick Start

```bash
# Authenticate
export FILESCANIO=your-api-key

# Submit a URL and wait for the settled report
filescan scan url https://example.com --wait

# Look up a hash reputation
filescan reputation hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Export a scan report as SARIF
filescan report <report_id> <sha256> --filter allSignalGroups --format sarif -o out.sarif

# Read a scan report as a human
filescan report <report_id> <sha256> --filter f:all --format report
```

---

## Authentication

The API key is resolved in this order:

1. `--api-key` CLI flag / `FileScanClient(api_key=...)`
2. `FILESCANIO` environment variable
3. `~/.filescanio.toml` config file (`api_key`, optional `base_url`)

The base URL resolves independently, in the same order: `--base-url`,
`FILESCANIO_BASE_URL`, the config file, then `https://www.filescan.io`.

```bash
filescan config init --api-key your-api-key
filescan config show
```

On POSIX the config file is created `0600` and a symlink at that path is
refused rather than followed. Windows expresses neither, so there the key
relies on the access control list its directory already carries — keep it
under your user profile.

---

## Usage

### Command Line Interface

```bash
filescan scan file sample.bin --tags "malware|test" --wait --wait-timeout 1800
filescan scan url https://example.com --wait
filescan scan report <flow_id>
filescan report <report_id> <sha256> --filter general --filter allSignalGroups
filescan search "mirai" --verdict malicious --filetype peexe --age 7  # --filetype validates against the platform's type list
filescan reports public --page 1
filescan reports matches <report_id> --filter verdict=malicious
filescan report-download <report_id> --as pdf -o report.pdf   # misp|stix|html|pdf
filescan files availability <sha256> [<sha256> ...]
filescan files download <sha256> --password infected -o sample.zip
filescan similarity <sha256> --min-similarity 80   # endpoint deprecated upstream
filescan reputation hash <sha256> [<sha256> ...]      # bulk when several
filescan reputation ioc domain evil.example [more...] # domain|ip|url
filescan threatintel prevalence --domain example.com --days 30
filescan threatintel similars --imphash <hash>
filescan feed reports
filescan system version|info|config|features|mitre|mbc|news|...
filescan system yara -o rules.json
filescan system logo --theme dark -o logo.svg
filescan users avatar <account_id> -o avatar.png
filescan users tags|ioc-stats|interesting
filescan misc openapi|sitemap
```

### Command Groups

| Command | Description |
|---------|-------------|
| `filescan scan` | Submit files or URLs, fetch and poll flow reports |
| `filescan report` | A single report by report ID and file hash |
| `filescan search` / `reports` | Search by text or by field (verdict, hashes, IOCs, YARA rule, age...), public listings, match filters |
| `filescan files` | Hash availability, sample download |
| `filescan reputation` | Hash and IOC reputation, bulk when several values are given |
| `filescan threatintel` | IOC prevalence and special-hash similarity |
| `filescan system` | Platform info, config, YARA, MITRE/MBC reference data |
| `filescan users` / `feed` / `misc` | Account data, public feeds, OpenAPI and sitemap |
| `filescan config` | Write and inspect the local credentials file |

### Output Formats

`--format` picks how a response is rendered. Without it the CLI shows a
**table** when stdout is a terminal and **JSON** when it is piped or
redirected, so `filescan system info` is readable and
`filescan system info | jq` still works.

| Format | Notes |
|--------|-------|
| `table` | Column layout via prettytable. Default on a terminal. |
| `json` | Pretty-printed; `--raw` puts it on one line. Default when piped or with `-o`. |
| `toon` | [TOON](https://github.com/toon-format/spec) — compact, token-efficient, for LLM prompts. Encoding only, comma delimiter, two-space indent. |
| `sarif` | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) for scan reports, so findings can be uploaded to code-scanning tools. |
| `report` | A readable digest of a scan report: verdict, tags, signal groups, per-family file details (PE/ELF/PDF/Office/LNK/Mbox), emulation, IOCs, disassembly, YARA, notable strings, extracted files, OSINT and geolocation. Sections with nothing to say are omitted. |

`--format report` adds colour when stdout is a terminal, honouring the
[`NO_COLOR` / `FORCE_COLOR`](https://no-color.org) conventions; pipes,
redirections and `-o` files always receive plain text. `scan file` and
`scan url` show a spinner on stderr under the same rules, so scripts stay
completely silent.

A format that cannot express a response falls back to JSON and says so on
stderr — asking for a table of a nested scan report, or SARIF of
`system languages`, never fails the command. Binary responses
(`system logo`, `users avatar`) and text ones (`feed reports`,
`misc sitemap`) always pass through untouched.

Reports return only basic data unless you ask for sections with `--filter`
(`general`, `finalVerdict`, `allTags`, `allSignalGroups`, `f:all`, `fd:all`,
`dr:all`, ...). `--wait` polls until the scan flow is fully settled, not
merely until `allFinished` turns true: the API sets that flag while
post-processing is still running and the report is still missing sections
such as `allSignalGroups`.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Other client-side failure |
| 2 | Usage error (argparse) |
| 3 | Missing or invalid configuration |
| 4 | API returned 4xx |
| 5 | API returned 5xx |
| 6 | Network or protocol failure |

---

## Python Library

### Basic Usage

```python
from filescanio import FileScanClient

with FileScanClient() as client:
    scan = client.scan.url("https://example.com")
    report = client.scan.wait_for_report(scan["flow_id"])

    results = client.reports.search("mirai", page_size=10)
    reputation = client.reputation.file_hash("e3b0c44298fc1c...")
    prevalence = client.threatintel.prevalence(domain=["example.com"])
```

Groups: `scan`, `reports`, `files`, `similarity`, `system`, `users`, `feed`,
`misc`, `reputation`, `threatintel` — one method per API endpoint.

### Error Handling

```python
from filescanio import ApiError, ConfigError, FileScanClient, RequestTimeout

try:
    with FileScanClient() as client:
        client.reports.get("missing", "hash")
except ApiError as exc:
    print(exc.status_code, exc.detail, exc.retry_after)
except RequestTimeout:
    print("the API did not answer in time")
except ConfigError as exc:
    print("no usable credentials:", exc)
```

Every failure is a `FileScanError` subclass, so one `except FileScanError`
catches the lot.

### Rendering

```python
from filescanio.render import Format, Unrepresentable, render

try:
    print(render(report, Format.SARIF))
except Unrepresentable as exc:
    print("that shape has no SARIF form:", exc)
```

---

## SARIF and Code Scanning

SARIF is built from scan reports: one result per entry in `allSignalGroups`,
falling back to the report's `finalVerdict`, with the sample recorded as a
SARIF artifact carrying its SHA-256. Ask for the sections you want first:

```bash
filescan report <report_id> <sha256> --filter allSignalGroups --format sarif -o results.sarif
```

Uploading those findings to GitHub Code Scanning:

```yaml
- name: Scan a sample and export SARIF
  env:
    FILESCANIO: ${{ secrets.FILESCANIO }}
  run: filescan scan file sample.bin --wait --format sarif -o results.sarif

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Requirements

- Python 3.14+
- Windows, Linux or macOS, x64 or ARM
- See [pyproject.toml](pyproject.toml) for dependencies and the `dev` extra

---

## Development

All dependencies live in `pyproject.toml`; the development toolchain is the
`dev` extra in the same file:

```bash
python -m venv venv && venv/bin/pip install -e ".[dev]"
```

Quality and security gates, all of which must pass without a single warning
and without any suppression:

```bash
black --check . && ruff check . && mypy .
bandit -c pyproject.toml -r . && pip-audit --skip-editable
pytest   # enforces 100% coverage, tests hit a real in-process HTTP server
```

Nothing in `tests/` is skipped or needs credentials. Two directories sit
outside the coverage scope, because a test that cannot run everywhere would
count as uncovered wherever it is skipped:

- `posix/` runs with the suite but is not measured. It holds the checks for
  permission bits, symlink refusal, FIFO handling and broken-pipe behaviour,
  none of which Windows can express.
- `smoke/` talks to the real API, so it is not collected at all. Besides the
  request smoke checks it verifies that every path the published OpenAPI
  document declares is implemented, fetching that document rather than
  keeping a copy of it in the repository:

  ```bash
  FILESCANIO=your-key pytest smoke --no-cov
  ```

CI runs every gate on Ubuntu, macOS and Windows. The coverage gate is
enforced once, on Ubuntu, because the CLI's broken-pipe handling needs POSIX
pipe semantics: demanding 100% on Windows would fail over code Windows cannot
reach rather than over a gap in the suite. Every platform still runs every
test.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Every gate above must pass before a change is accepted, and suppressing a
warning to make one pass is not an option.

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/filescancli](https://github.com/seifreed/filescancli)

---

<p align="center">
  <sub>Built for practical malware analysis workflows and security automation</sub>
</p>
