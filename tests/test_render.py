"""Tests for the output renderers."""

import json
import math
from typing import Any

import pytest

from filescanio.errors import Unrepresentable
from filescanio.render import (
    SARIF_SCHEMA,
    Format,
    render,
    render_json,
    render_sarif,
    render_table,
    render_toon,
)

# ---------------------------------------------------------------- JSON


def test_json_is_indented_by_default() -> None:
    assert render_json({"a": 1}) == '{\n  "a": 1\n}'


def test_json_compact_is_one_line() -> None:
    assert render_json({"a": 1, "b": 2}, compact=True) == '{"a": 1, "b": 2}'


# --------------------------------------------------------------- table


def test_table_of_records_unions_the_columns() -> None:
    out = render_table([{"id": 1, "name": "a"}, {"id": 2, "extra": True}])
    assert out.splitlines()[1].split() == ["|", "id", "|", "name", "|", "extra", "|"]
    assert "| 1  | a    | null  |" in out
    assert "| 2  | null | true  |" in out


def test_table_of_scalars_has_one_column() -> None:
    out = render_table(["a", "b"])
    assert "| value |" in out
    assert "| a     |" in out


def test_table_of_a_flat_object_is_field_and_value() -> None:
    out = render_table({"api_version": "4.2"})
    assert "| field       | value |" in out
    assert "| api_version | 4.2   |" in out


def test_table_of_a_map_of_records_promotes_the_key() -> None:
    out = render_table({"es": {"name": "Spanish"}, "de": {"name": "German"}})
    assert "| key | name    |" in out
    assert "| es  | Spanish |" in out


def test_table_of_a_map_of_records_renames_a_clashing_key_column() -> None:
    out = render_table({"es": {"key": "K", "name": "Spanish"}})
    assert "| key_ | key | name    |" in out
    assert "| es   | K   | Spanish |" in out


@pytest.mark.parametrize(
    "value",
    [
        pytest.param([{}], id="list of one empty record"),
        pytest.param([{}, {}], id="list of empty records"),
        pytest.param({"items": [{}]}, id="envelope of empty records"),
    ],
)
def test_table_refuses_records_without_any_field(value: Any) -> None:
    with pytest.raises(Unrepresentable):
        render_table(value)


def test_table_unwraps_an_items_envelope_and_footers_the_rest() -> None:
    out = render_table({"items": [{"id": 1}], "count": 1, "method": "or"})
    assert "| id |" in out
    assert "| count  | 1     |" in out
    assert "| method | or    |" in out


def test_table_envelope_footers_a_nested_sibling_as_json() -> None:
    """A dropped sibling would hide things like a pagination total."""
    out = render_table({"items": [{"id": 1}], "pagination": {"total": 4213}})
    assert "| id |" in out
    assert '| pagination | {"total": 4213} |' in out


def test_table_shortens_an_oversized_cell() -> None:
    out = render_table([{"content": "x" * 200}])
    assert "…" in out
    assert "x" * 200 not in out


def test_table_renders_a_nested_cell_as_compact_json() -> None:
    out = render_table([{"a": {"b": 1}}])
    assert '{"b": 1}' in out


@pytest.mark.parametrize(
    "value",
    [
        pytest.param([], id="empty list"),
        pytest.param([1, {"a": 1}], id="mixed list"),
        pytest.param({}, id="empty object"),
        pytest.param({"a": {"b": 1}, "c": 2}, id="mixed object"),
        pytest.param(5, id="scalar"),
        pytest.param(None, id="null"),
        pytest.param("text", id="string"),
    ],
)
def test_table_refuses_shapes_without_rows(value: Any) -> None:
    with pytest.raises(Unrepresentable):
        render_table(value)


# ---------------------------------------------------------------- TOON


def test_toon_matches_the_specification_example() -> None:
    out = render_toon(
        {
            "location": {"city": "Berlin", "country": "DE"},
            "alerts": ["frost", "wind"],
            "forecast": [
                {"day": "Mon", "condition": "snow"},
                {"day": "Tue", "condition": "cloudy"},
            ],
        }
    )
    assert out == (
        "location:\n"
        "  city: Berlin\n"
        "  country: DE\n"
        "alerts[2]: frost,wind\n"
        "forecast[2]{day,condition}:\n"
        "  Mon,snow\n"
        "  Tue,cloudy"
    )


def test_toon_uses_list_form_for_non_uniform_records() -> None:
    out = render_toon({"rows": [{"a": 1}, {"b": 2}]})
    assert out.splitlines()[0] == "rows[2]:"
    assert out.splitlines()[1].strip().startswith("- ")


def test_toon_uses_list_form_for_a_list_mixing_scalars_and_records() -> None:
    out = render_toon({"rows": [1, {"a": 2}]})
    assert out.splitlines()[0] == "rows[2]:"
    assert out.splitlines()[1].strip() == "- 1"


def test_toon_uses_list_form_when_a_record_holds_a_nested_value() -> None:
    out = render_toon({"rows": [{"a": {"deep": 1}}, {"a": {"deep": 2}}]})
    assert out.splitlines()[0] == "rows[2]:"


def test_toon_indents_a_list_item_under_its_own_dash() -> None:
    out = render_toon({"rows": [{"a": 1, "b": {"c": 2}}, {"a": 3, "b": {"c": 4}}]})
    assert out == "rows[2]:\n  - a: 1\n    b:\n      c: 2\n  - a: 3\n    b:\n      c: 4"


def test_toon_root_array_of_scalars() -> None:
    assert render_toon([1, 2, 3]) == "[3]: 1,2,3"


def test_toon_root_empty_array() -> None:
    assert render_toon([]) == "[]"


def test_toon_empty_collections() -> None:
    assert render_toon({"a": [], "b": {}}) == "a: []\nb:"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param({}, id="at the root"),
        pytest.param({"a": [{}]}, id="as the only list item"),
        pytest.param({"a": [{}, {}]}, id="as every list item"),
    ],
)
def test_toon_refuses_an_object_with_no_key_to_carry_it(value: Any) -> None:
    """Rendered anyway it is a blank line, which no decoder can read back."""
    with pytest.raises(Unrepresentable):
        render_toon(value)


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        pytest.param(1, "1", id="int"),
        pytest.param(1.0, "1", id="trailing zero dropped"),
        pytest.param(-0.0, "0", id="negative zero"),
        pytest.param(1.5, "1.5", id="fraction"),
        pytest.param(1e-7, "1e-7", id="below the plain range"),
        pytest.param(1e25, "1e+25", id="above the plain range"),
        pytest.param(0.000001, "0.000001", id="lower bound stays plain"),
        pytest.param(1e20, "100000000000000000000", id="upper range stays plain"),
        pytest.param(
            1.2345678901234567e-06,
            "0.0000012345678901234567",
            id="every significant digit survives",
        ),
    ],
)
def test_toon_numbers_are_canonical(number: float, expected: str) -> None:
    assert render_toon({"n": number}) == f"n: {expected}"


@pytest.mark.parametrize("number", [math.inf, math.nan])
def test_toon_refuses_non_finite_numbers(number: float) -> None:
    with pytest.raises(Unrepresentable):
        render_toon({"n": number})


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("plain", "plain", id="bare"),
        pytest.param("", '""', id="empty"),
        pytest.param(" pad ", '" pad "', id="padded"),
        pytest.param("true", '"true"', id="reserved word"),
        pytest.param("12", '"12"', id="numeric"),
        pytest.param("a,b", '"a,b"', id="delimiter"),
        pytest.param("-lead", '"-lead"', id="leading dash"),
        pytest.param("#hash", '"#hash"', id="leading hash"),
        pytest.param("a:b", '"a:b"', id="structural"),
    ],
)
def test_toon_quotes_strings_that_need_it(text: str, expected: str) -> None:
    assert render_toon({"s": text}) == f"s: {expected}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("a\\b", '"a\\\\b"', id="backslash"),
        pytest.param('a"b', '"a\\"b"', id="quote"),
        pytest.param("a\nb", '"a\\nb"', id="newline"),
        pytest.param("a\rb", '"a\\rb"', id="carriage return"),
        pytest.param("a\tb", '"a\\tb"', id="tab"),
        pytest.param("a\x01b", '"a\\u0001b"', id="control"),
        pytest.param("a\x7fb", '"a\\u007fb"', id="delete"),
    ],
)
def test_toon_uses_only_the_six_legal_escapes(text: str, expected: str) -> None:
    assert render_toon({"s": text}) == f"s: {expected}"


def test_toon_quotes_keys_that_are_not_bare() -> None:
    assert render_toon({"with space": 1}) == '"with space": 1'


def test_toon_booleans_and_null() -> None:
    assert (
        render_toon({"a": True, "b": False, "c": None}) == "a: true\nb: false\nc: null"
    )


@pytest.mark.parametrize(
    "value",
    [pytest.param(5, id="scalar root"), pytest.param("text", id="string root")],
)
def test_toon_needs_a_collection_at_the_root(value: Any) -> None:
    with pytest.raises(Unrepresentable):
        render_toon(value)


def test_toon_refuses_a_type_outside_the_json_model() -> None:
    with pytest.raises(Unrepresentable):
        render_toon({"a": object()})


def test_toon_never_emits_tabs_or_trailing_whitespace() -> None:
    out = render_toon({"rows": [{"a": 1, "b": 2}], "note": "x", "nested": {"k": []}})
    assert "\t" not in out
    assert all(line == line.rstrip() for line in out.splitlines())


def test_toon_declared_length_matches_the_row_count() -> None:
    records = [{"a": i} for i in range(4)]
    lines = render_toon({"rows": records}).splitlines()
    assert lines[0].startswith("rows[4]{")
    assert len(lines) - 1 == 4


# --------------------------------------------------------------- SARIF

MALICIOUS_REPORT = {
    # fileSize sits beside "reports" in the API, not inside a report.
    "fileSize": 2048,
    "reports": {
        "r1": {
            "file": {"name": "evil.exe", "hash": "a" * 64},
            "finalVerdict": {"verdict": "malicious", "threatLevel": 0.9},
            "allSignalGroups": [
                {
                    "id": "SG-1",
                    "description": "Writes to the run key",
                    "strength": "7",
                    "mitre_technique_ids": "T1547, T1112",
                },
                {
                    "id": "SG-2",
                    "description": "Weak signal",
                    "strength": "not-a-number",
                },
            ],
        }
    },
}


def _log(value: Any) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(render_sarif(value))
    return parsed


def test_sarif_document_is_well_formed() -> None:
    log = _log(MALICIOUS_REPORT)
    assert log["$schema"] == SARIF_SCHEMA
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "filescan.io"


def test_sarif_records_the_artifact_with_an_iana_hash_name() -> None:
    artifact = _log(MALICIOUS_REPORT)["runs"][0]["artifacts"][0]
    assert artifact["location"]["uri"] == "evil.exe"
    assert artifact["hashes"] == {"sha-256": "a" * 64}
    assert artifact["length"] == 2048
    assert artifact["roles"] == ["analysisTarget"]


def test_sarif_turns_each_signal_group_into_a_result() -> None:
    run = _log(MALICIOUS_REPORT)["runs"][0]
    assert [r["ruleId"] for r in run["results"]] == ["SG-1", "SG-2"]
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"
    assert run["results"][0]["message"]["text"] == "Writes to the run key"


def test_sarif_locations_point_at_the_whole_file() -> None:
    location = _log(MALICIOUS_REPORT)["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"] == {
        "uri": "evil.exe",
        "index": 0,
    }
    assert "region" not in location["physicalLocation"]


def test_sarif_declares_a_rule_per_signal_with_mitre_tags() -> None:
    rules = _log(MALICIOUS_REPORT)["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["SG-1", "SG-2"]
    assert rules[0]["properties"]["tags"] == ["T1547", "T1112"]
    assert "tags" not in rules[1]["properties"]


def test_sarif_deduplicates_repeated_rules() -> None:
    group = {"id": "SG-1", "description": "d", "strength": "1"}
    report = {"reports": {"a": {"allSignalGroups": [group, group]}}}
    run = _log(report)["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        pytest.param("malicious", {"level": "error"}, id="malicious"),
        pytest.param("likely_malicious", {"level": "error"}, id="likely malicious"),
        pytest.param("suspicious", {"level": "warning"}, id="suspicious"),
        pytest.param("informational", {"level": "note"}, id="informational"),
        pytest.param("benign", {"kind": "pass"}, id="benign"),
        pytest.param("no_threat", {"kind": "pass"}, id="no threat"),
        pytest.param("unknown", {"kind": "notApplicable"}, id="unknown"),
        pytest.param("surprise", {"kind": "notApplicable"}, id="unrecognised"),
    ],
)
def test_sarif_maps_the_verdict_when_there_are_no_signals(
    verdict: str, expected: dict[str, str]
) -> None:
    report = {"reports": {"a": {"finalVerdict": {"verdict": verdict}}}}
    result = _log(report)["runs"][0]["results"][0]
    assert expected.items() <= result.items()
    if "kind" in expected:
        # SARIF 2.1.0 3.27.9: a kind other than "fail" carries no level.
        assert "level" not in result


def test_sarif_carries_the_threat_level_as_a_rank() -> None:
    report = {
        "reports": {"a": {"finalVerdict": {"verdict": "malicious", "threatLevel": 0.5}}}
    }
    assert _log(report)["runs"][0]["results"][0]["rank"] == 50.0


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        pytest.param(75, 100.0, id="above the fraction range"),
        pytest.param(-3, 0.0, id="below the fraction range"),
    ],
)
def test_sarif_keeps_the_rank_within_the_range_sarif_allows(
    level: float, expected: float
) -> None:
    report = {"reports": {"a": {"finalVerdict": {"threatLevel": level}}}}
    assert _log(report)["runs"][0]["results"][0]["rank"] == expected


@pytest.mark.parametrize(
    "level",
    [
        pytest.param(True, id="boolean"),
        pytest.param(math.nan, id="not a number"),
        pytest.param("0.5", id="string"),
    ],
)
def test_sarif_omits_a_rank_the_server_did_not_send_as_a_number(level: Any) -> None:
    report = {"reports": {"a": {"finalVerdict": {"threatLevel": level}}}}
    assert "rank" not in _log(report)["runs"][0]["results"][0]


def test_sarif_takes_the_artifact_length_only_from_a_real_integer() -> None:
    one = {"reports": {"a": {"file": {"name": "f"}}}}
    assert _log(one | {"fileSize": 42})["runs"][0]["artifacts"][0]["length"] == 42
    assert "length" not in _log(one | {"fileSize": True})["runs"][0]["artifacts"][0]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        pytest.param("evil.exe", "evil.exe", id="already a uri reference"),
        pytest.param("my report.exe", "my%20report.exe", id="spaces"),
        pytest.param("C:\\dir\\bad.exe", "C%3A%5Cdir%5Cbad.exe", id="windows path"),
        pytest.param("100%.exe", "100%25.exe", id="percent"),
        pytest.param("файл.exe", "%D1%84%D0%B0%D0%B9%D0%BB.exe", id="non-ascii"),
        pytest.param("bad\udcffname.exe", "bad%3Fname.exe", id="lone surrogate"),
    ],
)
def test_sarif_percent_encodes_the_artifact_uri(name: str, expected: str) -> None:
    """SARIF wants a uri-reference, which a sample name very often is not."""
    run = _log({"reports": {"a": {"file": {"name": name}}}})["runs"][0]
    assert run["artifacts"][0]["location"]["uri"] == expected
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == expected


def test_sarif_leaves_the_length_off_when_the_flow_unpacked_several_files() -> None:
    """One uploaded size cannot describe each of the files extracted from it."""
    unpacked = {
        "fileSize": 2048,
        "reports": {"a": {"file": {"name": "x"}}, "b": {"file": {"name": "y"}}},
    }
    assert all("length" not in a for a in _log(unpacked)["runs"][0]["artifacts"])


def test_sarif_omits_the_rank_when_the_report_has_no_threat_level() -> None:
    report = {"reports": {"a": {"finalVerdict": {"verdict": "malicious"}}}}
    assert "rank" not in _log(report)["runs"][0]["results"][0]


def test_sarif_defaults_to_unknown_without_a_final_verdict() -> None:
    report = {"reports": {"a": {"file": {"name": "x"}}}}
    assert _log(report)["runs"][0]["results"][0]["kind"] == "notApplicable"


def test_sarif_accepts_reports_as_a_list() -> None:
    report = {"reports": [{"finalVerdict": {"verdict": "benign"}}]}
    assert _log(report)["runs"][0]["results"][0]["kind"] == "pass"


def test_sarif_names_an_unnamed_artifact() -> None:
    report = {"reports": [{"finalVerdict": {"verdict": "benign"}}]}
    assert _log(report)["runs"][0]["artifacts"][0]["location"]["uri"] == "unknown"


def test_sarif_omits_the_rules_array_when_nothing_declared_one() -> None:
    report = {"reports": [{"finalVerdict": {"verdict": "benign"}}]}
    assert "rules" not in _log(report)["runs"][0]["tool"]["driver"]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(["not", "a", "report"], id="list"),
        pytest.param({"languages": ["es"]}, id="no reports key"),
        pytest.param({"reports": {}}, id="empty reports"),
        pytest.param({"reports": "text"}, id="reports is a string"),
    ],
)
def test_sarif_refuses_responses_that_are_not_scan_reports(value: Any) -> None:
    with pytest.raises(Unrepresentable):
        render_sarif(value)


# ------------------------------------------------------------ dispatch


def test_render_dispatches_to_each_format() -> None:
    assert render({"a": 1}, Format.JSON, compact=True) == '{"a": 1}'
    assert "| field | value |" in render({"a": 1}, Format.TABLE)
    assert render({"a": 1}, Format.TOON) == "a: 1"
    assert '"version": "2.1.0"' in render(MALICIOUS_REPORT, Format.SARIF)
    assert "Verdict" in render(MALICIOUS_REPORT, Format.REPORT)
