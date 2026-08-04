import json

from filescanio.client import FileScanClient


def test_prevalence_all_fields(client: FileScanClient) -> None:
    echo = client.threatintel.prevalence(
        domain=["evil.example"],
        ip=["1.2.3.4"],
        url=["https://evil.example/x"],
        uuid=["u1"],
        email=["a@b.c"],
        registry_path=["HKLM\\Software\\X"],
        revision_save_id=["r1"],
        sha1=["s1"],
        sha256=["s256"],
        sha512=["s512"],
        md5=["m5"],
        imphash=["i1"],
        ssdeep=["ss1"],
        authentihash=["au1"],
        fuzzyfsiohash=["fz1"],
        unc_path=["\\\\server\\share"],
        days=7,
        exclude_report_ids=["rep1", "rep2"],
    )
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/threatintel/get-prevalence"
    assert echo["query"] == {"exclude_report_ids": ["rep1", "rep2"]}
    assert echo["api_key"] == "k"
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == {
        "domain": ["evil.example"],
        "ip": ["1.2.3.4"],
        "url": ["https://evil.example/x"],
        "uuid": ["u1"],
        "email": ["a@b.c"],
        "registry_path": ["HKLM\\Software\\X"],
        "revision_save_id": ["r1"],
        "sha1": ["s1"],
        "sha256": ["s256"],
        "sha512": ["s512"],
        "md5": ["m5"],
        "imphash": ["i1"],
        "ssdeep": ["ss1"],
        "authentihash": ["au1"],
        "fuzzyfsiohash": ["fz1"],
        "unc_path": ["\\\\server\\share"],
        "days": 7,
    }


def test_prevalence_minimal(client: FileScanClient) -> None:
    echo = client.threatintel.prevalence(sha256=["s256"])
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/threatintel/get-prevalence"
    assert echo["query"] == {}
    assert json.loads(echo["body"]) == {"sha256": ["s256"]}


def test_similars_all_params(client: FileScanClient) -> None:
    echo = client.threatintel.similars(
        imphash="i1",
        ssdeep="ss1",
        fuzzyfsiohash="fz1",
        authentihash="au1",
        days=30,
        exclude_report_ids=["rep1", "rep2"],
    )
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/threatintel/get-similars"
    assert echo["query"] == {
        "imphash": ["i1"],
        "ssdeep": ["ss1"],
        "fuzzyfsiohash": ["fz1"],
        "authentihash": ["au1"],
        "days": ["30"],
        "exclude_report_ids": ["rep1", "rep2"],
    }
    assert echo["body"] == ""


def test_similars_minimal(client: FileScanClient) -> None:
    echo = client.threatintel.similars(imphash="i1")
    assert echo["method"] == "GET"
    assert echo["query"] == {"imphash": ["i1"]}
