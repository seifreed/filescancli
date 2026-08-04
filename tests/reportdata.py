"""Scan-report fixtures for the readable renderer tests.

Plain literals only: this module is coverage-measured, so it must not
contain a single conditional.
"""

from typing import Any

FULL_REPORT: dict[str, Any] = {
    "fileSize": 4096,
    "reports": {
        "r1": {
            "id": "report-1",
            "flowId": "flow-1",
            "created_date": "2026-08-01T12:00:00Z",
            "file": {"name": "dropper.exe", "hash": "a" * 64},
            "finalVerdict": {
                "verdict": "MALICIOUS",
                "threatLevel": 1,
                "confidence": 0.95,
            },
            "allTags": [
                {"source": "MEDIA_TYPE", "isRootTag": True, "tag": {"name": "peexe"}},
                {"source": "SIGNAL", "tag": {"name": "trojan"}},
                {"source": "SIGNAL", "tag": {}},
            ],
            "allSignalGroups": [
                {
                    "description": "Writes to another process",
                    "verdict": {"verdict": "MALICIOUS", "threatLevel": 0.9},
                    "allTags": [{"tag": {"name": "injection"}}],
                    "allMitreTechniques": [
                        {
                            "name": "Process Injection",
                            "relatedTactic": {"name": "Defense Evasion"},
                        },
                        {"name": "Obfuscated Files or Information"},
                        {},
                    ],
                    "signals": [
                        {
                            "signalReadable": "Opens a \n   remote process",
                            "originType": "static_analysis",
                        },
                        {},
                    ],
                },
                {
                    "description": "Contains long flat data streams",
                    "verdict": {"verdict": "INFORMATIONAL"},
                },
            ],
            "resources": {
                "res-file": {
                    "resourceReference": {"name": "file"},
                    "mediaType": {"string": "application/x-msdownload"},
                    "fileSize": 4096,
                    "digests": {"SHA-256": "a" * 64, "MD5": "b" * 32},
                    "extendedData": {
                        "fileMagicDescription": "PE32 executable (GUI) Intel 80386",
                        "imphash": "c" * 32,
                        "ssdeep": "3:abc:xyz",
                        "architecture": "x86",
                        "subsystemReadable": "Windows GUI",
                        "language": "C++",
                        "isDigitallySigned": False,
                        "isDotNet": False,
                        "isPacked": True,
                        "packers": ["UPX"],
                        "dates": {"dateUtc": "2020-01-01T00:00:00Z"},
                    },
                    "emulationMetaData": {
                        "Overview": {
                            "FunctionCount": {"CreateFileW": 2, "WriteFile": 5},
                            "Duration": "3ms",
                        }
                    },
                    "emulationData": [
                        {
                            "action": "CallAPI",
                            "interesting": True,
                            "additionalInformation": {
                                "Library": "kernel32",
                                "Alias": "CreateFileW",
                                "Arguments": ["path=C:\\evil.tmp"],
                            },
                        },
                        {
                            "action": "WriteMemory",
                            "additionalInformation": {"Address": "0x5000"},
                        },
                    ],
                    "extractedUrls": [
                        {
                            "origin": {"type": "static_analysis"},
                            "references": [
                                {"data": "http://evil.example/c2", "interesting": True}
                            ],
                        }
                    ],
                    "extractedDomains": [
                        {
                            "origin": {"type": "static_analysis"},
                            "references": [{"data": "evil.example"}],
                        }
                    ],
                    "disassemblySections": [
                        {
                            "fileRva": "0x1000",
                            "humanDescriptor": "entry point",
                            "instructions": ["push ebp", "mov ebp, esp"],
                        }
                    ],
                    "yaraMatches": [
                        {
                            "ruleName": "win_upx_packed",
                            "verdict": {"verdict": "SUSPICIOUS"},
                            "matchedStrings": ["UPX0", "UPX1"],
                            "metaData": {"author": "analyst"},
                        }
                    ],
                    "strings": [
                        {
                            "origin": {"type": "static_analysis"},
                            "references": [
                                {"str": "cmd.exe /c  \n  whoami", "interesting": True},
                                {"str": "hello", "interesting": False},
                            ],
                        },
                        {"origin": {"type": "osint"}, "references": []},
                    ],
                    "extractedFiles": [
                        {
                            "submitName": "payload.bin",
                            "fileSize": 1024,
                            "mediaType": {"string": "application/octet-stream"},
                            "digests": {
                                "MD5": "d" * 32,
                                "SHA-1": "e" * 40,
                                "SHA-256": "f" * 64,
                                "SHA-512": "0" * 128,
                            },
                            "extendedData": {"fileMagicDescription": "data"},
                            "metaData": {"entropy": 7.9},
                            "allTags": [{"tag": {"name": "dropped"}}],
                        }
                    ],
                },
                "res-osint": {
                    "resourceReference": {"name": "osint"},
                    "results": [
                        {
                            "resource": "http://evil.example/c2",
                            "type": "url",
                            "origin": {"type": "static_analysis"},
                            "osintProvider": "virustotal",
                            "verdict": "malicious",
                            "tags": [{"tag": {"name": "c2"}}],
                            "data": {"positives": 42, "total": 70, "response_code": 1},
                        }
                    ],
                },
                "res-geo": {
                    "resourceReference": {"name": "domain-resolve"},
                    "domainResolveResults": [
                        {
                            "inetAddr": "198.51.100.7",
                            "resource": {"data": "evil.example"},
                            "geoData": {
                                "country_name": "Netherlands",
                                "city": "Amsterdam",
                                "country_code": "NL",
                                "latitude": 52.37,
                                "longitude": 4.9,
                                "connection": {"asn": 64500, "isp": "Example ISP"},
                            },
                        }
                    ],
                },
            },
        }
    },
}

BARE_REPORT: dict[str, Any] = {"reports": {"x": {"resources": {}}}}
