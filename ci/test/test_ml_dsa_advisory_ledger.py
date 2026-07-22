# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
REFERENCE_DIR = REPO_ROOT / "contrib" / "ml-dsa-ref"
DRIVER = ENGINEERING_DIR / "run_advisory_ledger.py"
LEDGER = ENGINEERING_DIR / "advisory_ledger.json"
VECTORS = REFERENCE_DIR / "vectors.json"
COMPARATOR = REFERENCE_DIR / "compare_oracles.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-advisory-ledger.yml"
IMMUTABLE_REVIEW = REPO_ROOT / "docs" / "reviews" / "ML_DSA_44_AI_ASSISTED_TECHNICAL_REVIEW.md"
IMMUTABLE_REVIEW_RUN = REPO_ROOT / "docs" / "reviews" / "evidence" / "ml-dsa-44-review-run.json"


SPEC = importlib.util.spec_from_file_location("run_advisory_ledger", DRIVER)
assert SPEC is not None and SPEC.loader is not None
advisory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = advisory
SPEC.loader.exec_module(advisory)


EXPECTED_CURRENT_SCAN_IDS = {
    "RUSTSEC-2024-0436",
    "RUSTSEC-2026-0162",
    "RUSTSEC-2026-0163",
    "RUSTSEC-2026-0166",
    "RUSTSEC-2026-0173",
    "RUSTSEC-2026-0190",
    "RUSTSEC-2026-0204",
}

EXPECTED_SELECTED_LEDGER_IDS = {
    "RUSTSEC-2019-0035",
    "RUSTSEC-2021-0023",
    "RUSTSEC-2025-0133",
    "RUSTSEC-2026-0074",
    "RUSTSEC-2026-0076",
    "RUSTSEC-2026-0077",
    "RUSTSEC-2026-0097",
    "RUSTSEC-2026-0125",
    "RUSTSEC-2026-0126",
    "RUSTSEC-2026-0207",
    "RUSTSEC-2026-0208",
    "RUSTSEC-2026-0212",
}

OPENSSL_REVIEWED_36_IDS = {
    "CVE-2025-11187",
    "CVE-2025-15467",
    "CVE-2025-15468",
    "CVE-2025-15469",
    "CVE-2025-66199",
    "CVE-2025-68160",
    "CVE-2025-69418",
    "CVE-2025-69419",
    "CVE-2025-69420",
    "CVE-2025-69421",
    "CVE-2026-22795",
    "CVE-2026-22796",
    "CVE-2026-2673",
    "CVE-2026-28386",
    "CVE-2026-28387",
    "CVE-2026-28388",
    "CVE-2026-28389",
    "CVE-2026-28390",
    "CVE-2026-31789",
    "CVE-2026-31790",
    "CVE-2026-34180",
    "CVE-2026-34181",
    "CVE-2026-34182",
    "CVE-2026-34183",
    "CVE-2026-35188",
    "CVE-2026-42764",
    "CVE-2026-42765",
    "CVE-2026-42766",
    "CVE-2026-42767",
    "CVE-2026-42768",
    "CVE-2026-42769",
    "CVE-2026-42770",
    "CVE-2026-45445",
    "CVE-2026-45446",
    "CVE-2026-45447",
    "CVE-2026-7383",
    "CVE-2026-9076",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MlDsaAdvisoryLedgerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER.read_text(encoding="utf8"))
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf8"))

    def expected_findings(self) -> list[dict[str, object]]:
        return copy.deepcopy(self.ledger["scanners"]["expected_findings"])

    def cargo_audit_evidence(self) -> dict[str, object]:
        vulnerabilities = []
        warnings: dict[str, list[dict[str, object]]] = {}
        for finding in self.expected_findings():
            item = {
                "advisory": {"id": finding["id"]},
                "package": {
                    "name": finding["package"],
                    "version": finding["version"],
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
                "versions": {"patched": [], "unaffected": []},
            }
            if finding["cargo_audit_kind"] == "vulnerability":
                vulnerabilities.append(item)
            else:
                category = str(finding["cargo_audit_category"])
                warnings.setdefault(category, []).append(item)
        return {
            "database": {
                "advisory-count": 1166,
                "last-commit": "0123456789abcdef0123456789abcdef01234567",
            },
            "lockfile": {"dependency-count": 139},
            "vulnerabilities": {
                "found": bool(vulnerabilities),
                "count": len(vulnerabilities),
                "list": vulnerabilities,
            },
            "warnings": warnings,
        }

    def osv_evidence(self) -> dict[str, object]:
        findings_by_package: dict[tuple[str, str], list[dict[str, object]]] = {}
        for finding in self.expected_findings():
            key = (str(finding["package"]), str(finding["version"]))
            findings_by_package.setdefault(key, []).append(finding)
        packages = []
        for package in self.ledger["source_contract"]["full_lock"]["packages"]:
            key = (str(package["name"]), str(package["version"]))
            item: dict[str, object] = {
                "package": {
                    "name": key[0],
                    "version": key[1],
                    "ecosystem": "crates.io",
                }
            }
            findings = findings_by_package.get(key, [])
            if findings:
                item["vulnerabilities"] = [
                    {"id": finding["id"]} for finding in findings
                ]
                item["groups"] = [
                    {"ids": [finding["id"]], "aliases": []}
                    for finding in findings
                ]
            packages.append(item)
        self.assertEqual(len(packages), 139)
        return {
            "results": [
                {
                    "source": {"path": "Cargo.lock", "type": "lockfile"},
                    "packages": packages,
                }
            ],
            "experimental_config": {},
        }

    def sbom_component(self, name: str, version: str, ref: str) -> dict[str, str]:
        return {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}?ref={ref}",
        }

    def sbom_evidence(self) -> dict[str, object]:
        graph = self.ledger["source_contract"]["sbom_graph"]
        root_identity = (graph["root"]["name"], graph["root"]["version"])
        nested_identities = {
            (entry["name"], entry["version"])
            for entry in graph["nested_targets"]
        }
        identities = {
            (entry["name"], entry["version"])
            for entry in graph["components"]
        }
        component_ids = {f"{name}@{version}" for name, version in identities}
        refs = {component_id: f"urn:pqbtc:{component_id}" for component_id in component_ids}
        root_id = f"{root_identity[0]}@{root_identity[1]}"
        root = self.sbom_component(*root_identity, refs[root_id])
        root["components"] = [
            self.sbom_component(
                name,
                version,
                refs[f"{name}@{version}"],
            )
            for name, version in sorted(nested_identities)
        ]
        top = [
            self.sbom_component(
                name,
                version,
                refs[f"{name}@{version}"],
            )
            for name, version in sorted(identities - {root_identity} - nested_identities)
        ]
        dependencies = [
            {
                "ref": refs[row["component"]],
                **(
                    {"dependsOn": [refs[item] for item in row["depends_on"]]}
                    if row["depends_on"]
                    else {}
                ),
            }
            for row in graph["dependency_nodes"]
        ]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000189",
            "version": 1,
            "metadata": {
                "component": root,
                "properties": [
                    {
                        "name": "cdx:rustc:sbom:target:triple",
                        "value": graph["target_triple"],
                    }
                ],
            },
            "components": top,
            "dependencies": dependencies,
        }

    def miri_evidence(self) -> dict[str, object]:
        contract = self.ledger["execution_contract"]
        return {
            "schema_version": 1,
            "status": "PASS",
            "role": "SUPPLEMENTARY",
            "toolchain": self.ledger["tools"]["miri"]["toolchain"],
            "rustc": self.ledger["tools"]["miri"]["rustc"],
            "compiled_backend": contract["compiled_backend"],
            "called_backend": contract["called_backend"],
            "architecture": contract["architecture"],
            "target_triple": contract["target_triple"],
            "tests": [
                {"name": name, "status": "PASS"}
                for name in self.ledger["miri"]["checks"]
            ],
        }

    def oracle_source(self, name: str) -> dict[str, object]:
        return next(
            source
            for source in self.ledger["source_contract"]["oracles"]
            if source["name"] == name
        )

    def openssl_feed_summary(self) -> dict[str, object]:
        source = self.oracle_source("openssl")
        feed = source["advisory_feed"]
        return {
            "status": "PASS",
            "repository": feed["repository"],
            "commit": "eafb178d9fdde541157e1a2eafc5c3db7db05a5a",
            "tree": "9d2bf1bf2b5becc1dd49ab3602ad4c1fe605981d",
            "secjson_tree": "68602ed5f20c17189a8a76b534ff497eba0eac94",
            "committed_at": "2026-07-20T16:08:14+00:00",
            "record_count": 272,
            "minimum_record_count": 272,
            "data_versions": {"5.0": 224, "5.1": 48},
            "branch": "3.6",
            "branch_relevant_ids": sorted(OPENSSL_REVIEWED_36_IDS),
            "exact_pin": source["version"],
            "exact_pin_affected_ids": [],
            "secjson_manifest_sha256": "0" * 64,
            "relevant_records": [],
        }

    def mldsa_feed_summary(self) -> dict[str, object]:
        feed = self.oracle_source("mldsa_native")["advisory_feed"]
        return {
            "status": "PASS",
            "request_url": feed["url"],
            "curl_exit_code": 0,
            "http_status": 200,
            "content_type": "application/json; charset=utf-8",
            "api_version": feed["api_version"],
            "published_advisory_ids": [],
            "body_sha256": hashlib.sha256(b"[]").hexdigest(),
            "headers_sha256": "1" * 64,
            "fetch_sha256": "2" * 64,
            "request_sha256": "3" * 64,
        }

    def openssl_cve(
        self,
        cve_id: str,
        *,
        lower: str = "3.6.0",
        upper: str = "3.6.3",
        inclusive: bool = False,
        data_version: str = "5.1",
    ) -> dict[str, object]:
        version = {
            "version": lower,
            "status": "affected",
            "versionType": "semver",
            ("lessThanOrEqual" if inclusive else "lessThan"): upper,
        }
        return {
            "dataType": "CVE_RECORD",
            "dataVersion": data_version,
            "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "OpenSSL",
                            "product": "OpenSSL",
                            "defaultStatus": "unaffected",
                            "versions": [version],
                        }
                    ]
                }
            },
        }

    def write_openssl_feed(
        self,
        root: Path,
        *,
        upper: str = "3.6.3",
        inclusive: bool = False,
    ) -> Path:
        repository = root / "release-metadata"
        secjson = repository / "secjson"
        secjson.mkdir(parents=True)
        for index, cve_id in enumerate(sorted(OPENSSL_REVIEWED_36_IDS)):
            record = self.openssl_cve(
                cve_id,
                upper=upper if index == 0 else "3.6.3",
                inclusive=inclusive if index == 0 else False,
                data_version="5.0" if index == 0 else "5.1",
            )
            (secjson / f"{cve_id}.json").write_text(
                json.dumps(record, sort_keys=True) + "\n", encoding="utf8"
            )
        irregular_id = "CVE-2023-2650"
        irregular = self.openssl_cve(
            irregular_id, lower="3.1.1", upper="3.1.1", data_version="5.0"
        )
        (secjson / f"{irregular_id}.json").write_text(
            json.dumps(irregular, sort_keys=True) + "\n", encoding="utf8"
        )
        filler_count = 272 - len(OPENSSL_REVIEWED_36_IDS) - 1
        for index in range(filler_count):
            cve_id = f"CVE-2099-{10000 + index}"
            record = self.openssl_cve(
                cve_id, lower="1.0.0", upper="1.0.1", data_version="5.0"
            )
            (secjson / f"{cve_id}.json").write_text(
                json.dumps(record, sort_keys=True) + "\n", encoding="utf8"
            )
        (secjson / "statements.json").write_text(
            '{"disputed": [], "statements": []}\n', encoding="utf8"
        )
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "remote",
                "add",
                "origin",
                "https://github.com/openssl/release-metadata.git",
            ],
            check=True,
        )
        self.commit_fixture(repository, "baseline")
        return repository

    def commit_fixture(self, repository: Path, message: str) -> None:
        subprocess.run(["git", "-C", str(repository), "add", "--all"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "-c",
                "user.name=PQBTC Tests",
                "-c",
                "user.email=pqbtc-tests@example.invalid",
                "commit",
                "-q",
                "-m",
                message,
            ],
            check=True,
        )

    def mldsa_feed_inputs(self):
        feed = self.oracle_source("mldsa_native")["advisory_feed"]
        body = []
        body_bytes = b"[]"
        headers = "\r\n".join(
            (
                "HTTP/2 200",
                "content-type: application/json; charset=utf-8",
                f"x-github-api-version-selected: {feed['api_version']}",
                "x-ratelimit-resource: core",
                "x-ratelimit-limit: 60",
                "x-ratelimit-remaining: 59",
                "x-ratelimit-used: 1",
                "x-ratelimit-reset: 2147483647",
                "",
                "",
            )
        )
        fetch = {
            "exitcode": 0,
            "http_code": 200,
            "url_effective": feed["url"],
            "content_type": "application/json; charset=utf-8",
            "size_download": len(body_bytes),
            "num_redirects": 0,
        }
        request = {
            "url": feed["url"],
            "accept": feed["accept"],
            "api_version": feed["api_version"],
            "user_agent": feed["user_agent"],
            "authenticated": False,
        }
        return body, body_bytes, headers, fetch, request

    def validate_exact_evidence(self, **overrides):
        contract = self.ledger["execution_contract"]
        arguments = {
            "ledger": self.ledger,
            "cargo_audit": self.cargo_audit_evidence(),
            "osv": self.osv_evidence(),
            "sbom": self.sbom_evidence(),
            "miri": self.miri_evidence(),
            "openssl_feed": self.openssl_feed_summary(),
            "mldsa_native_feed": self.mldsa_feed_summary(),
            "compiled_backend": contract["compiled_backend"],
            "called_backend": contract["called_backend"],
            "architecture": contract["architecture"],
            "cargo_audit_exit_code": 1,
            "osv_exit_code": 1,
        }
        arguments.update(overrides)
        return advisory.validate_evidence(**arguments)

    def test_checked_in_ledger_validates_and_is_complete_for_current_scope(self):
        self.assertIsNone(advisory.validate_ledger(self.ledger, self.vectors))
        self.assertEqual(self.ledger["schema_version"], 1)
        self.assertEqual(self.ledger["inventory_date"], "2026-07-21")
        self.assertEqual(
            {finding["id"] for finding in self.expected_findings()},
            EXPECTED_CURRENT_SCAN_IDS,
        )
        self.assertTrue(
            EXPECTED_SELECTED_LEDGER_IDS.issubset(
                {entry["id"] for entry in self.ledger["advisories"]}
            )
        )

        contract = self.ledger["execution_contract"]
        self.assertEqual(contract["compiled_backend"], "portable")
        self.assertEqual(contract["called_backend"], "portable")
        self.assertEqual(contract["architecture"], "x86_64")
        self.assertEqual(contract["target_triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(contract["production_backend"], "NONE")
        self.assertFalse(contract["simd256_admitted"])
        self.assertEqual(contract["miri_role"], "SUPPLEMENTARY")
        libcrux = next(
            source
            for source in self.ledger["source_contract"]["oracles"]
            if source["name"] == "libcrux"
        )
        self.assertEqual(
            libcrux["cargo_toml_sha256"],
            "5796c72c70ced10baba72fdb0fa2345163a2ab628b2c04d89ef883ede90f44c1",
        )

    def test_plan_only_cli_is_machine_readable_and_freezes_scope(self):
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--plan-only"],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["execution_contract"], self.ledger["execution_contract"])
        self.assertEqual(set(plan["expected_scanner_ids"]), EXPECTED_CURRENT_SCAN_IDS)
        self.assertEqual(plan["miri"]["role"], "SUPPLEMENTARY")
        self.assertTrue(plan["miri"]["required"])

    def test_json_loader_rejects_duplicate_malformed_and_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            for payload in (
                '{"id": 1, "id": 2}',
                '{"id": }',
                '{"value": NaN}',
                '["not", "an", "object"]',
            ):
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf8")
                    with self.assertRaises(advisory.AuditError):
                        advisory.load_json_object(path, "test evidence")

    def test_exact_classified_scans_pass_despite_scanner_exit_one(self):
        report = self.validate_exact_evidence()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(
            report["scanner_exit_codes"], {"cargo_audit": 1, "osv": 1}
        )
        self.assertEqual(report["miri"]["role"], "SUPPLEMENTARY")
        self.assertEqual(report["miri"]["status"], "PASS")
        self.assertEqual(
            report["oracle_advisory_feed_validation"]["openssl"]
            ["exact_pin_affected_ids"],
            [],
        )
        self.assertEqual(
            report["oracle_advisory_feed_validation"]["mldsa_native"]
            ["published_advisory_ids"],
            [],
        )

    def test_openssl_live_feed_semver_boundaries_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            summary = advisory.validate_openssl_advisory_feed(
                self.ledger, repository
            )
            self.assertEqual(summary["record_count"], 272)
            self.assertEqual(summary["exact_pin_affected_ids"], [])
            self.assertEqual(
                set(summary["branch_relevant_ids"]), OPENSSL_REVIEWED_36_IDS
            )

        for upper, inclusive in (("3.6.4", False), ("3.6.3", True)):
            with self.subTest(upper=upper, inclusive=inclusive):
                with tempfile.TemporaryDirectory() as temporary:
                    repository = self.write_openssl_feed(
                        Path(temporary), upper=upper, inclusive=inclusive
                    )
                    with self.assertRaisesRegex(advisory.AuditError, "3.6.3"):
                        advisory.validate_openssl_advisory_feed(
                            self.ledger, repository
                        )

    def test_openssl_live_feed_rejects_truncation_and_malformed_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            removed = sorted(OPENSSL_REVIEWED_36_IDS)[0]
            (repository / "secjson" / f"{removed}.json").unlink()
            self.commit_fixture(repository, "remove reviewed CVE")
            with self.assertRaisesRegex(advisory.AuditError, "missing"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            cve_id = sorted(OPENSSL_REVIEWED_36_IDS)[0]
            path = repository / "secjson" / f"{cve_id}.json"
            path.write_text(
                '{"dataType":"CVE_RECORD","dataType":"CVE_RECORD"}\n',
                encoding="utf8",
            )
            self.commit_fixture(repository, "duplicate JSON key")
            with self.assertRaisesRegex(advisory.AuditError, "duplicate JSON key"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            cve_id = sorted(OPENSSL_REVIEWED_36_IDS)[0]
            path = repository / "secjson" / f"{cve_id}.json"
            record = json.loads(path.read_text(encoding="utf8"))
            record["cveMetadata"]["cveId"] = "CVE-2099-99999"
            path.write_text(json.dumps(record) + "\n", encoding="utf8")
            self.commit_fixture(repository, "mismatched identity")
            with self.assertRaisesRegex(advisory.AuditError, "filename"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            path = repository / "secjson" / "CVE-2099-10000.json"
            record = json.loads(path.read_text(encoding="utf8"))
            version = record["containers"]["cna"]["affected"][0]["versions"][0]
            version.update(
                {
                    "version": "1.1.1 through 3.6.4",
                    "lessThan": "1.1.1z",
                    "versionType": "custom",
                }
            )
            path.write_text(json.dumps(record) + "\n", encoding="utf8")
            self.commit_fixture(repository, "ambiguous custom range")
            with self.assertRaisesRegex(advisory.AuditError, "custom range"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

    def test_openssl_live_feed_records_only_provably_non_target_empty_ranges(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            summary = advisory.validate_openssl_advisory_feed(
                self.ledger, repository
            )
            self.assertEqual(
                summary["non_target_irregular_ranges"][0]["id"],
                "CVE-2023-2650",
            )

        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary))
            path = repository / "secjson" / "CVE-2099-10000.json"
            record = json.loads(path.read_text(encoding="utf8"))
            version = record["containers"]["cna"]["affected"][0]["versions"][0]
            version["version"] = "3.1.2"
            version["lessThan"] = "3.1.2"
            path.write_text(json.dumps(record) + "\n", encoding="utf8")
            self.commit_fixture(repository, "unreviewed non-target empty range")
            with self.assertRaisesRegex(advisory.AuditError, "unreviewed empty"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

        with tempfile.TemporaryDirectory() as temporary:
            repository = self.write_openssl_feed(Path(temporary), upper="3.6.0")
            with self.assertRaisesRegex(advisory.AuditError, "inside OpenSSL 3.6"):
                advisory.validate_openssl_advisory_feed(self.ledger, repository)

    def test_mldsa_native_live_feed_rejects_advisories_http_and_pagination(self):
        _body, body_bytes, headers, fetch, request = self.mldsa_feed_inputs()
        summary = advisory.validate_mldsa_native_advisory_feed(
            self.ledger, body_bytes, headers, fetch, request, 0
        )
        self.assertEqual(summary["published_advisory_ids"], [])

        advisory_body = b'[{"ghsa_id":"GHSA-2345-6789-cfgh"}]'
        advisory_fetch = copy.deepcopy(fetch)
        advisory_fetch["size_download"] = len(advisory_body)
        with self.assertRaisesRegex(advisory.AuditError, "GHSA"):
            advisory.validate_mldsa_native_advisory_feed(
                self.ledger,
                advisory_body,
                headers,
                advisory_fetch,
                request,
                0,
            )

        failed_fetch = copy.deepcopy(fetch)
        failed_fetch["exitcode"] = 22
        failed_fetch["http_code"] = 429
        failed_headers = headers.replace("HTTP/2 200", "HTTP/2 429")
        with self.assertRaises(advisory.AuditError):
            advisory.validate_mldsa_native_advisory_feed(
                self.ledger,
                body_bytes,
                failed_headers,
                failed_fetch,
                request,
                22,
            )

        paginated_headers = headers.replace(
            "content-type:",
            'link: <https://api.github.com/example?page=2>; rel="next"\r\n'
            "content-type:",
        )
        with self.assertRaisesRegex(advisory.AuditError, "pagination"):
            advisory.validate_mldsa_native_advisory_feed(
                self.ledger,
                body_bytes,
                paginated_headers,
                fetch,
                request,
                0,
            )

        bad_content_fetch = copy.deepcopy(fetch)
        bad_content_fetch["content_type"] = "application/jsonp"
        bad_content_headers = headers.replace(
            "application/json; charset=utf-8", "application/jsonp"
        )
        with self.assertRaisesRegex(advisory.AuditError, "JSON"):
            advisory.validate_mldsa_native_advisory_feed(
                self.ledger,
                body_bytes,
                bad_content_headers,
                bad_content_fetch,
                request,
                0,
            )

        fractional_size_fetch = copy.deepcopy(fetch)
        fractional_size_fetch["size_download"] = 2.9
        with self.assertRaisesRegex(advisory.AuditError, "body size"):
            advisory.validate_mldsa_native_advisory_feed(
                self.ledger,
                body_bytes,
                headers,
                fractional_size_fetch,
                request,
                0,
            )

    def test_live_oracle_feed_cli_validates_raw_inputs_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.write_openssl_feed(root)
            _body, body_bytes, headers, fetch, request = self.mldsa_feed_inputs()
            body_path = root / "mldsa-native-advisories.json"
            headers_path = root / "mldsa-native-response-headers.txt"
            fetch_path = root / "mldsa-native-fetch.json"
            request_path = root / "mldsa-native-request.json"
            body_path.write_bytes(body_bytes)
            headers_path.write_text(headers, encoding="utf8")
            fetch_path.write_text(json.dumps(fetch) + "\n", encoding="utf8")
            request_path.write_text(json.dumps(request) + "\n", encoding="utf8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(DRIVER),
                    "--validate-oracle-feeds",
                    "--openssl-advisory-feed",
                    str(repository),
                    "--mldsa-native-advisories",
                    str(body_path),
                    "--mldsa-native-response-headers",
                    str(headers_path),
                    "--mldsa-native-fetch",
                    str(fetch_path),
                    "--mldsa-native-request",
                    str(request_path),
                    "--mldsa-native-curl-exit-code",
                    "0",
                ],
                cwd=REPO_ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            report = json.loads(completed.stdout)
            self.assertEqual(report["openssl"]["exact_pin_affected_ids"], [])
            self.assertEqual(
                report["mldsa_native"]["published_advisory_ids"], []
            )

    def test_new_rustsec_database_advisory_fails_closed(self):
        cargo = self.cargo_audit_evidence()
        cargo["vulnerabilities"]["list"].append(
            {
                "advisory": {"id": "RUSTSEC-2099-9999"},
                "package": {
                    "name": "libcrux-ml-dsa",
                    "version": "0.0.10",
                },
                "versions": {"patched": [], "unaffected": []},
            }
        )
        cargo["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(advisory.AuditError, "RUSTSEC-2099-9999"):
            self.validate_exact_evidence(cargo_audit=cargo)

    def test_missing_or_extra_cargo_audit_and_osv_ids_are_rejected(self):
        cargo_missing = self.cargo_audit_evidence()
        if cargo_missing["vulnerabilities"]["list"]:
            cargo_missing["vulnerabilities"]["list"].pop()
            cargo_missing["vulnerabilities"]["count"] -= 1
        else:
            first_category = next(iter(cargo_missing["warnings"]))
            cargo_missing["warnings"][first_category].pop()

        cargo_extra = self.cargo_audit_evidence()
        cargo_extra["warnings"].setdefault("notice", []).append(
            {
                "advisory": {"id": "RUSTSEC-2099-0001"},
                "package": {"name": "unexpected", "version": "1.0.0"},
                "versions": {"patched": [], "unaffected": []},
            }
        )

        osv_missing = self.osv_evidence()
        osv_missing["results"][0]["packages"].pop()

        osv_extra = self.osv_evidence()
        osv_extra["results"][0]["packages"].append(
            {
                "package": {
                    "name": "unexpected",
                    "version": "1.0.0",
                    "ecosystem": "crates.io",
                },
                "vulnerabilities": [{"id": "RUSTSEC-2099-0002"}],
                "groups": [{"ids": ["RUSTSEC-2099-0002"], "aliases": []}],
            }
        )

        for label, override in (
            ("cargo missing", {"cargo_audit": cargo_missing}),
            ("cargo extra", {"cargo_audit": cargo_extra}),
            ("osv missing", {"osv": osv_missing}),
            ("osv extra", {"osv": osv_extra}),
        ):
            with self.subTest(label=label):
                with self.assertRaises(advisory.AuditError):
                    self.validate_exact_evidence(**override)

    def test_osv_rejects_unresolved_vulnerabilities_and_truncated_inventory(self):
        for identifier in ("CVE-2099-0001", "OSV-2099-0001"):
            with self.subTest(identifier=identifier):
                osv = self.osv_evidence()
                osv["results"][0]["packages"][0]["vulnerabilities"] = [
                    {"id": identifier}
                ]
                osv["results"][0]["packages"][0]["groups"] = [
                    {"ids": [identifier], "aliases": []}
                ]
                with self.assertRaisesRegex(
                    advisory.AuditError, "exactly one reviewed advisory"
                ):
                    self.validate_exact_evidence(osv=osv)

        hidden = self.osv_evidence()
        vulnerable = next(
            item
            for item in hidden["results"][0]["packages"]
            if item.get("vulnerabilities")
        )
        vulnerable["vulnerabilities"].append({"id": "CVE-2099-0002"})
        vulnerable["groups"].append(
            {"ids": ["CVE-2099-0002"], "aliases": []}
        )
        with self.assertRaises(advisory.AuditError):
            self.validate_exact_evidence(osv=hidden)

        truncated = self.osv_evidence()
        truncated["results"][0]["packages"] = [
            item
            for item in truncated["results"][0]["packages"]
            if item.get("vulnerabilities")
        ]
        self.assertEqual(len(truncated["results"][0]["packages"]), 7)
        with self.assertRaisesRegex(advisory.AuditError, "package inventory drifted"):
            self.validate_exact_evidence(osv=truncated)

    def test_scanner_package_or_version_drift_is_rejected(self):
        cargo = self.cargo_audit_evidence()
        cargo_item = cargo["vulnerabilities"]["list"][0]
        cargo_item["package"]["version"] = "999.0.0"

        osv = self.osv_evidence()
        osv["results"][0]["packages"][0]["package"]["name"] = "wrong-package"

        for label, override in (
            ("cargo version", {"cargo_audit": cargo}),
            ("osv package", {"osv": osv}),
        ):
            with self.subTest(label=label):
                with self.assertRaises(advisory.AuditError):
                    self.validate_exact_evidence(**override)

    def test_compiled_called_backend_and_architecture_drift_are_rejected(self):
        for label, override in (
            ("compiled", {"compiled_backend": "simd256"}),
            ("called", {"called_backend": "simd256"}),
            ("architecture", {"architecture": "aarch64"}),
        ):
            with self.subTest(label=label):
                with self.assertRaises(advisory.AuditError):
                    self.validate_exact_evidence(**override)

    def test_simd256_cannot_be_admitted_by_ledger_mutation(self):
        for field, value in (
            ("compiled_backend", "simd256"),
            ("called_backend", "simd256"),
            ("simd256_admitted", True),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.ledger)
                mutated["execution_contract"][field] = value
                with self.assertRaises(advisory.AuditError):
                    advisory.validate_ledger(mutated, self.vectors)

    def test_advisory_test_dispositions_cannot_be_promoted_or_detached(self):
        for finding_id in (
            "RUSTSEC-2026-0077",
            "RUSTSEC-2026-0125",
            "RUSTSEC-2026-0126",
        ):
            with self.subTest(finding_id=finding_id):
                mutated = copy.deepcopy(self.ledger)
                entry = next(
                    item for item in mutated["advisories"] if item["id"] == finding_id
                )
                entry["test_status"] = "PASS"
                entry["evidence"] = ["unbound claim"]
                with self.assertRaisesRegex(advisory.AuditError, "disposition drifted"):
                    advisory.validate_ledger(mutated, self.vectors)

        detached = copy.deepcopy(self.ledger)
        entry = next(
            item
            for item in detached["advisories"]
            if item["id"] == "RUSTSEC-2026-0076"
        )
        entry["evidence"] = ["nonempty but inexact"]
        with self.assertRaisesRegex(advisory.AuditError, "not bound to exact evidence"):
            advisory.validate_ledger(detached, self.vectors)

    def test_full_lock_and_sbom_graph_fail_closed(self):
        mutated = copy.deepcopy(self.ledger)
        mutated["source_contract"]["full_lock"]["packages"][0] = copy.deepcopy(
            mutated["source_contract"]["full_lock"]["packages"][1]
        )
        with self.assertRaisesRegex(advisory.AuditError, "full lock"):
            advisory.validate_ledger(mutated, self.vectors)

        cases = []
        graphless = self.sbom_evidence()
        graphless.pop("dependencies")
        cases.append(("graphless", graphless))
        wrong_root = self.sbom_evidence()
        wrong_root["metadata"]["component"]["name"] = "wrong-root"
        cases.append(("wrong root", wrong_root))
        dangling = self.sbom_evidence()
        dangling["dependencies"][0]["dependsOn"] = ["urn:pqbtc:missing@1.0.0"]
        cases.append(("dangling", dangling))
        wrong_target = self.sbom_evidence()
        wrong_target["metadata"]["properties"][0]["value"] = "aarch64-apple-darwin"
        cases.append(("wrong target", wrong_target))
        for label, sbom in cases:
            with self.subTest(label=label):
                with self.assertRaises(advisory.AuditError):
                    self.validate_exact_evidence(sbom=sbom)

    def test_scan_sbom_and_supplementary_miri_evidence_are_all_required(self):
        for field in (
            "cargo_audit",
            "osv",
            "sbom",
            "miri",
            "openssl_feed",
            "mldsa_native_feed",
        ):
            with self.subTest(field=field):
                with self.assertRaises(advisory.AuditError):
                    self.validate_exact_evidence(**{field: None})

    def test_workflow_is_pinned_read_only_scheduled_and_retains_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        for required in (
            "pull_request:",
            "push:",
            "- main",
            "schedule:",
            "cron:",
            "workflow_dispatch:",
            "contents: read",
            "persist-credentials: false",
            "timeout-minutes: 180",
            "run_advisory_ledger.py",
            "openssl/release-metadata.git",
            "mldsa-native/security-advisories?state=published&per_page=100&page=1",
            "--validate-oracle-feeds",
            "--openssl-advisory-feed",
            "--mldsa-native-advisories",
            "--mldsa-native-curl-exit-code",
            "mldsa-native-response-headers.txt",
            "openssl-release-metadata-secjson.tar.gz",
            "--fail-with-body",
            "--proto '=https'",
            "X-GitHub-Api-Version:",
            "ci.test.test_ml_dsa_backend_admission",
            "ci.test.test_ml_dsa_sustained_fuzz",
            "cargo-audit",
            "osv-scanner",
            "cargo-cyclonedx",
            "miri run",
            "ML_DSA_COMPILED_BACKEND: portable",
            "ML_DSA_CALLED_BACKEND: portable",
            "ML_DSA_ARCHITECTURE: x86_64",
            "ML_DSA_TARGET_TRIPLE: x86_64-unknown-linux-gnu",
            'test "$(uname -m)" = "$ML_DSA_ARCHITECTURE"',
            "rustc 1.99.0-nightly (9f36de775 2026-07-19)",
            "miri-prepared-Cargo.toml",
            "job_status=",
            "if: always()",
            "if-no-files-found: error",
            "retention-days: 90",
            "SHA256SUMS",
            "github.run_id",
            "github.run_attempt",
        ):
            self.assertIn(required, workflow)

        action_refs = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(action_refs), 2)
        for ref in action_refs:
            self.assertRegex(ref, r"^[0-9a-f]{40}$")
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("security-events: write", workflow)
        self.assertNotIn("gh pr", workflow)
        self.assertNotIn("Authorization:", workflow)
        self.assertNotIn("docs/reviews/evidence", workflow)

    def test_comparator_no_longer_claims_package_wide_advisory_pass(self):
        comparator = COMPARATOR.read_text(encoding="utf8")
        self.assertNotIn("libcrux_disclosed_advisory_regressions", comparator)
        self.assertNotIn(
            '"libcrux_disclosed_advisory_regressions": "PASS"', comparator
        )
        self.assertIn("libcrux_executed_security_regressions", comparator)

    def test_prior_review_artifacts_remain_immutable_historical_evidence(self):
        self.assertEqual(
            sha256_file(IMMUTABLE_REVIEW),
            "f593e479e5aaf93fbdddd7678403c919ca27cb4f47188118efef7362d306e171",
        )
        self.assertEqual(
            sha256_file(IMMUTABLE_REVIEW_RUN),
            "661bb132d97c6fee227ca49362aa3485cd1ff210898daa7864c96fb411df9b6d",
        )


if __name__ == "__main__":
    unittest.main()
