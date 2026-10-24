"""Exercise scanner variations through normalization and report aggregation."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.container_findings import finding, scout_findings, trivy_findings
from salty_actions.container_packages import inventory
from salty_actions.container_report import aggregate
from salty_actions.container_scan import sarif_report, scan

from .test_container_security import (
    EXPECTED,
    IMAGE_ID,
    REPOSITORY,
    TARGET,
    scan_report,
    scout_report,
    trivy_report,
)


def application_trivy(purl="pkg:golang/github.com/go-chi/chi/v5@5.3.2"):
    payload = trivy_report()
    payload["Results"][0].update(Class="lang-pkgs", Type="gobinary")
    vuln = payload["Results"][0]["Vulnerabilities"][0]
    vuln["PkgIdentifier"]["PURL"] = purl
    vuln["InstalledVersion"] = "5.3.2"
    return payload


def application_scout(purl="pkg:golang/github.com/go-chi/chi/v5@5.3.2"):
    payload = scout_report()
    payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["purls"] = [purl]
    return payload


class PackageIdentityTests(unittest.TestCase):
    def test_real_scout_application_report_aggregates_without_distro(self):
        path = (
            Path(__file__).parent
            / "fixtures/container-security/scout-v1.26.0-application.sarif"
        )
        findings = scout_findings(json.loads(path.read_text()), all_severities=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "CVE-2026-114437")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["distro"], "application")
        report = scan_report()
        report["findings"] = findings
        self.assertTrue(aggregate([report], EXPECTED, REPOSITORY)["complete"])

    def test_language_identity_matches_across_scanners_and_base_distributions(self):
        expected = scout_findings(application_scout())[0]
        self.assertEqual(expected["distro"], "application")
        for family, version in (("alpine", "3.24.2"), ("debian", "13.7")):
            with self.subTest(family=family):
                payload = application_trivy()
                payload["Metadata"]["OS"] = {"Family": family, "Name": version}
                actual = trivy_findings(payload)[0]
                self.assertEqual(actual["key"], expected["key"])
                self.assertEqual(actual["distro"], "application")

    def test_language_packages_work_without_os_metadata(self):
        for metadata in ({}, {"OS": None}):
            with self.subTest(metadata=metadata):
                payload = application_trivy()
                payload["Metadata"] = metadata
                self.assertEqual(trivy_findings(payload)[0]["distro"], "application")
                self.assertEqual(inventory(payload)["status"], "unsupported")

    def test_clean_osless_reports_do_not_require_an_inventory(self):
        payload = {"SchemaVersion": 2, "Metadata": {}, "Results": []}
        self.assertEqual(trivy_findings(payload), [])
        self.assertEqual(inventory(payload)["status"], "unsupported")

    def test_missing_os_identity_still_rejects_os_findings(self):
        payload = trivy_report()
        payload["Metadata"] = {}
        with self.assertRaises(ValueError):
            trivy_findings(payload)
        payload = scout_report()
        props = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        props["purls"] = ["pkg:apk/alpine/python3@3.14.7-r1"]
        with self.assertRaisesRegex(ValueError, "distro identity"):
            scout_findings(payload)

    def test_scoped_and_escaped_names_survive_report_validation(self):
        for purl, namespace, name in (
            ("pkg:npm/%40babel/core@7.0.0", "@babel", "core"),
            ("pkg:generic/vendor/a%40b%3Fc%23d%25e@1.0", "vendor", "a@b?c#d%e"),
            ("pkg:maven/org.example/library@1.0", "org.example", "library"),
            ("pkg:pypi/requests@2.32.0", "", "requests"),
        ):
            with self.subTest(purl=purl):
                report = scan_report()
                report["findings"] = scout_findings(application_scout(purl))
                result = aggregate([report], EXPECTED, REPOSITORY)
                group = next(iter(result["groups"].values()))
                self.assertEqual(
                    (group["namespace"], group["package"]), (namespace, name)
                )

    def test_purl_fragment_is_not_part_of_os_qualifier(self):
        payload = scout_report()
        props = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        props["purls"] = [
            "pkg:apk/alpine/python3@3.14.7-r1?os_name=alpine&os_version=3.24#usr/lib"
        ]
        self.assertEqual(scout_findings(payload)[0]["distro"], "alpine/3.24")

    def test_os_identity_cannot_inject_control_characters(self):
        payload = scout_report()
        props = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        props["purls"] = ["pkg:deb/debian/libc6@1?os_name=debian%0Aother&os_version=13"]
        with self.assertRaises(ValueError):
            scout_findings(payload)

    def test_partial_os_package_lists_cannot_prove_a_complete_inventory(self):
        payload = trivy_report()
        payload["Results"] = [
            {"Class": "os-pkgs", "Type": "alpine", "Packages": []},
            {"Class": "os-pkgs", "Type": "alpine"},
        ]
        self.assertEqual(inventory(payload)["status"], "unknown")


class ScannerEvidenceTests(unittest.TestCase):
    def test_repeated_scout_advisory_preserves_distinct_severity_and_fix_evidence(self):
        payload = scout_report(severity="Low")
        run = payload["runs"][0]
        second = copy.deepcopy(run["tool"]["driver"]["rules"][0])
        second["properties"].update(cvssV3_severity="HIGH", fixed_version="3.14.8-r0")
        run["tool"]["driver"]["rules"].append(second)
        run["results"].extend([{"ruleId": second["id"], "ruleIndex": 1}] * 2)
        findings = scout_findings(payload, all_severities=True)
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {(item["severity"], item["fix"]) for item in findings},
            {("LOW", ""), ("HIGH", "3.14.8-r0")},
        )
        self.assertEqual(scout_findings(payload)[0]["severity"], "HIGH")

    def test_sarif_rule_retains_highest_observed_severity_in_either_order(self):
        high = finding(
            "CVE-2026-19445",
            "pkg:golang/example/module",
            "1",
            "HIGH",
            "application",
            "scout",
        )
        low = {**high, "severity": "LOW"}
        for findings in ([high, low], [low, high]):
            report = sarif_report(findings)
            self.assertEqual(
                report["runs"][0]["tool"]["driver"]["rules"][0]["properties"][
                    "security-severity"
                ],
                "8.0",
            )

    def test_failed_scout_invocation_cannot_become_a_clean_assessment(self):
        payload = scout_report(clean=True)
        payload["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        with self.assertRaises(ValueError):
            scout_findings(payload, kev=True)

    def test_scan_keeps_vulnerabilities_when_optional_inventory_or_db_is_invalid(self):
        for failure in ("inventory", "database"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                output = Path(directory)

                def runner(command, failure=failure, **_kwargs):
                    if command[:3] == ["docker", "image", "inspect"]:
                        return json.dumps(
                            {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"}
                        )
                    if command[0] not in {"trivy", "docker-scout"}:
                        return ""
                    destination = Path(command[command.index("--output") + 1])
                    payload = scout_report(clean="--only-cisa-kev" in command)
                    if command[0] == "trivy":
                        payload = trivy_report()
                        payload["Results"][0].update(Class="os-pkgs", Type="alpine")
                        if failure == "inventory":
                            payload["Results"][0]["Packages"] = [
                                {
                                    "Name": "python3",
                                    "Version": "3.14.7-r1",
                                    "Arch": arch,
                                }
                                for arch in ("x86_64", "x86")
                            ]
                        else:
                            metadata = (
                                Path(command[command.index("--cache-dir") + 1])
                                / "db/metadata.json"
                            )
                            metadata.parent.mkdir(parents=True)
                            metadata.write_text("not json")
                    destination.write_text(json.dumps(payload))
                    return ""

                report = scan(
                    TARGET,
                    "published",
                    output,
                    runner=runner,
                    installer=lambda name, *_args: Path(
                        "trivy" if name == "trivy" else "docker-scout"
                    ),
                )
                self.assertEqual(report["scanners"]["trivy"], "complete")
                self.assertTrue(
                    any(item["source"] == "trivy" for item in report["findings"])
                )
                self.assertEqual(report["kev_status"], "clear")
                self.assertEqual(report["inventory"]["status"], "unknown")
                self.assertTrue(report["enrichment_errors"])

    def test_timestamp_is_required_before_report_can_manage_issues(self):
        for timestamp in (None, "", 123):
            with self.subTest(timestamp=timestamp):
                report = scan_report()
                report["scanned_at"] = timestamp
                with self.assertRaises(ValueError):
                    aggregate([report], EXPECTED, REPOSITORY)

    def test_published_osless_scan_has_complete_coverage_and_unsupported_availability(
        self,
    ):
        def runner(command, **_kwargs):
            if command[:3] == ["docker", "image", "inspect"]:
                return json.dumps(
                    {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"}
                )
            if command[0] not in {"trivy", "docker-scout"}:
                return ""
            destination = Path(command[command.index("--output") + 1])
            if command[0] == "trivy":
                payload = application_trivy()
                payload["Metadata"] = {}
            else:
                payload = (
                    scout_report(clean=True)
                    if "--only-cisa-kev" in command
                    else application_scout()
                )
            destination.write_text(json.dumps(payload))
            return ""

        with tempfile.TemporaryDirectory() as directory:
            report = scan(
                TARGET,
                "published",
                Path(directory),
                runner=runner,
                installer=lambda name, *_args: Path(
                    "trivy" if name == "trivy" else "docker-scout"
                ),
            )
        report.update(repository=REPOSITORY, run_id="123", run_attempt="1")
        result = aggregate([report], EXPECTED, REPOSITORY)
        self.assertTrue(result["complete"])
        self.assertEqual(result["availability_status"], "unsupported")
        self.assertEqual(result["availability_errors"], [])
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(report["inventory"]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
