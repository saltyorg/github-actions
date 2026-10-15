from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .test_container_security import (
    BOT,
    DIGEST,
    FakeIssueClient,
    TARGET,
    scan_report,
    scout_report,
    trivy_report,
)
from salty_actions.container_findings import scout_findings
from salty_actions.container_issues import issue_marker
from salty_actions.container_packages import assess, digest, inventory, vendor_fixes
from salty_actions.container_report import reconcile
from salty_actions.container_scan import scan
from salty_actions.container_tools import OperationError
from salty_actions.container_tracking import read_state


class AppliedIssues(FakeIssueClient):
    def write(self, action):
        self.writes.append(copy.deepcopy(action))
        number = action.get("number") or len(self.issues) + 1
        issue = next((row for row in self.issues if row["number"] == number), None)
        if issue is None:
            issue = {"number": number, "state": "open", "user": {"login": BOT}}
            self.issues.append(issue)
        issue.update(action["payload"])
        return {**issue, "html_url": f"https://example.test/issues/{number}"}


def package_inventory(version="3.14.7-r1", *, removed=False):
    result = {
        "status": "complete",
        "distro": "alpine/3.24",
        "eosl": False,
        "packages": []
        if removed
        else [
            {
                "name": "python3",
                "version": version,
                "source_name": "python3",
                "source_version": version,
            }
        ],
    }
    return {**result, "sha256": digest(result)}


def report_v2(
    run="100", *, hours_ago=18, clean=False, version="3.14.7-r1", removed=False
):
    report = scan_report(clean=clean)
    key = scout_findings(scout_report())[0]["key"]
    report.update(
        schema=2,
        run_id=run,
        scanned_at=(
            datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        ).isoformat(),
        inventory=package_inventory(version, removed=removed),
        provenance={"trivy_version": "v0.74.0"},
        availability={
            "status": "complete",
            "errors": [],
            "remediated": [key] if clean else [],
            "fixes": {
                key: {
                    "status": "fixed" if clean else "installable",
                    "source": "Alpine secdb",
                    "versions": ["3.14.8-r0"],
                    "candidates": ["3.14.8-r0"],
                }
            },
        },
    )
    if clean:
        report["image_id"] = "sha256:" + "c" * 64
        report["target"]["image"] = "example/base@sha256:" + "d" * 64
    return report


def apply(client, report, *, extra_expected=()):
    expected = [
        {**report["target"], "tracking_reference": "example/base:latest"},
        *extra_expected,
    ]
    return reconcile(
        [report],
        expected,
        "containers",
        client,
        dry_run=False,
        runner=lambda *args, **kwargs: json.dumps(
            {"manifest": {"digest": report["target"]["image"].split("@", 1)[1]}}
        ),
    )


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.client = AppliedIssues()
        apply(self.client, report_v2())

    def state(self):
        return read_state(self.client.issues[0]["body"])

    def test_single_clean_scan_then_recurrence_never_closes(self):
        apply(self.client, report_v2("101", clean=True))
        self.assertEqual(self.state()["status"], "review")
        apply(self.client, report_v2("102"))
        self.assertEqual(self.state()["status"], "detected")
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertNotIn(
            "close", [action["operation"] for action in self.client.writes]
        )

    def test_fixed_published_inventory_and_two_spaced_runs_close_and_recurrence_reopens(
        self,
    ):
        apply(
            self.client, report_v2("101", clean=True, version="3.14.8-r0", hours_ago=12)
        )
        self.assertEqual(self.state()["status"], "pending")
        self.assertFalse((issue_marker(self.client.issues[0]) or {})["resolved"])
        apply(
            self.client, report_v2("102", clean=True, version="3.14.8-r0", hours_ago=5)
        )
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.assertTrue((issue_marker(self.client.issues[0]) or {})["resolved"])
        self.assertIn("3.14.8-r0", self.client.issues[0]["body"])
        self.assertIn("example/base@sha256:" + "d" * 64, self.client.issues[0]["body"])
        apply(self.client, report_v2("103", hours_ago=1))
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertEqual(self.client.writes[-1]["operation"], "reopen")

    def test_reruns_and_insufficient_elapsed_time_do_not_confirm(self):
        for run, hour in [("101", 12), ("101", 5), ("102", 10)]:
            apply(
                self.client,
                report_v2(run, clean=True, version="3.14.8-r0", hours_ago=hour),
            )
            self.assertEqual(self.state()["status"], "pending")
        self.assertEqual(self.client.issues[0]["state"], "open")

    def test_incomplete_intervening_scan_resets_confirmation(self):
        apply(
            self.client, report_v2("101", clean=True, version="3.14.8-r0", hours_ago=12)
        )
        broken = report_v2("102", clean=True, version="3.14.8-r0", hours_ago=10)
        broken["scanners"]["scout"] = "error"
        broken["report_status"] = "incomplete"
        apply(self.client, broken)
        self.assertEqual(self.state()["status"], "incomplete")
        apply(
            self.client, report_v2("103", clean=True, version="3.14.8-r0", hours_ago=5)
        )
        self.assertEqual(self.state()["status"], "pending")

    def test_changed_publication_resets_confirmation(self):
        apply(
            self.client, report_v2("101", clean=True, version="3.14.8-r0", hours_ago=12)
        )
        newer = report_v2("102", clean=True, version="3.14.8-r0", hours_ago=5)
        newer["image_id"] = "sha256:" + "e" * 64
        apply(self.client, newer)
        self.assertEqual(self.state()["status"], "pending")
        self.assertEqual(self.state()["pending"]["run_id"], "102")

    def test_package_removal_requires_complete_inventory_and_confirmation(self):
        for run, hour in [("101", 12), ("102", 5)]:
            apply(self.client, report_v2(run, clean=True, removed=True, hours_ago=hour))
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.assertIn("package removed", self.client.issues[0]["body"])

    def test_missing_architecture_or_changed_scope_never_closes(self):
        report = report_v2("101", clean=True, version="3.14.8-r0")
        missing = {
            **report["target"],
            "platform": "linux/arm64",
            "tracking_reference": "example/base:latest",
        }
        result = apply(self.client, report, extra_expected=[missing])
        self.assertFalse(result["complete"])
        self.assertEqual(self.state()["status"], "incomplete")

    def test_unknown_vendor_evidence_and_stale_reports_cannot_resolve(self):
        for change in ("availability", "time", "inventory"):
            report = report_v2("101", clean=True, version="3.14.8-r0", hours_ago=12)
            if change == "availability":
                report["availability"] = {
                    "status": "unknown",
                    "errors": ["repository unavailable"],
                }
            elif change == "time":
                report["scanned_at"] = (
                    datetime.now(timezone.utc) - timedelta(days=2)
                ).isoformat()
            else:
                report["inventory"] = {"status": "unknown"}
            if change == "time":
                with self.assertRaisesRegex(ValueError, "stale"):
                    apply(self.client, report)
                continue
            apply(self.client, report)
            self.assertEqual(self.state()["status"], "review")

    def test_low_severity_continues_existing_issue_without_creating_new_ones(self):
        report = report_v2("101")
        report["findings"] = scout_findings(
            scout_report(severity="Low"), all_severities=True
        )
        apply(self.client, report)
        self.assertEqual(self.state()["status"], "detected")
        self.assertIn("LOW", self.client.issues[0]["body"])
        other = AppliedIssues()
        apply(other, report)
        self.assertEqual(other.issues, [])

    def test_identical_assessments_are_noops_and_human_text_is_preserved(self):
        issue = self.client.issues[0]
        issue["body"] = "Human notes\n" + issue["body"] + "\nDo not remove"
        before = issue["body"]
        result = apply(self.client, report_v2("101", hours_ago=12))
        self.assertEqual(result["actions"], [])
        self.assertEqual(issue["body"], before)
        report = report_v2("102")
        key = report["findings"][0]["key"]
        report["availability"]["fixes"][key]["status"] = "blocked"
        apply(self.client, report)
        self.assertIn("Upgrade blocked", issue["body"])
        self.assertTrue(issue["body"].startswith("Human notes\n"))
        self.assertTrue(issue["body"].endswith("\nDo not remove"))

    def test_corrupt_state_or_inventory_stops_writes(self):
        count = len(self.client.writes)
        self.client.issues[0]["body"] = self.client.issues[0]["body"].replace(
            '"affected":[', '"affected":null,"broken":[', 1
        )
        with self.assertRaisesRegex(ValueError, "tracking state"):
            apply(self.client, report_v2("101"))
        self.assertEqual(len(self.client.writes), count)
        report = report_v2()
        report["inventory"]["packages"][0]["version"] = "99.0-r0"
        with self.assertRaisesRegex(ValueError, "inventory hash"):
            apply(AppliedIssues(), report)

    def test_manual_reopening_does_not_reuse_old_resolution(self):
        for run, hour in [("101", 12), ("102", 5)]:
            apply(self.client, report_v2(run, clean=True, removed=True, hours_ago=hour))
        self.client.issues[0]["state"] = "open"
        apply(self.client, report_v2("103", clean=True, removed=True, hours_ago=1))
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertEqual(self.state()["status"], "review")
        apply(self.client, report_v2("104", clean=True, removed=True, hours_ago=0))
        self.assertEqual(self.state()["status"], "review")

    def test_source_package_still_present_under_another_binary_name_is_not_removal(
        self,
    ):
        report = report_v2("101", clean=True, removed=True)
        entry = {
            "name": "python3-renamed",
            "source_name": "python3",
            "version": "3.14.7-r1",
            "source_version": "3.14.7-r1",
        }
        report["inventory"]["packages"] = [entry]
        report["inventory"]["sha256"] = digest(
            {k: v for k, v in report["inventory"].items() if k != "sha256"}
        )
        report["availability"] = {"status": "unknown", "errors": []}
        apply(self.client, report)
        self.assertEqual(self.state()["status"], "review")

    def test_eol_inventory_cannot_prove_resolution(self):
        report = report_v2("101", clean=True, removed=True)
        report["inventory"]["eosl"] = True
        report["inventory"]["sha256"] = digest(
            {k: v for k, v in report["inventory"].items() if k != "sha256"}
        )
        apply(self.client, report)
        self.assertEqual(self.state()["status"], "review")

    def test_per_platform_fix_lag_is_visible_and_one_remaining_detection_blocks_closure(
        self,
    ):
        left = report_v2("101")
        right = copy.deepcopy(left)
        right["target"]["platform"] = "linux/arm64"
        key = left["findings"][0]["key"]
        right["availability"]["fixes"][key]["status"] = "not_available"
        expected = [
            {**r["target"], "tracking_reference": "example/base:latest"}
            for r in (left, right)
        ]
        result = reconcile(
            [left, right],
            expected,
            "containers",
            self.client,
            dry_run=False,
            runner=lambda *args, **kwargs: json.dumps({"manifest": {"digest": DIGEST}}),
        )
        self.assertTrue(result["complete"])
        self.assertIn("some affected targets", self.client.issues[0]["body"])
        self.assertIn(
            "Fix not yet in configured repositories", self.client.issues[0]["body"]
        )
        left["findings"] = []
        reconcile(
            [left, right],
            expected,
            "containers",
            self.client,
            dry_run=False,
            runner=lambda *args, **kwargs: json.dumps({"manifest": {"digest": DIGEST}}),
        )
        self.assertEqual(self.client.issues[0]["state"], "open")

    def test_scanner_advertised_fix_change_updates_existing_body(self):
        report = report_v2("101")
        report["findings"][0]["fix"] = "3.14.9-r0"
        apply(self.client, report)
        self.assertIn("3.14.9-r0", self.client.issues[0]["body"])
        self.assertIn("Vendor fix", self.client.issues[0]["body"])


class PackageEvidenceTests(unittest.TestCase):
    def vendor(self, repository="main"):
        return {
            "distroversion": "v3.24",
            "reponame": repository,
            "packages": [
                {
                    "pkg": {
                        "name": "python3",
                        "secfixes": {
                            "3.14.8-r0": ["CVE-2026-19445"],
                            "0": ["CVE-2026-1"],
                        },
                    }
                }
            ],
        }

    def test_secdb_branch_source_mapping_and_unfixed_records(self):
        fixes = vendor_fixes(self.vendor(), "3.24", "main")
        self.assertEqual(fixes["python3"], {"CVE-2026-19445": {"3.14.8-r0"}})
        with self.assertRaisesRegex(ValueError, "another branch"):
            vendor_fixes(self.vendor(), "3.23", "main")

    def run_probe(self, *, status="installable", fail=False, source_split=False):
        packages = package_inventory()
        if status == "fixed":
            packages = package_inventory("3.14.8-r0")
        if source_split:
            packages["packages"][0]["name"] = "python3-pyc"
        observations = scout_findings(scout_report())

        def runner(command, **kwargs):
            self.probe_calls.append(command)
            if command[:2] == ["docker", "rm"]:
                return ""
            if command[0] == "curl":
                repository = (
                    "main" if command[-1].endswith("main.json") else "community"
                )
                Path(command[command.index("--output") + 1]).write_text(
                    json.dumps(self.vendor(repository))
                )
                return ""
            if fail:
                raise OperationError("repository network failure")
            arguments = command[command.index("apk-fix-probe") + 2 :]
            responses = ["APK\tapk-tools 3.0.8"]
            for index in range(0, len(arguments), 4):
                key, package, installed, fixed = arguments[index : index + 4]
                comparison = "=" if status == "fixed" else "<"
                responses.append(
                    f"CHECK\t{key}\t{fixed}\t{comparison}\t3.14.8-r0\t{status}"
                )
            self.assertIn("--cap-drop", command)
            self.assertNotIn("--available", command)
            return "\n".join(responses)

        self.probe_calls = []
        with tempfile.TemporaryDirectory() as directory:
            return assess(
                packages,
                observations,
                TARGET,
                "sha256:" + "b" * 64,
                Path(directory),
                runner,
            )

    def test_installable_blocked_and_per_source_fix_statuses(self):
        key = scout_findings(scout_report())[0]["key"]
        for status in ("installable", "blocked", "not_available", "fixed"):
            result = self.run_probe(status=status)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["fixes"][key]["status"], status)
            self.assertEqual(key in result["remediated"], status == "fixed")

    def test_split_binary_package_proves_source_package_fix(self):
        key = scout_findings(scout_report())[0]["key"]
        result = self.run_probe(status="fixed", source_split=True)
        self.assertIn(key, result["remediated"])

    def test_network_failures_are_unknown_and_distroless_never_executes_apk(self):
        result = self.run_probe(fail=True)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["errors"])
        self.assertTrue(
            any(
                command[:3] == ["docker", "rm", "--force"]
                for command in self.probe_calls
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            result = assess(
                {"status": "complete", "distro": "debian/13"},
                [],
                TARGET,
                DIGEST,
                Path(directory),
                lambda *args, **kwargs: self.fail("unexpected execution"),
            )
        self.assertEqual(result["status"], "unsupported")

    def test_inventory_distinguishes_missing_lists_from_complete_empty_lists(self):
        payload = trivy_report()
        self.assertEqual(inventory(payload)["status"], "unknown")
        payload["Results"][0].update(Class="os-pkgs", Type="alpine", Packages=[])
        self.assertEqual(inventory(payload)["status"], "complete")

    def test_candidate_scans_never_execute_availability_probes(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:3] == ["docker", "image", "inspect"]:
                return json.dumps(
                    {"Id": "sha256:" + "b" * 64, "Os": "linux", "Architecture": "amd64"}
                )
            if command[0] in {"trivy", "scout"}:
                payload = (
                    trivy_report()
                    if command[0] == "trivy"
                    else scout_report(clean=True)
                )
                Path(command[command.index("--output") + 1]).write_text(
                    json.dumps(payload)
                )
            return ""

        with tempfile.TemporaryDirectory() as directory:
            scan(
                TARGET,
                "candidate",
                Path(directory),
                runner=runner,
                installer=lambda name, *args: Path(name),
            )
        self.assertFalse(any(command[:2] == ["docker", "run"] for command in calls))


if __name__ == "__main__":
    unittest.main()
