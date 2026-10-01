from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.container_findings import finding, scout_findings, trivy_findings
from salty_actions.container_issues import (
    BOT, END, START, IssueClient, issue_marker, managed_body, plan_issues,
)
from salty_actions.container_report import aggregate, ensure_trusted_write, reconcile, main as report_main
from salty_actions.container_scan import main as scan_main, scan, sarif_report
from salty_actions.container_tools import CommandRunner, OperationError, install_tool
from salty_actions.container_snapshot import freeze_targets
from salty_actions.transport import AmbiguousRequestError, GitHubTransport
from .http_fakes import FakeResponse, RecordingOpener
from .test_transport import http_error

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
TARGET = {"name": "base", "platform": "linux/amd64", "image": "example/base@" + DIGEST}
EXPECTED = [{**TARGET, "tracking_reference": "example/base:latest"}]
REPOSITORY = "example/images"


def trivy_report():
    return {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "alpine", "Name": "3.24.2"}},
            "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-19445",
                "PkgName": "python3", "PkgIdentifier": {
                    "PURL": "pkg:apk/alpine/python3@3.14.7-r1?distro=alpine-3.24.2"},
                "InstalledVersion": "3.14.7-r1", "Severity": "CRITICAL",
                "FixedVersion": "3.14.8-r0", "PrimaryURL": "https://example.test/CVE-2026-19445"}]}]}


def scout_report(*, clean=False, severity="Critical"):
    rule = {"id": "CVE-2026-19445", "helpUri": "https://example.test/CVE-2026-19445",
            "properties": {"purls": ["pkg:apk/alpine/python3@3.14.7-r1?distro=alpine-3.24.2"],
                           "cvssV3_severity": severity.upper(), "fixed_version": "not fixed"}}
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "docker scout",
            "rules": [] if clean else [rule]}},
            "results": [] if clean else [{"ruleId": rule["id"], "ruleIndex": 0}]}]}


def scan_report(*, clean=False, complete=True, kind="published"):
    return {"schema": 1, "kind": kind, "target": dict(TARGET), "repository": REPOSITORY,
            "image_id": IMAGE_ID, "run_id": "123", "run_attempt": "1",
            "scanned_at": "2026-10-01T12:00:00+00:00",
            "scanners": {"trivy": "complete", "scout": "complete", "kev": "complete"} if complete else
                        {"trivy": "error", "scout": "complete", "kev": "complete"},
            "findings": [] if clean else scout_findings(scout_report()),
            "errors": [] if complete else ["Trivy network failure"],
            "kev_status": "clear", "report_status": "complete" if complete else "incomplete"}


def current_runner(command, **kwargs):
    return json.dumps({"manifest": {"digest": DIGEST}})


class FakeIssueClient:
    repository = REPOSITORY

    def __init__(self, issues=None):
        self.issues = issues or []
        self.writes = []
        self.bot_closed = True

    def list_issues(self):
        return copy.deepcopy(self.issues)

    def closed_by_automation(self, number):
        return self.bot_closed

    def write(self, action):
        self.writes.append(action)
        return {"number": len(self.writes), "html_url": "https://example.test/issue"}


def tracked_issue(group, *, resolved=False, state="open", number=1):
    return {"number": number, "state": state, "user": {"login": BOT},
            "title": f"{group['id']}: {group['package']} ({group['distro']})",
            "body": managed_body("containers", group, resolved=resolved)}


class ParserTests(unittest.TestCase):
    def test_real_pinned_scout_sarif_report(self):
        payload = json.loads((ROOT / "tests/fixtures/container-security/scout-v1.26.0.sarif").read_text())
        findings = scout_findings(payload)
        python = next(item for item in findings if item["id"] == "CVE-2026-19445")
        self.assertEqual(python["package"], "python3")
        self.assertEqual(python["distro"], "alpine/3.24")
        self.assertEqual(python["version"], "3.14.7-r1")
        self.assertEqual(python["fix"], "3.14.8-r0")
        self.assertEqual(python["severity"], "CRITICAL")

    def test_trivy_and_scout_identity_matches_despite_patch_release_and_purl_qualifiers(self):
        left = trivy_findings(trivy_report())[0]
        right = scout_findings(scout_report())[0]
        self.assertEqual(left["key"], right["key"])
        self.assertEqual(left["fix"], "3.14.8-r0")
        self.assertEqual(right["fix"], "")  # Do not invent an unreported fixed version.

    def test_wrong_schema_and_missing_identity_fail_closed(self):
        for parser, payload in [(trivy_findings, {}), (scout_findings, {}),
                                (scout_findings, {**scout_report(), "runs": []})]:
            with self.subTest(parser=parser):
                with self.assertRaises(ValueError):
                    parser(payload)
        payload = trivy_report()
        del payload["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]
        with self.assertRaises(ValueError):
            trivy_findings(payload)

    def test_sarif_unknown_rule_or_invalid_rule_index_is_an_error(self):
        for change in [{"ruleIndex": 8}, {"ruleId": "missing"}]:
            payload = scout_report()
            payload["runs"][0]["results"][0].update(change)
            with self.assertRaises(ValueError):
                scout_findings(payload)

    def test_lower_severity_kev_is_retained_and_v4_critical_is_reported(self):
        payload = scout_report(severity="Low")
        self.assertEqual(scout_findings(payload), [])
        self.assertEqual(scout_findings(payload, kev=True)[0]["severity"], "LOW")
        payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["cvssV4_severity"] = "CRITICAL"
        self.assertEqual(scout_findings(payload)[0]["severity"], "CRITICAL")

    def test_exported_low_severity_kev_does_not_become_a_high_severity_alert(self):
        findings = scout_findings(scout_report(severity="Low"), kev=True)
        exported = sarif_report(findings)
        score = float(exported["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"])
        self.assertLess(score, 4)

    def test_same_cve_different_packages_do_not_merge(self):
        a = scout_findings(scout_report())[0]
        b = finding(a["id"], "pkg:apk/alpine/python3-pyc", a["version"], a["severity"],
                    a["distro"], "scout")
        self.assertNotEqual(a["key"], b["key"])


class RetryTests(unittest.TestCase):
    def test_subprocess_transient_errors_retry_and_eventually_succeed(self):
        execute = unittest.mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 1, "", "HTTP 503 service unavailable"),
            subprocess.TimeoutExpired("scanner", 1),
            subprocess.CompletedProcess([], 0, "{}", "")])
        sleeps = []
        self.assertEqual(CommandRunner(execute=execute, sleep=sleeps.append)(["scanner"]), "{}")
        self.assertEqual(sleeps, [1, 2])

    def test_permanent_errors_are_not_retried(self):
        for error in ["unauthorized", "manifest unknown", "checksum mismatch", "unknown flag"]:
            execute = unittest.mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", error))
            with self.assertRaises(OperationError):
                CommandRunner(execute=execute, sleep=lambda _: self.fail("unexpected retry"))(["scanner"])
            self.assertEqual(execute.call_count, 1)

    def test_rate_limit_honors_retry_after_and_retry_budget(self):
        execute = unittest.mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, "", "HTTP 429 Retry-After: 37"))
        sleeps = []
        with self.assertRaises(OperationError):
            CommandRunner(execute=execute, sleep=sleeps.append)(["scanner"])
        self.assertEqual(sleeps, [37, 37, 37])
        self.assertEqual(execute.call_count, 4)

    def test_subprocess_errors_redact_credentials(self):
        execute = unittest.mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "bad secret-password"))
        with patch.dict(os.environ, {"DOCKER_SCOUT_HUB_PASSWORD": "secret-password"}):
            with self.assertRaises(OperationError) as caught:
                CommandRunner(execute=execute)(["scanner"])
            self.assertNotIn("secret-password", str(caught.exception))

    def test_download_checksums_and_safe_archive_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            def download(command, **kwargs):
                dest = Path(command[command.index("--dir") + 1])
                archive = dest / "docker-scout_1.26.0_linux_amd64.tar.gz"
                with tarfile.open(archive, "w:gz") as release:
                    binary = tarfile.TarInfo("../../docker-scout")
                    binary.size = 6
                    release.addfile(binary, io.BytesIO(b"binary"))
                    evil = tarfile.TarInfo("../../escaped-file")
                    evil.size = 1
                    release.addfile(evil, io.BytesIO(b"x"))
                checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                (dest / "docker-scout_1.26.0_checksums.txt").write_text(f"{checksum}  {archive.name}\n")
                return ""
            binary = install_tool("scout", "v1.26.0", "X64", Path(directory), download)
            self.assertEqual(binary.read_bytes(), b"binary")
            self.assertFalse((Path(directory).parent / "escaped-file").exists())

    def test_invalid_release_or_checksum_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                install_tool("scout", "main", "X64", Path(directory), lambda *a, **k: self.fail("download"))
            def bad_download(command, **kwargs):
                dest = Path(command[command.index("--dir") + 1])
                name = "docker-scout_1.26.0_linux_amd64.tar.gz"
                (dest / name).write_bytes(b"untrusted")
                (dest / "docker-scout_1.26.0_checksums.txt").write_text("0" * 64 + "  " + name)
                return ""
            with self.assertRaisesRegex(OperationError, "checksum"):
                install_tool("scout", "v1.26.0", "X64", Path(directory), bad_download)


class ScanTests(unittest.TestCase):
    def run_scan(self, *, failed=(), kev=False):
        def runner(command, **kwargs):
            if command[:3] == ["docker", "image", "inspect"]:
                return json.dumps({"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"})
            if command[0] in {"trivy", "docker-scout"}:
                mode = "trivy" if command[0] == "trivy" else (
                    "kev" if "--only-cisa-kev" in command else "scout")
                if mode in failed:
                    raise OperationError("network failed after retries")
                path = Path(command[command.index("--output") + 1])
                payload = trivy_report() if mode == "trivy" else scout_report(clean=mode == "kev" and not kev)
                path.write_text(json.dumps(payload))
            return ""
        with tempfile.TemporaryDirectory() as directory:
            report = scan(TARGET, "published", Path(directory), runner=runner,
                          installer=lambda name, *args: Path("trivy" if name == "trivy" else "docker-scout"))
            self.assertTrue((Path(directory) / "report.json").is_file())
            self.assertTrue((Path(directory) / "findings.sarif").is_file())
            return report

    def test_ordinary_critical_findings_are_complete_and_kev_clear(self):
        report = self.run_scan()
        self.assertEqual(report["report_status"], "complete")
        self.assertEqual(report["kev_status"], "clear")
        self.assertEqual(len(report["findings"]), 2)

    def test_advisory_failure_does_not_destroy_kev_assessment(self):
        report = self.run_scan(failed={"trivy"})
        self.assertEqual(report["report_status"], "incomplete")
        self.assertEqual(report["kev_status"], "clear")
        self.assertEqual(len(report["findings"]), 1)

    def test_failed_kev_is_unknown_and_detected_kev_found(self):
        self.assertEqual(self.run_scan(failed={"kev"})["kev_status"], "unknown")
        self.assertEqual(self.run_scan(kev=True)["kev_status"], "found")

    def test_platform_mismatch_preserves_error_report(self):
        with tempfile.TemporaryDirectory() as directory:
            report = scan(TARGET, "published", Path(directory),
                          runner=lambda *a, **k: json.dumps({"Id": IMAGE_ID, "Os": "linux", "Architecture": "arm64"}))
            self.assertEqual(report["kev_status"], "unknown")
            self.assertIn("does not match", report["errors"][0])

    def test_published_mutable_reference_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "digest-pinned"):
                scan({**TARGET, "image": "example/base:latest"}, "published", Path(directory))

    def test_scout_disabled_candidate_cannot_claim_complete_kev_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "require Scout"):
                scan(TARGET, "published", Path(directory), scout_enabled=False)
            def runner(command, **kwargs):
                if command[:3] == ["docker", "image", "inspect"]:
                    return json.dumps({"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"})
                if command[0] == "trivy":
                    Path(command[command.index("--output") + 1]).write_text(json.dumps(trivy_report()))
                return ""
            report = scan(TARGET, "candidate", Path(directory), scout_enabled=False, runner=runner,
                          installer=lambda name, *args: Path(name))
            self.assertEqual(report["kev_status"], "unknown")
            self.assertEqual(report["scanners"]["trivy"], "complete")

    def test_main_enforces_kev_but_does_not_block_ordinary_advisory_errors(self):
        for kev, expected in [("clear", 0), ("found", 1), ("unknown", 2)]:
            with self.subTest(kev=kev), patch.dict(os.environ, {"TRIVY_VERSION": "v0.74.0",
                    "SCOUT_VERSION": "v1.26.0"}, clear=True), patch(
                        "salty_actions.container_scan.scan", return_value={
                            "report_status": "incomplete", "kev_status": kev, "findings": [], "errors": []}):
                self.assertEqual(scan_main(), expected)


class ReportingTests(unittest.TestCase):
    def groups(self):
        return aggregate([scan_report()], EXPECTED, REPOSITORY)["groups"]

    def test_multiple_scanners_and_architectures_aggregate_into_one_issue(self):
        left = scan_report()
        left["findings"].extend(trivy_findings(trivy_report()))
        right = copy.deepcopy(left)
        right["target"]["platform"] = "linux/arm64"
        expected = EXPECTED + [{**EXPECTED[0], "platform": "linux/arm64"}]
        result = aggregate([left, right], expected, REPOSITORY)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(len(next(iter(result["groups"].values()))["observations"]), 4)

    def test_incomplete_reports_preserve_issues_and_report_positive_findings(self):
        group = next(iter(self.groups().values()))
        existing = tracked_issue({**group, "key": "another-key"})
        client = FakeIssueClient([existing])
        result = reconcile([scan_report(complete=False)], EXPECTED, "containers", client,
                           runner=current_runner)
        self.assertFalse(result["complete"])
        self.assertEqual([row["operation"] for row in result["actions"]], ["create"])
        self.assertEqual(client.writes, [])

    def test_clean_current_complete_scan_closes_existing_issue(self):
        client = FakeIssueClient([tracked_issue(next(iter(self.groups().values())))])
        result = reconcile([scan_report(clean=True)], EXPECTED, "containers", client,
                           dry_run=False, runner=current_runner)
        self.assertEqual([row["operation"] for row in client.writes], ["close"])
        self.assertTrue(issue_marker({**client.issues[0], **client.writes[0]["payload"]})["resolved"])
        self.assertTrue(result["complete"])

    def test_unchanged_scan_does_not_update_issue_and_preserves_human_notes(self):
        group = next(iter(self.groups().values()))
        existing = tracked_issue(group)
        existing["body"] = "human notes\n" + existing["body"] + "\nmore notes"
        client = FakeIssueClient([existing])
        self.assertEqual(plan_issues("containers", self.groups(), client.issues,
                                    complete=True, client=client), [])
        group["observations"][0]["version"] = "3.14.7-r2"
        actions = plan_issues("containers", {group["key"]: group}, client.issues, complete=True, client=client)
        self.assertTrue(actions[0]["payload"]["body"].startswith("human notes\n" + START))
        self.assertTrue(actions[0]["payload"]["body"].endswith(END + "\nmore notes"))

    def test_manual_closure_is_respected_and_bot_resolution_can_reopen(self):
        group = next(iter(self.groups().values()))
        client = FakeIssueClient([tracked_issue(group, state="closed", resolved=False)])
        self.assertEqual(plan_issues("containers", self.groups(), client.issues, complete=True, client=client), [])
        client.issues = [tracked_issue(group, state="closed", resolved=True)]
        self.assertEqual(plan_issues("containers", self.groups(), client.issues,
                                    complete=True, client=client)[0]["operation"], "reopen")
        client.bot_closed = False
        self.assertEqual(plan_issues("containers", self.groups(), client.issues, complete=True, client=client), [])

    def test_missing_architecture_never_closes_issues(self):
        client = FakeIssueClient([tracked_issue(next(iter(self.groups().values())))])
        expected = EXPECTED + [{**EXPECTED[0], "platform": "linux/arm64"}]
        result = reconcile([scan_report(clean=True)], expected, "containers", client, runner=current_runner)
        self.assertFalse(result["complete"])
        self.assertEqual(result["actions"], [])

    def test_snapshot_freezes_one_digest_for_all_platforms(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return current_runner(command)
        targets = [{**TARGET, "image": "example/base:latest"},
                   {**TARGET, "image": "example/base:latest", "platform": "linux/arm64"}]
        result = freeze_targets(targets, runner=runner)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result[0]["image"], result[1]["image"])
        self.assertEqual(result[0]["tracking_reference"], "example/base:latest")

    def test_snapshot_invalid_or_duplicate_targets_are_rejected(self):
        for targets in [[], [TARGET], [{**TARGET, "image": "example/base:latest"}] * 2]:
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                freeze_targets(targets, runner=current_runner)

    def test_candidate_foreign_duplicate_or_tampered_reports_rejected(self):
        for reports in [[scan_report(kind="candidate")], [{**scan_report(), "repository": "other/repo"}],
                        [scan_report(), scan_report()]]:
            with self.subTest(reports=reports), self.assertRaises(ValueError):
                aggregate(reports, EXPECTED, REPOSITORY)
        report = scan_report()
        report["findings"][0]["key"] = "wrong"
        with self.assertRaises(ValueError):
            aggregate([report], EXPECTED, REPOSITORY)

    def test_reports_from_an_older_attempt_cannot_close_current_issues(self):
        with self.assertRaisesRegex(ValueError, "run or attempt"):
            aggregate([scan_report(clean=True)], EXPECTED, REPOSITORY, run_id="123", run_attempt="2")

    def test_report_main_retains_error_output_for_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch.dict(os.environ, {"SECURITY_REPORT_OUTPUT": str(output)}, clear=True):
                self.assertEqual(report_main(), 2)
            self.assertFalse(json.loads(output.read_text())["complete"])
            self.assertTrue(json.loads(output.read_text())["errors"])

    def test_report_main_unwritable_output_returns_operational_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"SECURITY_REPORT_OUTPUT": directory}, clear=True):
                self.assertEqual(report_main(), 2)

    def test_action_commands_work_outside_the_tool_checkout(self):
        for action, expected in [("container-scan", "Container scan failed"),
                                 ("container-report", "Container reporting failed")]:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                commands = [line.removeprefix("      run: ") for line in
                            (ROOT / action / "action.yml").read_text().splitlines()
                            if line.startswith("      run: ")]
                self.assertEqual(len(commands), 1)
                env = {"PATH": os.environ["PATH"], "GITHUB_ACTION_PATH": str(ROOT / action),
                       "SECURITY_REPORT_OUTPUT": str(Path(directory) / "report.json")}
                result = subprocess.run(["bash", "-c", commands[0]], cwd=directory,
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_stale_snapshot_performs_no_writes(self):
        client = FakeIssueClient()
        with self.assertRaisesRegex(ValueError, "changed since scan"):
            reconcile([scan_report()], EXPECTED, "containers", client, dry_run=False,
                      runner=lambda *a, **k: json.dumps({"manifest": {"digest": IMAGE_ID}}))
        self.assertEqual(client.writes, [])

    def test_registry_outage_prevents_all_issue_writes(self):
        client = FakeIssueClient()
        def unavailable(*args, **kwargs):
            raise OperationError("registry timed out after retries")
        with self.assertRaises(OperationError):
            reconcile([scan_report()], EXPECTED, "containers", client, dry_run=False, runner=unavailable)
        self.assertEqual(client.writes, [])

    def test_partial_write_failure_is_retained(self):
        report = scan_report()
        second = finding("CVE-2026-19553", "pkg:apk/alpine/python3", "3.14.7-r1", "HIGH", "alpine/3.24", "scout")
        report["findings"].append(second)
        client = FakeIssueClient()
        original = client.write
        def fail_second(action):
            if client.writes:
                raise RuntimeError("HTTP 403")
            return original(action)
        client.write = fail_second
        result = reconcile([report], EXPECTED, "containers", client, dry_run=False, runner=current_runner)
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["applied"]), 1)
        self.assertIn("HTTP 403", result["errors"])

    def test_trusted_write_rejects_pr_and_nondefault_branches(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"repository": {"full_name": REPOSITORY, "default_branch": "main"}}))
            env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "schedule",
                   "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": "refs/heads/main"}
            ensure_trusted_write(env)
            for changes in [{"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/topic"}]:
                with self.assertRaises(ValueError):
                    ensure_trusted_write({**env, **changes})


class IssueTransportTests(unittest.TestCase):
    def action(self, *, update=False):
        group = next(iter(aggregate([scan_report()], EXPECTED, REPOSITORY)["groups"].values()))
        existing = tracked_issue(group)
        if update:
            existing["title"] = "old title"
        client = FakeIssueClient([existing] if update else [])
        return plan_issues("containers", {group["key"]: group}, client.issues,
                           complete=True, client=client)[0]

    def test_explicit_rate_limit_rejection_retries_issue_write(self):
        opener = RecordingOpener([http_error(429, headers={"Retry-After": "7"}),
                                  FakeResponse(201, {"number": 1})])
        sleeps = []
        transport = GitHubTransport("token", opener=opener, sleep=sleeps.append)
        self.assertEqual(transport.send_json("/issues", "POST", {"title": "test"}), {"number": 1})
        self.assertEqual(sleeps, [7])
        self.assertEqual(opener.requests[0].get_header("Content-type"), "application/json")

    def test_secondary_rate_limit_body_is_read_once_and_retried(self):
        opener = RecordingOpener([http_error(403, message="You have exceeded a secondary rate limit"),
                                  FakeResponse(201, {"number": 1})])
        sleeps = []
        transport = GitHubTransport("token", opener=opener, sleep=sleeps.append)
        self.assertEqual(transport.send_json("/issues", "POST", {}), {"number": 1})
        self.assertEqual(sleeps, [60])

    def test_lost_create_response_reconciles_without_second_post(self):
        action = self.action()
        existing = {"number": 1, "state": "open", "user": {"login": BOT}, **action["payload"]}
        opener = RecordingOpener([URLError("connection reset"), FakeResponse(200, [existing])])
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport(
            "token", opener=opener, sleep=lambda _: None))
        self.assertEqual(client.write(action)["number"], 1)
        self.assertEqual([request.method for request in opener.requests], ["POST", "GET"])

    def test_uncertain_create_missing_after_read_is_not_duplicated(self):
        for failure in [http_error(503), TimeoutError(), URLError("connection reset")]:
            opener = RecordingOpener([failure, FakeResponse(200, [])])
            client = IssueClient("token", REPOSITORY, transport=GitHubTransport(
                "token", opener=opener, sleep=lambda _: None))
            with self.assertRaises(AmbiguousRequestError):
                client.write(self.action())
            self.assertEqual([request.method for request in opener.requests], ["POST", "GET"])

    def test_uncertain_idempotent_patch_can_retry_after_unchanged_read(self):
        action = self.action(update=True)
        old = {"number": 1, "state": action["before_state"], "body": action["before_body"],
               "title": "old title", "user": {"login": BOT}}
        updated = {**old, **action["payload"]}
        opener = RecordingOpener([http_error(503), FakeResponse(200, [old]), FakeResponse(200, updated)])
        sleeps = []
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport(
            "token", opener=opener, sleep=sleeps.append))
        self.assertEqual(client.write(action)["title"], updated["title"])
        self.assertEqual([request.method for request in opener.requests], ["PATCH", "GET", "PATCH"])
        self.assertEqual(sleeps, [1])

    def test_concurrent_human_edit_stops_patch_retry(self):
        action = self.action(update=True)
        changed = {"number": 1, "state": action["before_state"], "body": action["before_body"],
                   "title": "human title", "user": {"login": BOT}}
        opener = RecordingOpener([http_error(503), FakeResponse(200, [changed])])
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport("token", opener=opener))
        with self.assertRaisesRegex(AmbiguousRequestError, "changed during"):
            client.write(action)
        self.assertEqual([request.method for request in opener.requests], ["PATCH", "GET"])

    def test_last_closure_actor_controls_reopening(self):
        opener = RecordingOpener([FakeResponse(200, [
            {"event": "closed", "actor": {"login": BOT}},
            {"event": "reopened", "actor": {"login": "human"}},
            {"event": "closed", "actor": {"login": "human"}},
        ])])
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport("token", opener=opener))
        self.assertFalse(client.closed_by_automation(1))

    def test_permission_error_is_not_retried_or_reconciled(self):
        opener = RecordingOpener([http_error(403)])
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport(
            "token", opener=opener, sleep=lambda _: None))
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            client.write(self.action())
        self.assertEqual(len(opener.requests), 1)

    def test_read_timeout_retries_and_recovers(self):
        opener = RecordingOpener([TimeoutError(), FakeResponse(200, [])])
        sleeps = []
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport(
            "token", opener=opener, sleep=sleeps.append))
        self.assertEqual(client.list_issues(), [])
        self.assertEqual(sleeps, [1])

    def test_pagination_includes_closed_issues_and_excludes_pull_requests(self):
        opener = RecordingOpener([FakeResponse(200, [{"pull_request": {}}] * 100),
                                  FakeResponse(200, [{"number": 2, "state": "closed"}])])
        client = IssueClient("token", REPOSITORY, transport=GitHubTransport("token", opener=opener))
        self.assertEqual(client.list_issues(), [{"number": 2, "state": "closed"}])
        self.assertIn("page=2", opener.requests[1].full_url)


if __name__ == "__main__":
    unittest.main()
