from __future__ import annotations

import copy
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.container_findings import finding
from salty_actions.container_issues import (
    BOT,
    IssueClient,
    issue_marker,
    managed_body,
    plan_issues,
)
from salty_actions.container_packages import digest
from salty_actions.container_tracking import evolve, read_state
from salty_actions.transport import GitHubTransport

from .http_fakes import FakeResponse, RecordingOpener
from .test_container_security import REPOSITORY, FakeIssueClient
from .test_transport import http_error


def language_group(distro: str = "application") -> dict:
    item = finding(
        "CVE-2026-114437",
        "pkg:golang/github.com/go-chi/chi/v5@5.3.2",
        "5.3.2",
        "HIGH",
        distro,
        "trivy",
    )
    return {
        **item,
        "observations": [
            {
                **item,
                "name": "base",
                "platform": "linux/amd64",
                "availability": {"status": "unsupported"},
            }
        ],
        "images": ["example/base@sha256:" + "a" * 64],
        "run_url": "",
    }


def assessment() -> dict:
    return {
        "targets": [
            {
                "name": "base",
                "platform": "linux/amd64",
                "inventory": {"status": "unknown"},
            }
        ],
        "run_id": "100",
        "at": datetime.now(UTC).isoformat(),
    }


def language_issue(group: dict, *, number: int = 1) -> dict:
    tracking = evolve(None, group, assessment(), complete=True)
    return {
        "number": number,
        "state": "open",
        "user": {"login": BOT},
        "title": "old title",
        "body": "Human introduction.\n"
        + managed_body("containers", group, tracking=tracking)
        + "\nHuman follow-up.",
    }


def legacy_language_issue(distro: str = "alpine/3.24", *, number: int = 1) -> dict:
    group = language_group(distro)
    return {
        "number": number,
        "state": "open",
        "user": {"login": BOT},
        "title": "legacy title is not identity evidence",
        "body": "Human introduction.\n"
        + managed_body("containers", group)
        + "\nHuman follow-up.",
    }


def inventoried_assessment(*distros: str) -> dict:
    current = assessment()
    current["targets"] = []
    for index, distro in enumerate(distros):
        inventory = {
            "status": "complete",
            "distro": distro,
            "eosl": False,
            "packages": [],
        }
        current["targets"].append(
            {
                "name": "base-" + str(index),
                "platform": "linux/amd64",
                "inventory": {**inventory, "sha256": digest(inventory)},
            }
        )
    return current


def issue_action(existing: dict, group: dict) -> dict:
    client = FakeIssueClient([existing])
    return plan_issues(
        "containers",
        {group["key"]: group},
        [existing],
        complete=True,
        client=client,
        assessment=assessment(),
    )[0]


class LanguageIssueMigrationTests(unittest.TestCase):
    def test_legacy_issue_without_tracking_migrates_by_verified_old_identity_hash(self):
        group = language_group()
        existing = legacy_language_issue()
        actions = plan_issues(
            "containers",
            {group["key"]: group},
            [existing],
            complete=True,
            client=FakeIssueClient([existing]),
            assessment=inventoried_assessment("alpine/3.24"),
        )
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["operation"], "update")
        self.assertEqual(actions[0]["number"], existing["number"])
        updated = {**existing, **actions[0]["payload"]}
        self.assertEqual((issue_marker(updated) or {})["key"], group["key"])
        self.assertTrue(updated["body"].startswith("Human introduction.\n"))
        self.assertTrue(updated["body"].endswith("\nHuman follow-up."))
        self.assertIsNotNone(read_state(updated["body"]))

    def test_verified_legacy_manual_closure_does_not_create_a_canonical_duplicate(self):
        group = language_group()
        existing = legacy_language_issue()
        existing["state"] = "closed"
        client = FakeIssueClient([existing])
        client.bot_closed = False
        self.assertEqual(
            plan_issues(
                "containers",
                {group["key"]: group},
                [existing],
                complete=True,
                client=client,
                assessment=inventoried_assessment("alpine/3.24"),
            ),
            [],
        )

    def test_legacy_identity_without_trusted_distro_evidence_blocks_new_app_issue(self):
        group = language_group()
        for current in (assessment(), inventoried_assessment("debian/13.7")):
            for state in ("open", "closed"):
                with self.subTest(assessment=current, state=state):
                    existing = legacy_language_issue()
                    existing["state"] = state
                    with self.assertRaisesRegex(ValueError, "manual reconciliation"):
                        plan_issues(
                            "containers",
                            {group["key"]: group},
                            [existing],
                            complete=True,
                            client=FakeIssueClient([existing]),
                            assessment=current,
                        )

    def test_legacy_review_state_without_a_baseline_does_not_bypass_ambiguity_guard(
        self,
    ):
        group = language_group()
        existing = legacy_language_issue()
        previous = evolve(None, None, assessment(), complete=True)
        existing["body"] = managed_body(
            "containers", language_group("alpine/3.24"), tracking=previous
        )
        with self.assertRaisesRegex(ValueError, "manual reconciliation"):
            plan_issues(
                "containers",
                {group["key"]: group},
                [existing],
                complete=True,
                client=FakeIssueClient([existing]),
                assessment=assessment(),
            )

    def test_multiple_untracked_legacy_identities_require_manual_reconciliation(self):
        group = language_group()
        issues = [
            legacy_language_issue("alpine/3.24", number=1),
            legacy_language_issue("debian/13.7", number=2),
        ]
        with self.assertRaisesRegex(ValueError, "manual reconciliation"):
            plan_issues(
                "containers",
                {group["key"]: group},
                issues,
                complete=True,
                client=FakeIssueClient(issues),
                assessment=inventoried_assessment("alpine/3.24", "debian/13.7"),
            )

    def test_exact_os_legacy_identity_does_not_block_an_unrelated_new_app_issue(self):
        item = finding(
            "CVE-2026-19445",
            "pkg:apk/alpine/python3@3.14.7-r1",
            "3.14.7-r1",
            "HIGH",
            "alpine/3.24",
            "trivy",
        )
        os_group = {
            **item,
            "observations": [{**item, "name": "base", "platform": "linux/amd64"}],
            "images": [],
            "run_url": "",
        }
        existing = {
            "number": 1,
            "state": "open",
            "user": {"login": BOT},
            "title": "legacy OS issue",
            "body": managed_body("containers", os_group),
        }
        group = language_group()
        actions = plan_issues(
            "containers",
            {os_group["key"]: os_group, group["key"]: group},
            [existing],
            complete=True,
            client=FakeIssueClient([existing]),
            assessment=assessment(),
        )
        self.assertEqual(
            {(action["operation"], action["number"]) for action in actions},
            {("update", 1), ("create", None)},
        )

    def test_tracked_language_issue_migrates_without_creating_a_second_issue(self):
        group = language_group()
        existing = language_issue(language_group("alpine/3.24"))
        action = issue_action(existing, group)
        self.assertEqual(action["operation"], "update")
        self.assertEqual(action["number"], existing["number"])
        self.assertEqual(action["key"], group["key"])
        updated = {**existing, **action["payload"]}
        self.assertEqual((issue_marker(updated) or {})["key"], group["key"])
        tracking = read_state(updated["body"])
        self.assertIsNotNone(tracking)
        if tracking is None:
            self.fail("expected persisted tracking state")
        self.assertEqual(tracking["group"]["distro"], "application")
        self.assertEqual(tracking["group"]["key"], group["key"])
        self.assertTrue(updated["body"].startswith("Human introduction.\n"))
        self.assertTrue(updated["body"].endswith("\nHuman follow-up."))

    def test_migrated_identity_remains_stable_on_the_following_scan(self):
        group = language_group()
        existing = language_issue(language_group("debian/13.7"))
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        self.assertEqual(
            plan_issues(
                "containers",
                {group["key"]: group},
                [updated],
                complete=True,
                client=FakeIssueClient([updated]),
                assessment=assessment(),
            ),
            [],
        )

    def test_language_migration_preserves_manual_closure_opt_out(self):
        group = language_group()
        existing = language_issue(language_group("alpine/3.24"))
        existing["state"] = "closed"
        client = FakeIssueClient([existing])
        client.bot_closed = False
        self.assertEqual(
            plan_issues(
                "containers",
                {group["key"]: group},
                [existing],
                complete=True,
                client=client,
                assessment=assessment(),
            ),
            [],
        )

    def test_multiple_legacy_distro_identities_require_manual_reconciliation(self):
        group = language_group()
        issues = [
            language_issue(language_group("alpine/3.24"), number=1),
            language_issue(language_group("debian/13.7"), number=2),
        ]
        with self.assertRaisesRegex(ValueError, "manual reconciliation"):
            plan_issues(
                "containers",
                {group["key"]: group},
                issues,
                complete=True,
                client=FakeIssueClient(issues),
                assessment=assessment(),
            )

    def test_existing_canonical_and_legacy_issue_collision_is_not_guessed(self):
        group = language_group()
        issues = [
            language_issue(group, number=1),
            language_issue(language_group("alpine/3.24"), number=2),
        ]
        with self.assertRaisesRegex(ValueError, "manual reconciliation"):
            plan_issues(
                "containers",
                {group["key"]: group},
                issues,
                complete=True,
                client=FakeIssueClient(issues),
                assessment=assessment(),
            )

    def test_migration_rejects_a_tracking_group_with_a_different_marker_key(self):
        group = language_group()
        existing = language_issue(language_group("alpine/3.24"))
        existing["body"] = existing["body"].replace(
            '"key":"' + (issue_marker(existing) or {})["key"] + '"',
            '"key":"' + "f" * 64 + '"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            issue_action(existing, group)

    def test_partial_migration_keeps_historical_rows_under_the_canonical_identity(self):
        legacy = language_group("alpine/3.24")
        legacy["observations"].append(
            {**legacy["observations"][0], "platform": "linux/arm64"}
        )
        existing = language_issue(legacy)
        group = language_group()
        current_assessment = assessment()
        current_assessment["targets"].append(
            {
                "name": "base",
                "platform": "linux/arm64",
                "inventory": {"status": "unknown"},
            }
        )
        actions = plan_issues(
            "containers",
            {group["key"]: group},
            [existing],
            complete=False,
            client=FakeIssueClient([existing]),
            assessment=current_assessment,
        )
        self.assertEqual(len(actions), 1)
        tracking = read_state(actions[0]["payload"]["body"])
        self.assertIsNotNone(tracking)
        if tracking is None:
            self.fail("expected persisted tracking state")
        rows = tracking["group"]["observations"]
        self.assertEqual(
            {row["platform"] for row in rows}, {"linux/amd64", "linux/arm64"}
        )
        self.assertTrue(all(row["key"] == group["key"] for row in rows))
        self.assertTrue(all(row["distro"] == "application" for row in rows))
        self.assertIn(
            "| base | linux/arm64 | 5.3.2 | HIGH | trivy, last known |",
            actions[0]["payload"]["body"],
        )

    def test_last_known_observations_are_labelled_in_the_rendered_report(self):
        group = language_group()
        group["observations"][0]["evidence_status"] = "last known"
        body = managed_body("containers", group)
        self.assertIn("last known", body)


class IssuePreflightTests(unittest.TestCase):
    def client(self, responses: list[object]) -> tuple[IssueClient, RecordingOpener]:
        opener = RecordingOpener(responses)
        return (
            IssueClient(
                "token",
                REPOSITORY,
                transport=GitHubTransport("token", opener=opener, sleep=lambda _: None),
            ),
            opener,
        )

    def test_patch_reads_the_exact_issue_before_writing(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        client, opener = self.client(
            [FakeResponse(200, existing), FakeResponse(200, updated)]
        )
        self.assertEqual(client.write(action)["number"], existing["number"])
        self.assertEqual([r.method for r in opener.requests], ["GET", "PATCH"])
        self.assertTrue(opener.requests[0].full_url.endswith("/issues/1"))

    def test_changed_body_title_state_or_ownership_prevents_patch(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        changes = [
            {"body": existing["body"] + "\nNew human note."},
            {"title": "New human title"},
            {"state": "closed"},
            {"user": {"login": "someone-else"}},
            {"number": 2},
            {"number": True},
            {"body": "Ownership markers removed."},
        ]
        for change in changes:
            with self.subTest(change=change):
                client, opener = self.client(
                    [FakeResponse(200, {**existing, **change})]
                )
                with self.assertRaisesRegex(ValueError, "changed|ownership"):
                    client.write(action)
                self.assertEqual([r.method for r in opener.requests], ["GET"])

    def test_ambiguous_patch_returns_an_already_applied_update_without_replay(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                URLError("connection reset"),
                FakeResponse(200, [updated]),
            ]
        )
        self.assertEqual(client.write(action)["number"], existing["number"])
        self.assertEqual([r.method for r in opener.requests], ["GET", "PATCH", "GET"])

    def test_ambiguous_unapplied_patch_is_rechecked_before_its_single_replay(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                URLError("connection reset"),
                FakeResponse(200, [existing]),
                FakeResponse(200, existing),
                FakeResponse(200, updated),
            ]
        )
        self.assertEqual(client.write(action)["number"], existing["number"])
        self.assertEqual(
            [r.method for r in opener.requests], ["GET", "PATCH", "GET", "GET", "PATCH"]
        )

    def test_ambiguous_migration_patch_accepts_the_unchanged_original_marker(self):
        group = language_group()
        existing = language_issue(language_group("alpine/3.24"))
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                URLError("connection reset"),
                FakeResponse(200, [existing]),
                FakeResponse(200, existing),
                FakeResponse(200, updated),
            ]
        )
        self.assertEqual(client.write(action)["number"], existing["number"])
        self.assertEqual(
            [r.method for r in opener.requests], ["GET", "PATCH", "GET", "GET", "PATCH"]
        )

    def test_edit_after_ambiguous_patch_prevents_replay(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        edited = copy.deepcopy(existing)
        edited["body"] += "\nNew human note."
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                URLError("connection reset"),
                FakeResponse(200, [edited]),
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "changed during reconciliation"):
            client.write(action)
        self.assertEqual([r.method for r in opener.requests], ["GET", "PATCH", "GET"])

    def test_edit_during_a_rate_limit_wait_prevents_the_rejected_patch_retry(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        edited = {**existing, "body": existing["body"] + "\nHuman edit during wait."}
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                http_error(429, headers={"Retry-After": "7"}),
                FakeResponse(200, edited),
            ]
        )
        with self.assertRaisesRegex(ValueError, "changed before write"):
            client.write(action)
        self.assertEqual([r.method for r in opener.requests], ["GET", "PATCH", "GET"])

    def test_unchanged_issue_is_revalidated_before_a_rate_limited_patch_retry(self):
        group = language_group()
        existing = language_issue(group)
        action = issue_action(existing, group)
        updated = {**existing, **action["payload"]}
        client, opener = self.client(
            [
                FakeResponse(200, existing),
                http_error(429, headers={"Retry-After": "7"}),
                FakeResponse(200, existing),
                FakeResponse(200, updated),
            ]
        )
        self.assertEqual(client.write(action)["number"], existing["number"])
        self.assertEqual(
            [r.method for r in opener.requests], ["GET", "PATCH", "GET", "PATCH"]
        )
