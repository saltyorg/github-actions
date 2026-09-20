from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.retry import RetryCoordinator

from .test_retry import FakeGitHubClient


def expired_approval_event() -> dict[str, Any]:
    """The unapproved run for Saltbox PR #515 completed a month after merging."""
    return {
        "repository": {"full_name": "saltyorg/Saltbox"},
        "workflow_run": {
            "id": 32403149082,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "failure",
            "run_attempt": 1,
            "head_sha": "d30a4cf3b23532f8588c7af043120df75bf7479d",
            "head_branch": "cloudplow-sqlite-sidecar-excludes",
            "head_repository": {"id": 665367445, "full_name": "balogan/Saltbox"},
            "created_at": "2026-08-20T18:25:56Z",
            "updated_at": "2026-09-19T18:26:46Z",
            "pull_requests": [],
        },
    }


def branch_pull() -> dict[str, Any]:
    return {
        "number": 515,
        "state": "closed",
        "created_at": "2026-08-20T18:25:52Z",
        "closed_at": "2026-08-20T19:34:36Z",
        "merged_at": "2026-08-20T19:34:36Z",
        "head": {
            "sha": "9e3c4adccb340ca4e4cd1af53cb8c8216d375b77",
            "ref": "cloudplow-sqlite-sidecar-excludes",
            "repo": {"id": 665367445, "full_name": "balogan/Saltbox"},
        },
        "base": {"ref": "master", "repo": {"full_name": "saltyorg/Saltbox"}},
    }


class BranchPullResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = expired_approval_event()
        self.client = FakeGitHubClient()
        self.client.jobs = []
        self.client.branch_pulls = [branch_pull()]
        self.client.pulls[515] = branch_pull()
        self.sleeps: list[int] = []
        self.coordinator = RetryCoordinator(self.client, self.sleeps.append)

    def assert_unresolved(self) -> None:
        result = self.coordinator.handle(self.payload, set())
        self.assertEqual(
            (result.decision, result.reason), ("terminal", "no-rerunnable-jobs")
        )
        self.assertEqual(self.client.rerun_calls, [])
        self.assertEqual(self.sleeps, [])

    def test_expired_approval_for_merged_pr_is_superseded(self) -> None:
        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(
            (result.decision, result.reason), ("superseded", "closed-pull-request")
        )
        self.assertEqual(result.failed_jobs, ())
        self.assertEqual(self.client.rerun_calls, [])
        self.assertEqual(self.sleeps, [])
        self.assertEqual(
            self.client.branch_pull_calls,
            [
                ("saltyorg/Saltbox", "balogan/Saltbox", "cloudplow-sqlite-sidecar-excludes")
            ],
        )

    def test_open_pr_with_newer_head_is_superseded(self) -> None:
        self.client.branch_pulls[0].update(state="open", closed_at=None, merged_at=None)
        self.client.pulls[515] = copy.deepcopy(self.client.branch_pulls[0])

        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(
            (result.decision, result.reason), ("superseded", "obsolete-head")
        )
        self.assertEqual(self.client.rerun_calls, [])
        self.assertEqual(self.sleeps, [])

    def test_current_open_pr_with_failed_jobs_still_retries(self) -> None:
        pull = self.client.branch_pulls[0]
        pull.update(state="open", closed_at=None, merged_at=None)
        pull["head"]["sha"] = self.payload["workflow_run"]["head_sha"]
        self.client.pulls[515] = copy.deepcopy(pull)
        self.client.jobs = [{"name": "radarr", "conclusion": "failure"}]

        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(result.decision, "retried")
        self.assertEqual(self.client.rerun_calls, [("saltyorg/Saltbox", 32403149082)])
        self.assertEqual(self.sleeps, [60])

    def test_current_open_pr_without_jobs_remains_terminal(self) -> None:
        pull = self.client.branch_pulls[0]
        pull.update(state="open", closed_at=None, merged_at=None)
        pull["head"]["sha"] = self.payload["workflow_run"]["head_sha"]
        self.client.pulls[515] = copy.deepcopy(pull)

        self.assert_unresolved()

    def test_no_branch_match_keeps_terminal_classification(self) -> None:
        self.client.branch_pulls = []
        self.assert_unresolved()

    def test_multiple_matching_prs_are_not_guessed(self) -> None:
        other = branch_pull()
        other["number"] = 516
        self.client.branch_pulls.append(other)
        self.assert_unresolved()

    def test_incomplete_candidate_cannot_make_a_closed_pr_look_unique(self) -> None:
        self.client.jobs = [{"name": "saltbox-lint", "conclusion": "failure"}]
        for missing in ("created_at", "source_id", "head_sha", "closed_at"):
            with self.subTest(missing=missing):
                other = branch_pull()
                other.update(number=516, state="open", closed_at=None, merged_at=None)
                other["head"]["sha"] = self.payload["workflow_run"]["head_sha"]
                other["base"]["ref"] = "another-base-branch"
                if missing == "source_id":
                    other["head"]["repo"].pop("id")
                elif missing == "head_sha":
                    other["head"].pop("sha")
                elif missing == "closed_at":
                    other.update(state="closed", closed_at=None)
                else:
                    other.pop(missing)
                self.client.branch_pulls = [branch_pull(), other]

                result = self.coordinator.handle(self.payload, {"saltbox-lint"})

                self.assertEqual(
                    (result.decision, result.reason), ("terminal", "non-retryable-job")
                )
                self.assertEqual(result.failed_jobs, ("saltbox-lint",))
                self.assertEqual(self.client.rerun_calls, [])
                self.assertEqual(self.sleeps, [])

    def test_unrelated_candidate_with_missing_dates_does_not_block_resolution(self) -> None:
        other = branch_pull()
        other["head"]["repo"]["id"] = 665367446
        other.pop("created_at")
        self.client.branch_pulls.append(other)

        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(result.reason, "closed-pull-request")

    def test_branch_reuse_selects_only_pr_alive_when_run_was_created(self) -> None:
        earlier = branch_pull()
        earlier.update(number=500, closed_at="2026-08-20T18:25:55Z")
        later = branch_pull()
        later.update(number=520, created_at="2026-08-20T18:25:57Z")
        self.client.branch_pulls = [earlier, branch_pull(), later]

        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(
            (result.decision, result.reason), ("superseded", "closed-pull-request")
        )

    def test_pr_outside_original_run_lifetime_does_not_match(self) -> None:
        for field, value in [
            ("created_at", "2026-08-20T18:25:57Z"),
            ("closed_at", "2026-08-20T18:25:55Z"),
        ]:
            with self.subTest(field=field):
                pull = branch_pull()
                pull[field] = value
                self.client.branch_pulls = [pull]
                self.assert_unresolved()

    def test_source_and_destination_identity_must_match(self) -> None:
        for key in ("source", "destination", "branch"):
            with self.subTest(key=key):
                pull = branch_pull()
                if key == "source":
                    pull["head"]["repo"]["id"] = 665367446
                elif key == "destination":
                    pull["base"]["repo"]["full_name"] = "another/Saltbox"
                else:
                    pull["head"]["ref"] = "different-branch"
                self.client.branch_pulls = [pull]
                self.assert_unresolved()

    def test_source_repository_id_must_be_an_integer(self) -> None:
        self.client.branch_pulls[0]["head"]["repo"]["id"] = 665367445.0
        self.assert_unresolved()

    def test_missing_or_malformed_run_metadata_skips_lookup(self) -> None:
        cases = [
            ("head_repository", None),
            ("head_repository", {"id": True, "full_name": "balogan/Saltbox"}),
            ("head_repository", {"id": 0, "full_name": "balogan/Saltbox"}),
            ("head_repository", {"id": 665367445, "full_name": "invalid"}),
            ("head_repository", {"id": 665367445, "full_name": None}),
            ("head_branch", ""),
            ("head_branch", 5),
            ("created_at", None),
            ("created_at", "invalid"),
            ("created_at", "2026-08-20T18:25:56"),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.payload = expired_approval_event()
                self.payload["workflow_run"][field] = value
                self.assert_unresolved()
                self.assertEqual(self.client.branch_pull_calls, [])

    def test_incomplete_pr_metadata_does_not_suppress_failure(self) -> None:
        for field, value in [
            ("head", None),
            ("base", None),
            ("created_at", "invalid"),
            ("closed_at", "invalid"),
        ]:
            with self.subTest(field=field):
                pull = branch_pull()
                pull[field] = value
                self.client.branch_pulls = [pull]
                self.assert_unresolved()

    def test_incomplete_refreshed_pr_does_not_become_obsolete(self) -> None:
        for field, value in [
            ("state", None),
            ("closed_at", None),
            ("number", True),
            ("head_sha", None),
            ("head_sha", "invalid"),
        ]:
            with self.subTest(field=field, value=value):
                pull = branch_pull()
                if field == "head_sha":
                    pull.update(state="open", closed_at=None, merged_at=None)
                    pull["head"]["sha"] = value
                else:
                    pull[field] = value
                self.client.pulls[515] = pull
                self.assert_unresolved()

    def test_pr_lifetime_boundaries_are_inclusive_and_timezone_aware(self) -> None:
        for timestamp in ("2026-08-20T18:25:56Z", "2026-08-20T20:25:56+02:00"):
            with self.subTest(timestamp=timestamp):
                pull = branch_pull()
                pull.update(created_at=timestamp, closed_at=timestamp)
                self.client.branch_pulls = [pull]
                self.client.pulls[515] = copy.deepcopy(pull)

                result = self.coordinator.handle(self.payload, set())

                self.assertEqual(result.reason, "closed-pull-request")

    def test_refreshed_pr_state_is_used(self) -> None:
        self.client.branch_pulls[0].update(state="open", closed_at=None, merged_at=None)

        result = self.coordinator.handle(self.payload, set())

        self.assertEqual(
            (result.decision, result.reason), ("superseded", "closed-pull-request")
        )

    def test_refreshed_pr_with_different_identity_is_not_used(self) -> None:
        self.client.pulls[515]["head"]["repo"]["id"] = 665367446
        self.assert_unresolved()

    def test_existing_event_or_commit_association_takes_precedence(self) -> None:
        for source in ("event", "commit"):
            with self.subTest(source=source):
                self.payload = expired_approval_event()
                if source == "event":
                    self.payload["workflow_run"]["pull_requests"] = [{"number": 515}]
                else:
                    self.client.commit_pulls = [{"number": 515}]

                result = self.coordinator.handle(self.payload, set())

                self.assertEqual(result.reason, "closed-pull-request")
                self.assertEqual(self.client.branch_pull_calls, [])

    def test_ambiguous_existing_association_does_not_invoke_fallback(self) -> None:
        for source in ("event", "commit"):
            with self.subTest(source=source):
                self.payload = expired_approval_event()
                candidates = [{"number": 515}, {"number": 516}]
                if source == "event":
                    self.payload["workflow_run"]["pull_requests"] = candidates
                else:
                    self.client.commit_pulls = candidates
                self.assert_unresolved()
                self.assertEqual(self.client.branch_pull_calls, [])

    def test_other_events_do_not_invoke_branch_fallback(self) -> None:
        for event in ("push", "workflow_dispatch", "pull_request_target"):
            with self.subTest(event=event):
                self.payload["workflow_run"]["event"] = event
                self.assert_unresolved()
                self.assertEqual(self.client.branch_pull_calls, [])

    def test_branch_lookup_errors_remain_observable(self) -> None:
        self.client.branch_pull_error = RuntimeError(
            "GitHub read request returned HTTP 403"
        )

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            self.coordinator.handle(self.payload, set())

        self.assertEqual(self.client.rerun_calls, [])


if __name__ == "__main__":
    unittest.main()
