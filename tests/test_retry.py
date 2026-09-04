from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.retry import (
    AmbiguousRequestError,
    RetryCoordinator,
    decide_retry,
    execution_attempt,
)


def workflow_run_event(
    *,
    run_attempt: int = 1,
    conclusion: str = "failure",
    event: str = "pull_request",
    head_sha: str = "a" * 40,
    pull_requests: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "repository": {"full_name": "saltyorg/Sandbox"},
        "workflow_run": {
            "id": 1234,
            "run_attempt": run_attempt,
            "status": "completed",
            "conclusion": conclusion,
            "event": event,
            "head_sha": head_sha,
            "pull_requests": pull_requests or [],
        },
    }


class FakeGitHubClient:
    def __init__(self) -> None:
        self.attempts: dict[int, dict[str, object]] = {
            1: {"run_attempt": 1, "conclusion": "failure"}
        }
        self.jobs: list[dict[str, object]] = [
            {"name": "radarr", "conclusion": "failure"}
        ]
        self.current_runs: list[dict[str, object]] = [
            {"run_attempt": 1, "status": "completed", "conclusion": "failure"}
        ]
        self.commit_pulls: list[dict[str, object]] = []
        self.pulls: dict[int, dict[str, object]] = {}
        self.rerun_calls: list[tuple[str, int]] = []
        self.rerun_error: Exception | None = None

    def get_run_attempt(
        self, repository: str, run_id: int, attempt: int
    ) -> dict[str, object]:
        return self.attempts[attempt]

    def list_run_jobs(
        self, repository: str, run_id: int, attempt: int
    ) -> list[dict[str, object]]:
        return self.jobs

    def get_run(self, repository: str, run_id: int) -> dict[str, object]:
        if len(self.current_runs) > 1:
            return self.current_runs.pop(0)
        return self.current_runs[0]

    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]:
        return self.commit_pulls

    def get_pull(self, repository: str, number: int) -> dict[str, object]:
        return self.pulls[number]

    def rerun_failed_jobs(self, repository: str, run_id: int) -> None:
        self.rerun_calls.append((repository, run_id))
        if self.rerun_error:
            raise self.rerun_error


class ExecutionAttemptTests(unittest.TestCase):
    def test_approval_placeholder_does_not_count_as_execution(self) -> None:
        self.assertEqual(execution_attempt(3, "action_required"), 2)

    def test_regular_first_attempt_counts_as_first_execution(self) -> None:
        self.assertEqual(execution_attempt(1, "failure"), 1)


class RetryPolicyTests(unittest.TestCase):
    def test_retry_budget_counts_executions_not_approval_placeholder(self) -> None:
        cases = [
            (1, "failure", "failure", "retry", "retryable-failure", 1),
            (2, "failure", "failure", "retry", "retryable-failure", 2),
            (3, "failure", "failure", "terminal", "attempt-limit", 3),
            (2, "action_required", "failure", "retry", "retryable-failure", 1),
            (3, "action_required", "failure", "retry", "retryable-failure", 2),
            (4, "action_required", "failure", "terminal", "attempt-limit", 3),
        ]

        for (
            run_attempt,
            first_conclusion,
            conclusion,
            decision,
            reason,
            actual,
        ) in cases:
            with self.subTest(
                run_attempt=run_attempt, first_conclusion=first_conclusion
            ):
                result = decide_retry(
                    run_attempt=run_attempt,
                    first_conclusion=first_conclusion,
                    workflow_conclusion=conclusion,
                    jobs=[{"name": "radarr", "conclusion": "failure"}],
                    non_retryable_jobs=set(),
                )
                self.assertEqual(result.decision, decision)
                self.assertEqual(result.reason, reason)
                self.assertEqual(result.execution_attempt, actual)

    def test_exact_non_retryable_failure_is_terminal(self) -> None:
        result = decide_retry(
            run_attempt=1,
            first_conclusion="failure",
            workflow_conclusion="failure",
            jobs=[
                {"name": "saltbox-lint-extra", "conclusion": "failure"},
                {"name": "saltbox-lint", "conclusion": "failure"},
            ],
            non_retryable_jobs={"saltbox-lint"},
        )

        self.assertEqual(result.decision, "terminal")
        self.assertEqual(result.reason, "non-retryable-job")
        self.assertEqual(result.failed_jobs, ("saltbox-lint", "saltbox-lint-extra"))

    def test_timed_out_non_retryable_job_remains_retryable(self) -> None:
        result = decide_retry(
            run_attempt=1,
            first_conclusion="timed_out",
            workflow_conclusion="timed_out",
            jobs=[{"name": "saltbox-lint", "conclusion": "timed_out"}],
            non_retryable_jobs={"saltbox-lint"},
        )

        self.assertEqual(result.decision, "retry")
        self.assertEqual(result.reason, "retryable-timeout")

    def test_failure_without_rerunnable_jobs_is_terminal(self) -> None:
        result = decide_retry(
            run_attempt=1,
            first_conclusion="failure",
            workflow_conclusion="failure",
            jobs=[],
            non_retryable_jobs=set(),
        )

        self.assertEqual(result.decision, "terminal")
        self.assertEqual(result.reason, "no-rerunnable-jobs")


class RetryCoordinatorTests(unittest.TestCase):
    def test_approved_pull_request_gets_third_execution(self) -> None:
        client = FakeGitHubClient()
        client.attempts[1] = {"run_attempt": 1, "conclusion": "action_required"}
        client.current_runs = [
            {"run_attempt": 3, "status": "completed", "conclusion": "failure"}
        ]
        sleeps: list[int] = []
        coordinator = RetryCoordinator(client, sleeps.append)

        result = coordinator.handle(
            workflow_run_event(run_attempt=3, event="push"), set()
        )

        self.assertEqual(result.decision, "retried")
        self.assertEqual(result.execution_attempt, 2)
        self.assertEqual(sleeps, [60])
        self.assertEqual(client.rerun_calls, [("saltyorg/Sandbox", 1234)])

    def test_terminal_failure_does_not_sleep_or_rerun(self) -> None:
        client = FakeGitHubClient()
        client.attempts[1] = {"run_attempt": 1, "conclusion": "action_required"}
        sleeps: list[int] = []
        coordinator = RetryCoordinator(client, sleeps.append)

        result = coordinator.handle(
            workflow_run_event(run_attempt=4, event="push"), set()
        )

        self.assertEqual(result.decision, "terminal")
        self.assertEqual(result.reason, "attempt-limit")
        self.assertEqual(sleeps, [])
        self.assertEqual(client.rerun_calls, [])

    def test_closed_pull_request_placeholder_is_superseded(self) -> None:
        client = FakeGitHubClient()
        client.jobs = []
        client.commit_pulls = [{"number": 556}]
        client.pulls[556] = {
            "number": 556,
            "state": "closed",
            "merged_at": "2026-09-02T06:51:50Z",
            "head": {"sha": "b" * 40},
        }
        coordinator = RetryCoordinator(client, lambda _: None)

        result = coordinator.handle(workflow_run_event(), set())

        self.assertEqual(result.decision, "superseded")
        self.assertEqual(result.reason, "closed-pull-request")
        self.assertEqual(client.rerun_calls, [])

    def test_obsolete_pull_request_commit_is_superseded(self) -> None:
        client = FakeGitHubClient()
        client.pulls[42] = {
            "number": 42,
            "state": "open",
            "merged_at": None,
            "head": {"sha": "b" * 40},
        }
        coordinator = RetryCoordinator(client, lambda _: None)

        result = coordinator.handle(
            workflow_run_event(pull_requests=[{"number": 42}]), set()
        )

        self.assertEqual(result.decision, "superseded")
        self.assertEqual(result.reason, "obsolete-head")
        self.assertEqual(client.rerun_calls, [])

    def test_newer_attempt_after_cooldown_supersedes_handler(self) -> None:
        client = FakeGitHubClient()
        client.current_runs = [
            {"run_attempt": 2, "status": "in_progress", "conclusion": None}
        ]
        coordinator = RetryCoordinator(client, lambda _: None)

        result = coordinator.handle(
            workflow_run_event(run_attempt=1, event="push"), set()
        )

        self.assertEqual(result.decision, "superseded")
        self.assertEqual(result.reason, "newer-attempt")
        self.assertEqual(client.rerun_calls, [])

    def test_ambiguous_rerun_response_is_reconciled(self) -> None:
        client = FakeGitHubClient()
        client.current_runs = [
            {"run_attempt": 1, "status": "completed", "conclusion": "failure"},
            {"run_attempt": 2, "status": "queued", "conclusion": None},
        ]
        client.rerun_error = AmbiguousRequestError("rerun response was lost")
        coordinator = RetryCoordinator(client, lambda _: None)

        result = coordinator.handle(
            workflow_run_event(run_attempt=1, event="push"), set()
        )

        self.assertEqual(result.decision, "retried")
        self.assertEqual(result.reason, "rerun-reconciled")
        self.assertEqual(client.rerun_calls, [("saltyorg/Sandbox", 1234)])

    def test_unconfirmed_ambiguous_rerun_response_fails(self) -> None:
        client = FakeGitHubClient()
        client.rerun_error = AmbiguousRequestError("rerun response was lost")
        coordinator = RetryCoordinator(client, lambda _: None)

        with self.assertRaisesRegex(AmbiguousRequestError, "could not be reconciled"):
            coordinator.handle(workflow_run_event(event="push"), set())


if __name__ == "__main__":
    unittest.main()
