from __future__ import annotations

import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .github import REPOSITORY_RE, GitHubClient
from .transport import AmbiguousRequestError

MAX_EXECUTIONS = 3


@dataclass(frozen=True)
class RetryDecision:
    decision: str
    reason: str
    execution_attempt: int
    failed_jobs: tuple[str, ...]


class GitHubRetryClient(Protocol):
    def get_run_attempt(
        self, repository: str, run_id: int, attempt: int
    ) -> dict[str, object]: ...

    def list_run_jobs(
        self, repository: str, run_id: int, attempt: int
    ) -> list[dict[str, object]]: ...

    def get_run(self, repository: str, run_id: int) -> dict[str, object]: ...

    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]: ...

    def get_pull(self, repository: str, number: int) -> dict[str, object]: ...

    def list_branch_pulls(
        self, repository: str, head_repository: str, head_branch: str
    ) -> list[dict[str, object]]: ...

    def rerun_failed_jobs(self, repository: str, run_id: int) -> None: ...


def execution_attempt(run_attempt: int, first_conclusion: str) -> int:
    """Return the number of actual executions represented by a raw attempt."""
    return run_attempt - (1 if first_conclusion == "action_required" else 0)


def decide_retry(
    *,
    run_attempt: int,
    first_conclusion: str,
    workflow_conclusion: str,
    jobs: Iterable[Mapping[str, object]],
    non_retryable_jobs: set[str],
) -> RetryDecision:
    """Classify a completed workflow attempt without causing side effects."""
    actual_attempt = execution_attempt(run_attempt, first_conclusion)
    job_list = tuple(jobs)
    failed_jobs = tuple(
        sorted(
            str(job["name"])
            for job in job_list
            if job.get("conclusion") in {"failure", "timed_out"}
        )
    )
    deterministic_failures = {
        str(job["name"]) for job in job_list if job.get("conclusion") == "failure"
    } & non_retryable_jobs

    if deterministic_failures:
        return RetryDecision(
            "terminal", "non-retryable-job", actual_attempt, failed_jobs
        )
    if not failed_jobs:
        return RetryDecision(
            "terminal", "no-rerunnable-jobs", actual_attempt, failed_jobs
        )
    if actual_attempt >= MAX_EXECUTIONS:
        return RetryDecision("terminal", "attempt-limit", actual_attempt, failed_jobs)

    reason = (
        "retryable-timeout"
        if workflow_conclusion == "timed_out"
        else "retryable-failure"
    )
    return RetryDecision("retry", reason, actual_attempt, failed_jobs)


class RetryCoordinator:
    def __init__(
        self,
        client: GitHubRetryClient,
        sleep: Callable[[int], None],
    ) -> None:
        self.client = client
        self.sleep = sleep

    def handle(
        self,
        payload: Mapping[str, object],
        non_retryable_jobs: set[str],
    ) -> RetryDecision:
        repository_data = _mapping(payload.get("repository"), "repository")
        workflow_run = _mapping(payload.get("workflow_run"), "workflow_run")
        repository = _string(repository_data.get("full_name"), "repository.full_name")
        run_id = _integer(workflow_run.get("id"), "workflow_run.id")
        run_attempt = _integer(
            workflow_run.get("run_attempt"), "workflow_run.run_attempt"
        )
        conclusion = _string(workflow_run.get("conclusion"), "workflow_run.conclusion")
        event = _string(workflow_run.get("event"), "workflow_run.event")
        head_sha = _string(workflow_run.get("head_sha"), "workflow_run.head_sha")

        if event in {"pull_request", "pull_request_target"}:
            superseded_reason = self._pull_request_supersession(
                repository, workflow_run, head_sha
            )
            if superseded_reason:
                return RetryDecision("superseded", superseded_reason, run_attempt, ())

        if run_attempt == 1:
            first_conclusion = conclusion
        else:
            first_attempt = self.client.get_run_attempt(repository, run_id, 1)
            first_conclusion = _string(
                first_attempt.get("conclusion"), "attempt[1].conclusion"
            )

        jobs = self.client.list_run_jobs(repository, run_id, run_attempt)
        policy = decide_retry(
            run_attempt=run_attempt,
            first_conclusion=first_conclusion,
            workflow_conclusion=conclusion,
            jobs=jobs,
            non_retryable_jobs=non_retryable_jobs,
        )
        if policy.decision != "retry":
            return policy

        self.sleep(60)
        current = self.client.get_run(repository, run_id)
        if (
            current.get("run_attempt") != run_attempt
            or current.get("status") != "completed"
            or current.get("conclusion") != conclusion
        ):
            return RetryDecision(
                "superseded",
                "newer-attempt",
                policy.execution_attempt,
                policy.failed_jobs,
            )

        try:
            self.client.rerun_failed_jobs(repository, run_id)
        except AmbiguousRequestError as error:
            reconciled = self.client.get_run(repository, run_id)
            if (
                _integer(reconciled.get("run_attempt"), "workflow_run.run_attempt")
                > run_attempt
            ):
                return RetryDecision(
                    "retried",
                    "rerun-reconciled",
                    policy.execution_attempt,
                    policy.failed_jobs,
                )
            raise AmbiguousRequestError(
                "rerun response was ambiguous and could not be reconciled"
            ) from error

        return RetryDecision(
            "retried",
            policy.reason,
            policy.execution_attempt,
            policy.failed_jobs,
        )

    def _pull_request_supersession(
        self,
        repository: str,
        workflow_run: Mapping[str, object],
        head_sha: str,
    ) -> str | None:
        pull_requests = workflow_run.get("pull_requests")
        candidates = pull_requests if isinstance(pull_requests, list) else []
        if not candidates:
            candidates = self.client.list_commit_pulls(repository, head_sha)
        if candidates:
            if len(candidates) != 1:
                return None
            candidate = _mapping(candidates[0], "workflow_run.pull_requests[0]")
            number = _integer(candidate.get("number"), "pull_request.number")
            pull_request = self.client.get_pull(repository, number)
        elif workflow_run.get("event") == "pull_request":
            pull_request = self._branch_pull(repository, workflow_run)
            if pull_request is None:
                return None
        else:
            return None

        if pull_request.get("state") == "closed" or pull_request.get("merged_at"):
            return "closed-pull-request"

        head = _mapping(pull_request.get("head"), "pull_request.head")
        if head.get("sha") != head_sha:
            return "obsolete-head"
        return None

    def _branch_pull(
        self, repository: str, workflow_run: Mapping[str, object]
    ) -> dict[str, object] | None:
        source = workflow_run.get("head_repository")
        if not isinstance(source, Mapping):
            return None
        source_name = source.get("full_name")
        source_id = source.get("id")
        branch = workflow_run.get("head_branch")
        created_at = _timestamp(workflow_run.get("created_at"))
        if (
            not isinstance(source_name, str)
            or not REPOSITORY_RE.fullmatch(source_name)
            or not isinstance(source_id, int)
            or isinstance(source_id, bool)
            or source_id < 1
            or not isinstance(branch, str)
            or not branch
            or created_at is None
        ):
            return None

        def matches(pull: Mapping[str, object]) -> bool | None:
            """Return None when incomplete metadata leaves identity uncertain."""
            number = pull.get("number")
            state = pull.get("state")
            if (
                not isinstance(number, int)
                or isinstance(number, bool)
                or number < 1
                or state not in ("open", "closed")
            ):
                return None
            head = pull.get("head")
            base = pull.get("base")
            if not isinstance(head, Mapping) or not isinstance(base, Mapping):
                return None
            head_repo = head.get("repo")
            base_repo = base.get("repo")
            if not isinstance(head_repo, Mapping) or not isinstance(base_repo, Mapping):
                return None
            target_name = base_repo.get("full_name")
            head_sha = head.get("sha")
            if (
                not isinstance(head_repo.get("id"), int)
                or isinstance(head_repo.get("id"), bool)
                or not isinstance(head.get("ref"), str)
                or not head.get("ref")
                or not isinstance(target_name, str)
                or not REPOSITORY_RE.fullmatch(target_name)
            ):
                return None
            if (
                head_repo.get("id") != source_id
                or head.get("ref") != branch
                or target_name.casefold() != repository.casefold()
            ):
                return False
            if not isinstance(head_sha, str) or not re.fullmatch(
                r"[0-9a-fA-F]{40}", head_sha
            ):
                return None
            opened_at = _timestamp(pull.get("created_at"))
            if opened_at is None:
                return None
            if opened_at > created_at:
                return False
            # A reused branch may have older, already-closed PRs. Match the
            # original run creation time, not its much later completion time.
            if pull.get("closed_at") is not None:
                closed_at = _timestamp(pull["closed_at"])
                if closed_at is None:
                    return None
                if closed_at < created_at:
                    return False
            elif state == "closed":
                return None
            return True

        candidates = []
        for pull in self.client.list_branch_pulls(repository, source_name, branch):
            match = matches(pull)
            if match is None:
                return None
            if match:
                candidates.append(pull)
        if len(candidates) != 1:
            return None
        number = _integer(candidates[0].get("number"), "pull_request.number")
        pull = self.client.get_pull(repository, number)
        return pull if pull.get("number") == number and matches(pull) is True else None


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    return value


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo is not None else None


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def run_action(
    env: Mapping[str, str],
    *,
    client: GitHubRetryClient,
    sleep: Callable[[int], None] = time.sleep,
) -> RetryDecision:
    event_path = Path(_env(env, "GITHUB_EVENT_PATH"))
    output_path = Path(_env(env, "GITHUB_OUTPUT"))
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("GitHub event payload must be an object")
    non_retryable_jobs = {
        line.strip()
        for line in env.get("NON_RETRYABLE_JOBS", "").splitlines()
        if line.strip()
    }
    result = RetryCoordinator(client, sleep).handle(payload, non_retryable_jobs)
    outputs = {
        "decision": result.decision,
        "reason": result.reason,
        "execution-attempt": str(result.execution_attempt),
        "failed-jobs": json.dumps(result.failed_jobs, separators=(",", ":")),
    }
    with output_path.open("a", encoding="utf-8") as output:
        for name, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise ValueError(f"output {name} must be a single line")
            output.write(f"{name}={value}\n")
    print(
        f"Retry decision: {result.decision} "
        f"({result.reason}), execution {result.execution_attempt}"
    )
    return result


def main() -> int:
    try:
        token = _env(os.environ, "GITHUB_TOKEN")
        run_action(os.environ, client=GitHubClient(token))
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        print(f"::error::Retry orchestration failed: {error}", file=sys.stderr)
        return 1
    return 0


def _env(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
