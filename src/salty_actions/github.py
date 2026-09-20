from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlencode
from urllib.request import urlopen

from .transport import GitHubTransport

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        api_url: str = "https://api.github.com",
    ) -> None:
        self._transport = GitHubTransport(
            token, opener=opener, sleep=sleep, now=now, api_url=api_url
        )

    def get_run_attempt(
        self, repository: str, run_id: int, attempt: int
    ) -> dict[str, object]:
        self._validate(repository, run_id)
        if attempt < 1:
            raise ValueError("attempt must be a positive integer")
        result = self._transport.get_json(
            f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}"
        )
        return _object(result)

    def list_run_jobs(
        self, repository: str, run_id: int, attempt: int
    ) -> list[dict[str, object]]:
        self._validate(repository, run_id)
        if attempt < 1:
            raise ValueError("attempt must be a positive integer")

        jobs: list[dict[str, object]] = []
        page = 1
        while True:
            query = urlencode({"per_page": 100, "page": page})
            result = _object(
                self._transport.get_json(
                    f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?{query}"
                )
            )
            page_jobs = result.get("jobs")
            if not isinstance(page_jobs, list):
                raise TypeError("GitHub jobs response did not contain a jobs array")
            jobs.extend(_object(item) for item in page_jobs)
            total_count = result.get("total_count")
            if not isinstance(total_count, int):
                raise TypeError("GitHub jobs response did not contain total_count")
            if len(jobs) >= total_count:
                return jobs
            if not page_jobs:
                raise RuntimeError("GitHub jobs pagination ended before total_count")
            page += 1

    def get_run(self, repository: str, run_id: int) -> dict[str, object]:
        self._validate(repository, run_id)
        return _object(
            self._transport.get_json(f"/repos/{repository}/actions/runs/{run_id}")
        )

    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]:
        self._validate(repository, 1)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
            raise ValueError("head SHA must be 40 hexadecimal characters")
        result = self._transport.get_json(
            f"/repos/{repository}/commits/{head_sha}/pulls"
        )
        if not isinstance(result, list):
            raise TypeError("GitHub commit pulls response was not an array")
        return [_object(item) for item in result]

    def get_pull(self, repository: str, number: int) -> dict[str, object]:
        self._validate(repository, number)
        return _object(
            self._transport.get_json(f"/repos/{repository}/pulls/{number}")
        )

    def list_branch_pulls(
        self, repository: str, head_repository: str, head_branch: str
    ) -> list[dict[str, object]]:
        self._validate(repository, 1)
        self._validate(head_repository, 1)
        if not isinstance(head_branch, str) or not head_branch:
            raise ValueError("head branch must be a non-empty string")
        head_owner = head_repository.split("/", 1)[0]
        pulls: list[dict[str, object]] = []
        page = 1
        while True:
            query = urlencode(
                {
                    "state": "all",
                    "head": f"{head_owner}:{head_branch}",
                    "per_page": 100,
                    "page": page,
                }
            )
            result = self._transport.get_json(f"/repos/{repository}/pulls?{query}")
            if not isinstance(result, list):
                raise TypeError("GitHub branch pulls response was not an array")
            pulls.extend(_object(item) for item in result)
            if len(result) < 100:
                return pulls
            page += 1

    def rerun_failed_jobs(self, repository: str, run_id: int) -> None:
        self._validate(repository, run_id)
        self._transport.post_mutation(
            f"/repos/{repository}/actions/runs/{run_id}/rerun-failed-jobs"
        )

    @staticmethod
    def _validate(repository: str, positive_number: int) -> None:
        if not REPOSITORY_RE.fullmatch(repository):
            raise ValueError("repository must use owner/name format")
        if (
            not isinstance(positive_number, int)
            or isinstance(positive_number, bool)
            or positive_number < 1
        ):
            raise ValueError("identifier must be a positive integer")


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("GitHub response was not an object")
    return cast(dict[str, object], value)
