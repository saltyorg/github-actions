from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .retry import AmbiguousRequestError

API_VERSION = "2026-03-10"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TRANSIENT_STATUS = {429, *range(500, 600)}


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[int], None] = time.sleep,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise ValueError("GitHub token must not be empty")
        self._token = token
        self._opener = opener
        self._sleep = sleep
        self._api_url = api_url.rstrip("/")

    def get_run_attempt(
        self, repository: str, run_id: int, attempt: int
    ) -> dict[str, object]:
        self._validate(repository, run_id)
        if attempt < 1:
            raise ValueError("attempt must be a positive integer")
        result = self._get_json(
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
                self._get_json(
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
        return _object(self._get_json(f"/repos/{repository}/actions/runs/{run_id}"))

    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]:
        self._validate(repository, 1)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
            raise ValueError("head SHA must be 40 hexadecimal characters")
        result = self._get_json(f"/repos/{repository}/commits/{head_sha}/pulls")
        if not isinstance(result, list):
            raise TypeError("GitHub commit pulls response was not an array")
        return [_object(item) for item in result]

    def get_pull(self, repository: str, number: int) -> dict[str, object]:
        self._validate(repository, number)
        return _object(self._get_json(f"/repos/{repository}/pulls/{number}"))

    def rerun_failed_jobs(self, repository: str, run_id: int) -> None:
        self._validate(repository, run_id)
        request = self._request(
            f"/repos/{repository}/actions/runs/{run_id}/rerun-failed-jobs",
            method="POST",
            data=b"{}",
        )
        try:
            with self._opener(request, timeout=30) as response:
                if response.status != 201:
                    raise RuntimeError(
                        f"GitHub rerun request returned HTTP {response.status}"
                    )
        except HTTPError as error:
            if error.code in {409, 422}:
                raise AmbiguousRequestError(
                    f"GitHub rerun request returned HTTP {error.code}"
                ) from error
            raise RuntimeError(
                f"GitHub rerun request returned HTTP {error.code}"
            ) from error
        except URLError as error:
            raise AmbiguousRequestError(
                "GitHub rerun request ended without a definitive response"
            ) from error

    def _get_json(self, path: str) -> object:
        request = self._request(path)
        for request_number in range(3):
            try:
                with self._opener(request, timeout=30) as response:
                    if response.status != 200:
                        raise RuntimeError(
                            f"GitHub read request returned HTTP {response.status}"
                        )
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as error:
                if error.code in TRANSIENT_STATUS and request_number < 2:
                    self._sleep(2**request_number)
                    continue
                raise RuntimeError(
                    f"GitHub read request returned HTTP {error.code}"
                ) from error
            except URLError as error:
                if request_number < 2:
                    self._sleep(2**request_number)
                    continue
                raise RuntimeError(
                    "GitHub read request failed after three attempts"
                ) from error
        raise AssertionError("unreachable")

    def _request(
        self, path: str, *, method: str = "GET", data: bytes | None = None
    ) -> Request:
        return Request(
            f"{self._api_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "saltyorg/github-actions",
                "X-GitHub-Api-Version": API_VERSION,
            },
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
