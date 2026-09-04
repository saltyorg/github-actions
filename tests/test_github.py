from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.github import GitHubClient
from salty_actions.retry import AmbiguousRequestError

from .http_fakes import FakeResponse, RecordingOpener


class GitHubClientTests(unittest.TestCase):
    def test_attempt_jobs_are_paginated_without_falling_back_to_latest(self) -> None:
        first_page = [
            {"name": f"job-{index}", "conclusion": "success"} for index in range(100)
        ]
        second_page = [{"name": "saltbox-lint", "conclusion": "failure"}]
        opener = RecordingOpener(
            [
                FakeResponse(200, {"total_count": 101, "jobs": first_page}),
                FakeResponse(200, {"total_count": 101, "jobs": second_page}),
            ]
        )
        client = GitHubClient("secret-token", opener=opener, sleep=lambda _: None)

        jobs = client.list_run_jobs("saltyorg/Sandbox", 1234, 3)

        self.assertEqual(len(jobs), 101)
        self.assertEqual(jobs[-1]["name"], "saltbox-lint")
        self.assertEqual(
            opener.requests[0].full_url,
            "https://api.github.com/repos/saltyorg/Sandbox/actions/runs/1234/attempts/3/jobs?per_page=100&page=1",
        )
        self.assertEqual(
            opener.requests[1].full_url,
            "https://api.github.com/repos/saltyorg/Sandbox/actions/runs/1234/attempts/3/jobs?per_page=100&page=2",
        )

    def test_rerun_is_one_post_to_failed_jobs_endpoint(self) -> None:
        opener = RecordingOpener([FakeResponse(201)])
        client = GitHubClient("secret-token", opener=opener, sleep=lambda _: None)

        client.rerun_failed_jobs("saltyorg/Saltbox", 5678)

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].method, "POST")
        self.assertEqual(
            opener.requests[0].full_url,
            "https://api.github.com/repos/saltyorg/Saltbox/actions/runs/5678/rerun-failed-jobs",
        )

    def test_ambiguous_post_error_never_exposes_token(self) -> None:
        opener = RecordingOpener([URLError("connection reset")])
        client = GitHubClient("secret-token", opener=opener, sleep=lambda _: None)

        with self.assertRaises(AmbiguousRequestError) as raised:
            client.rerun_failed_jobs("saltyorg/Saltbox", 5678)

        self.assertNotIn("secret-token", str(raised.exception))
        self.assertEqual(len(opener.requests), 1)

    def test_read_retries_transient_server_error(self) -> None:
        error = HTTPError(
            "https://api.github.com/example",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b"unavailable"),
        )
        opener = RecordingOpener(
            [error, FakeResponse(200, {"run_attempt": 2, "conclusion": "failure"})]
        )
        sleeps: list[int] = []
        client = GitHubClient("secret-token", opener=opener, sleep=sleeps.append)

        result = client.get_run_attempt("saltyorg/Sandbox", 1234, 2)

        self.assertEqual(result["run_attempt"], 2)
        self.assertEqual(sleeps, [1])
        self.assertEqual(len(opener.requests), 2)

    def test_invalid_repository_is_rejected_before_request(self) -> None:
        opener = RecordingOpener([])
        client = GitHubClient("secret-token", opener=opener, sleep=lambda _: None)

        with self.assertRaisesRegex(ValueError, "owner/name"):
            client.get_run("saltyorg/Sandbox/extra", 1234)

        self.assertEqual(opener.requests, [])


if __name__ == "__main__":
    unittest.main()
