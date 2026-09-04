from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.transport import GitHubTransport

from .http_fakes import FakeResponse, RecordingOpener


class GitHubTransportTests(unittest.TestCase):
    def test_get_json_builds_authenticated_versioned_request(self) -> None:
        opener = RecordingOpener([FakeResponse(200, {"status": "completed"})])
        transport = GitHubTransport(
            "secret-token",
            opener=opener,
            sleep=lambda _: None,
            api_url="https://github.example/api/v3/",
        )

        result = transport.get_json("/repos/saltyorg/Saltbox/actions/runs/1234")

        self.assertEqual(result, {"status": "completed"})
        request = opener.requests[0]
        self.assertEqual(
            request.full_url,
            "https://github.example/api/v3/repos/saltyorg/Saltbox/actions/runs/1234",
        )
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(request.get_header("X-github-api-version"), "2026-03-10")

    def test_post_mutation_sends_one_json_request(self) -> None:
        opener = RecordingOpener([FakeResponse(201)])
        transport = GitHubTransport(
            "secret-token", opener=opener, sleep=lambda _: None
        )

        transport.post_mutation(
            "/repos/saltyorg/Saltbox/actions/runs/1234/rerun-failed-jobs"
        )

        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.data, b"{}")


if __name__ == "__main__":
    unittest.main()
