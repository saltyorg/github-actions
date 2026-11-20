from __future__ import annotations

import io
import json
import sys
import unittest
from datetime import datetime, timezone
from email.message import Message
from email.utils import format_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.transport import AmbiguousRequestError, GitHubTransport

from .http_fakes import FakeResponse, RecordingOpener


def http_error(
    code: int,
    *,
    headers: dict[str, str] | None = None,
    message: str = "request failed",
) -> HTTPError:
    response_headers = Message()
    for name, value in (headers or {}).items():
        response_headers[name] = value
    body = json.dumps({"message": message}).encode()
    return HTTPError(
        "https://api.github.com/example",
        code,
        message,
        response_headers,
        io.BytesIO(body),
    )


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
        transport = GitHubTransport("secret-token", opener=opener, sleep=lambda _: None)

        transport.post_mutation(
            "/repos/saltyorg/Saltbox/actions/runs/1234/rerun-failed-jobs"
        )

        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.data, b"{}")

    def test_transport_errors_use_four_attempts_with_exponential_delays(self) -> None:
        opener = RecordingOpener([URLError("reset") for _ in range(4)])
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        with self.assertRaisesRegex(RuntimeError, "after four attempts"):
            transport.get_json("/example")

        self.assertEqual(len(opener.requests), 4)
        self.assertEqual(sleeps, [1, 2, 4])

    def test_numeric_retry_after_is_honored_without_a_cap(self) -> None:
        opener = RecordingOpener(
            [
                http_error(429, headers={"Retry-After": "3600"}),
                FakeResponse(200, {"status": "completed"}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        result = transport.get_json("/example")

        self.assertEqual(result, {"status": "completed"})
        self.assertEqual(sleeps, [3600])

    def test_http_date_retry_after_uses_injected_clock(self) -> None:
        now = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        retry_at = datetime(2026, 9, 4, 12, 2, tzinfo=timezone.utc)
        opener = RecordingOpener(
            [
                http_error(429, headers={"Retry-After": format_datetime(retry_at)}),
                FakeResponse(200, {}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport(
            "secret-token",
            opener=opener,
            sleep=sleeps.append,
            now=lambda: now.timestamp(),
        )

        transport.get_json("/example")

        self.assertEqual(sleeps, [120])

    def test_primary_rate_limit_uses_reset_time(self) -> None:
        now = 1_780_000_000.0
        opener = RecordingOpener(
            [
                http_error(
                    403,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(now + 75)),
                    },
                ),
                FakeResponse(200, {}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport(
            "secret-token",
            opener=opener,
            sleep=sleeps.append,
            now=lambda: now,
        )

        transport.get_json("/example")

        self.assertEqual(sleeps, [75])

    def test_secondary_rate_limit_without_headers_waits_one_minute(self) -> None:
        opener = RecordingOpener(
            [
                http_error(403, message="You have exceeded a secondary rate limit."),
                FakeResponse(200, {}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        transport.get_json("/example")

        self.assertEqual(sleeps, [60])

    def test_permission_denied_is_not_retried(self) -> None:
        opener = RecordingOpener(
            [http_error(403, message="Resource not accessible by integration")]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            transport.get_json("/example")

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(sleeps, [])

    def test_headerless_too_many_requests_waits_one_minute(self) -> None:
        opener = RecordingOpener(
            [http_error(429), FakeResponse(200, {"status": "completed"})]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        transport.get_json("/example")

        self.assertEqual(sleeps, [60])

    def test_server_error_honors_retry_after(self) -> None:
        opener = RecordingOpener(
            [
                http_error(503, headers={"Retry-After": "20"}),
                FakeResponse(200, {}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        transport.get_json("/example")

        self.assertEqual(sleeps, [20])

    def test_invalid_retry_after_uses_rate_limit_fallback(self) -> None:
        opener = RecordingOpener(
            [
                http_error(429, headers={"Retry-After": "not-a-delay"}),
                FakeResponse(200, {}),
            ]
        )
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        transport.get_json("/example")

        self.assertEqual(sleeps, [60])

    def test_final_rate_limit_failure_does_not_sleep(self) -> None:
        opener = RecordingOpener([http_error(429) for _ in range(4)])
        sleeps: list[float] = []
        transport = GitHubTransport("secret-token", opener=opener, sleep=sleeps.append)

        with self.assertRaisesRegex(RuntimeError, "HTTP 429"):
            transport.get_json("/example")

        self.assertEqual(len(opener.requests), 4)
        self.assertEqual(sleeps, [60, 60, 60])


class HTTPErrorCleanupTests(unittest.TestCase):
    """Each handled HTTPError owns an open response body that must be closed."""

    def assert_closed(self, errors: list[HTTPError]) -> None:
        for error in errors:
            self.assertTrue(error.fp.closed, f"HTTP {error.code} body left open")

    def test_read_closes_retried_and_final_errors(self) -> None:
        errors = [http_error(503), http_error(429), http_error(404)]
        opener = RecordingOpener(list(errors))
        transport = GitHubTransport("secret-token", opener=opener, sleep=lambda _: None)

        with self.assertRaisesRegex(RuntimeError, "HTTP 404") as raised:
            transport.get_json("/example")

        self.assert_closed(errors)
        cause = raised.exception.__cause__
        self.assertIs(cause, errors[-1])
        self.assertEqual(errors[-1].code, 404)
        self.assertEqual(errors[-1].reason, "request failed")

    def test_issue_write_closes_retried_and_final_errors(self) -> None:
        errors = [http_error(429), http_error(502)]
        opener = RecordingOpener(list(errors))
        transport = GitHubTransport("secret-token", opener=opener, sleep=lambda _: None)

        with self.assertRaisesRegex(AmbiguousRequestError, "HTTP 502"):
            transport.send_json("/repos/o/r/issues", "POST", {"title": "t"})

        self.assert_closed(errors)

    def test_rejected_issue_write_closes_error(self) -> None:
        error = http_error(422)
        transport = GitHubTransport(
            "secret-token", opener=RecordingOpener([error]), sleep=lambda _: None
        )

        with self.assertRaisesRegex(RuntimeError, "HTTP 422"):
            transport.send_json("/repos/o/r/issues", "PATCH", {"title": "t"})

        self.assert_closed([error])

    def test_mutation_closes_error(self) -> None:
        for code, expected in [(409, AmbiguousRequestError), (500, RuntimeError)]:
            with self.subTest(code=code):
                error = http_error(code)
                transport = GitHubTransport(
                    "secret-token",
                    opener=RecordingOpener([error]),
                    sleep=lambda _: None,
                )

                with self.assertRaisesRegex(expected, f"HTTP {code}"):
                    transport.post_mutation("/repos/o/r/actions/runs/1/rerun")

                self.assert_closed([error])


if __name__ == "__main__":
    unittest.main()
