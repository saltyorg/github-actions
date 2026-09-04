from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.notify import build_notification, send_notification

from .http_fakes import FakeResponse, RecordingOpener

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


def workflow_event(
    *,
    event: str = "push",
    conclusion: str = "failure",
    run_attempt: int = 1,
    display_title: str = "CI",
    pull_requests: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "repository": {"full_name": "saltyorg/Sandbox"},
        "workflow_run": {
            "id": 1234,
            "name": "CI",
            "display_title": display_title,
            "run_attempt": run_attempt,
            "status": "completed",
            "conclusion": conclusion,
            "event": event,
            "head_branch": "feature/example",
            "head_sha": "a" * 40,
            "html_url": "https://github.com/saltyorg/Sandbox/actions/runs/1234",
            "actor": {"login": "contributor"},
            "triggering_actor": {"login": "github-actions[bot]"},
            "head_commit": {
                "message": "fix(example): correct behavior",
            },
            "pull_requests": pull_requests or [],
        },
    }


class PullRequestEnricher:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error

    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]:
        if self.error:
            raise self.error
        return [
            {
                "number": 538,
                "title": "feat(role): add silo",
                "html_url": "https://github.com/saltyorg/Sandbox/pull/538",
            }
        ]


class NotificationPayloadTests(unittest.TestCase):
    def test_terminal_notification_distinguishes_raw_and_execution_attempts(
        self,
    ) -> None:
        payload = build_notification(
            workflow_event(run_attempt=3),
            terminal_reason="attempt-limit",
            execution_attempt=2,
            github=None,
            now=NOW,
        )

        embed = payload["embeds"][0]
        self.assertEqual(embed["title"], "Failure: CI")
        self.assertEqual(embed["description"], "GitHub attempt: 3\nCI execution: 2")
        self.assertIn(
            {"name": "Result", "value": "attempt-limit", "inline": True},
            embed["fields"],
        )
        self.assertEqual(payload["allowed_mentions"], {"parse": []})

    def test_pull_request_uses_enriched_title_and_link(self) -> None:
        payload = build_notification(
            workflow_event(event="pull_request", pull_requests=[{"number": 538}]),
            github=PullRequestEnricher(),
            now=NOW,
        )

        event_field = payload["embeds"][0]["fields"][2]
        self.assertEqual(event_field["name"], "Event - pull_request")
        self.assertEqual(
            event_field["value"],
            "[#538](https://github.com/saltyorg/Sandbox/pull/538) feat(role): add silo",
        )

    def test_pull_request_enrichment_failure_keeps_minimal_notification(self) -> None:
        payload = build_notification(
            workflow_event(event="pull_request", pull_requests=[{"number": 538}]),
            github=PullRequestEnricher(error=ValueError("malformed response")),
            now=NOW,
        )

        event_field = payload["embeds"][0]["fields"][2]
        self.assertEqual(
            event_field["value"],
            "[#538](https://github.com/saltyorg/Sandbox/pull/538)",
        )

    def test_docs_downstream_workflow_uses_display_title(self) -> None:
        payload = build_notification(
            workflow_event(
                event="workflow_run",
                conclusion="success",
                display_title="PR #415: chore(deps): update mkdocs-material",
            ),
            github=None,
            now=NOW,
        )

        event_field = payload["embeds"][0]["fields"][2]
        self.assertEqual(event_field["name"], "Event - workflow_run")
        self.assertEqual(
            event_field["value"],
            "PR #415: chore(deps): update mkdocs-material",
        )

    def test_push_uses_event_head_commit_without_extra_api_call(self) -> None:
        payload = build_notification(workflow_event(), github=None, now=NOW)

        event_field = payload["embeds"][0]["fields"][2]
        self.assertEqual(event_field["name"], "Event - push")
        self.assertIn("fix(example): correct behavior", event_field["value"])
        self.assertIn("/commit/" + "a" * 40, event_field["value"])


class DiscordDeliveryTests(unittest.TestCase):
    def test_discord_delivery_posts_json_once(self) -> None:
        opener = RecordingOpener([FakeResponse(204)])
        payload = {"embeds": [{"title": "Success: CI"}]}

        send_notification(
            "https://discord.com/api/webhooks/123/secret", payload, opener=opener
        )

        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.data or b"{}"), payload)
        self.assertEqual(request.get_header("Content-type"), "application/json")

    def test_discord_transport_error_does_not_expose_webhook(self) -> None:
        webhook = "https://discord.com/api/webhooks/123/super-secret"
        opener = RecordingOpener([URLError("connection reset")])

        with self.assertRaises(RuntimeError) as raised:
            send_notification(webhook, {"embeds": []}, opener=opener)

        self.assertNotIn(webhook, str(raised.exception))
        self.assertNotIn("super-secret", str(raised.exception))
        self.assertEqual(len(opener.requests), 1)


if __name__ == "__main__":
    unittest.main()
