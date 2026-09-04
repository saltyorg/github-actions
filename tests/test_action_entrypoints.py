from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.notify import run_action as run_notify_action
from salty_actions.retry import run_action as run_retry_action

from .test_github import FakeResponse, RecordingOpener
from .test_notify import workflow_event
from .test_retry import FakeGitHubClient, workflow_run_event


class RetryEntrypointTests(unittest.TestCase):
    def test_action_writes_safe_terminal_outputs(self) -> None:
        client = FakeGitHubClient()
        client.jobs = [{"name": "saltbox-lint", "conclusion": "failure"}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = root / "event.json"
            output_path = root / "output"
            event_path.write_text(json.dumps(workflow_run_event(event="push")))
            env = {
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_OUTPUT": str(output_path),
                "NON_RETRYABLE_JOBS": "\nsaltbox-lint\nsaltbox-lint\n",
            }

            result = run_retry_action(env, client=client, sleep=lambda _: None)

            self.assertEqual(result.decision, "terminal")
            self.assertEqual(
                output_path.read_text().splitlines(),
                [
                    "decision=terminal",
                    "reason=non-retryable-job",
                    "execution-attempt=1",
                    'failed-jobs=["saltbox-lint"]',
                ],
            )


class NotifyEntrypointTests(unittest.TestCase):
    def test_action_uses_event_file_and_posts_notification(self) -> None:
        opener = RecordingOpener([FakeResponse(204)])
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(workflow_event(conclusion="success")))
            env = {
                "GITHUB_EVENT_PATH": str(event_path),
                "DISCORD_WEBHOOK": "https://discord.com/api/webhooks/123/secret",
                "TERMINAL_REASON": "",
                "EXECUTION_ATTEMPT": "",
            }

            run_notify_action(
                env,
                github=None,
                opener=opener,
                now=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
            )

            sent_payload = json.loads(opener.requests[0].data or b"{}")
            self.assertEqual(sent_payload["embeds"][0]["title"], "Success: CI")


if __name__ == "__main__":
    unittest.main()
