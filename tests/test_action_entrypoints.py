from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions.notify import run_action as run_notify_action
from salty_actions.retry import run_action as run_retry_action

from .http_fakes import FakeResponse, RecordingOpener
from .test_notify import workflow_event
from .test_retry import FakeGitHubClient, workflow_run_event

ROOT = Path(__file__).resolve().parents[1]


def action_command(action: str) -> str:
    prefix = "      run: "
    commands = [
        line.removeprefix(prefix)
        for line in (ROOT / action / "action.yml").read_text().splitlines()
        if line.startswith(prefix)
    ]
    if len(commands) != 1:
        raise AssertionError(f"{action}/action.yml must contain one inline run command")
    return commands[0]


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


class PackagedActionCommandTests(unittest.TestCase):
    def test_retry_action_command_loads_packaged_module(self) -> None:
        result = self._run_with_invalid_event("retry")

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "::error::Retry orchestration failed: repository must be an object",
            result.stderr,
        )

    def test_notify_action_command_loads_packaged_module(self) -> None:
        result = self._run_with_invalid_event("notify")

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "::error::Discord notification failed: repository must be an object",
            result.stderr,
        )

    def _run_with_invalid_event(self, action: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = root / "event.json"
            event_path.write_text("{}", encoding="utf-8")
            env = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "GITHUB_ACTION_PATH": str(ROOT / action),
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_OUTPUT": str(root / "output"),
                "GITHUB_TOKEN": "fixture-token",
                "NON_RETRYABLE_JOBS": "saltbox-lint",
                "DISCORD_WEBHOOK": "https://discord.invalid/api/webhooks/fixture",
                "TERMINAL_REASON": "",
                "EXECUTION_ATTEMPT": "",
            }
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", action_command(action)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )


if __name__ == "__main__":
    unittest.main()
