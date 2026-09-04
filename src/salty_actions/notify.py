from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DISCORD_FIELD_VALUE_LIMIT = 1024


class PullRequestEnricher(Protocol):
    def list_commit_pulls(
        self, repository: str, head_sha: str
    ) -> list[dict[str, object]]: ...


def build_notification(
    payload: Mapping[str, object],
    *,
    terminal_reason: str = "",
    execution_attempt: int | None = None,
    github: PullRequestEnricher | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    repository_data = _mapping(payload.get("repository"), "repository")
    workflow_run = _mapping(payload.get("workflow_run"), "workflow_run")
    repository = _string(repository_data.get("full_name"), "repository.full_name")
    run_id = _integer(workflow_run.get("id"), "workflow_run.id")
    run_attempt = _integer(workflow_run.get("run_attempt"), "workflow_run.run_attempt")
    workflow_name = _string(workflow_run.get("name"), "workflow_run.name")
    conclusion = _string(workflow_run.get("conclusion"), "workflow_run.conclusion")
    head_branch = str(workflow_run.get("head_branch") or "Unknown branch")
    triggering_actor = _login(workflow_run.get("triggering_actor"))
    workflow_url = str(
        workflow_run.get("html_url")
        or f"https://github.com/{repository}/actions/runs/{run_id}"
    )

    description = f"GitHub attempt: {run_attempt}"
    if execution_attempt is not None:
        description += f"\nCI execution: {execution_attempt}"

    fields: list[dict[str, object]] = [
        {
            "name": "Repository",
            "value": f"[{repository}](https://github.com/{repository})",
            "inline": True,
        },
        {"name": "Ref", "value": _truncate(head_branch), "inline": True},
        _event_field(repository, workflow_run, github),
        {"name": "Triggered by", "value": triggering_actor, "inline": True},
        {
            "name": "Workflow",
            "value": f"[{workflow_name}]({workflow_url})",
            "inline": True,
        },
    ]
    if terminal_reason:
        fields.append(
            {"name": "Result", "value": _truncate(terminal_reason), "inline": True}
        )

    timestamp = now or datetime.now(timezone.utc)
    return {
        "embeds": [
            {
                "title": f"{conclusion.capitalize()}: {workflow_name}",
                "description": description,
                "color": _discord_color(conclusion),
                "fields": fields,
                "timestamp": timestamp.isoformat(),
            }
        ],
        "allowed_mentions": {"parse": []},
    }


def send_notification(
    webhook_url: str,
    payload: Mapping[str, object],
    *,
    opener: Callable[..., Any] = urlopen,
) -> None:
    if not webhook_url:
        raise ValueError("Discord webhook must not be empty")
    request = Request(
        webhook_url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "saltyorg/github-actions",
        },
    )
    try:
        with opener(request, timeout=30) as response:
            if response.status != 204:
                raise RuntimeError(
                    f"Discord notification returned HTTP {response.status}"
                )
    except HTTPError as error:
        raise RuntimeError(
            f"Discord notification returned HTTP {error.code}"
        ) from error
    except URLError as error:
        raise RuntimeError(
            "Discord notification ended without a definitive response"
        ) from error


def _event_field(
    repository: str,
    workflow_run: Mapping[str, object],
    github: PullRequestEnricher | None,
) -> dict[str, object]:
    event = str(workflow_run.get("event") or "unknown")
    head_sha = str(workflow_run.get("head_sha") or "")

    if event in {"pull_request", "pull_request_target"}:
        number = _pull_request_number(workflow_run)
        title = ""
        url = f"https://github.com/{repository}/pull/{number}" if number else ""
        if github is not None and len(head_sha) == 40:
            try:
                pull_requests = github.list_commit_pulls(repository, head_sha)
                selected = next(
                    (
                        item
                        for item in pull_requests
                        if number is None or item.get("number") == number
                    ),
                    None,
                )
                if selected:
                    selected_number = selected.get("number")
                    if isinstance(selected_number, int):
                        number = selected_number
                    title = str(selected.get("title") or "")
                    url = str(
                        selected.get("html_url")
                        or f"https://github.com/{repository}/pull/{number}"
                    )
            except (OSError, TypeError, ValueError, RuntimeError):
                pass

        if number is not None:
            value = f"[#{number}]({url})"
            if title:
                value += f" {title}"
        else:
            value = f"Pull request event on {workflow_run.get('head_branch') or 'unknown branch'}"
        return {"name": f"Event - {event}", "value": _truncate(value)}

    if event == "push":
        head_commit = workflow_run.get("head_commit")
        commit = head_commit if isinstance(head_commit, Mapping) else {}
        message = str(commit.get("message") or "No commit message").strip()
        short_sha = head_sha[:7] if head_sha else "unknown"
        commit_url = f"https://github.com/{repository}/commit/{head_sha}"
        value = f"[`{short_sha}`]({commit_url}) {message}"
        return {"name": "Event - push", "value": _truncate(value)}

    if event == "workflow_run":
        display_title = str(workflow_run.get("display_title") or "Workflow run")
        return {
            "name": "Event - workflow_run",
            "value": _truncate(display_title),
        }

    if event == "workflow_dispatch":
        return {
            "name": "Event - workflow_dispatch",
            "value": f"Workflow manually triggered by {_login(workflow_run.get('triggering_actor'))}",
        }

    return {"name": "Event", "value": _truncate(event)}


def _pull_request_number(workflow_run: Mapping[str, object]) -> int | None:
    pull_requests = workflow_run.get("pull_requests")
    if not isinstance(pull_requests, list) or not pull_requests:
        return None
    first = pull_requests[0]
    if not isinstance(first, Mapping):
        return None
    number = first.get("number")
    return number if isinstance(number, int) and not isinstance(number, bool) else None


def _discord_color(conclusion: str) -> int:
    return {
        "success": 0x28A745,
        "failure": 0xCB2431,
        "cancelled": 0xDBAB09,
        "timed_out": 0xCB2431,
        "startup_failure": 0xCB2431,
    }.get(conclusion, 0xF1C232)


def _truncate(value: str) -> str:
    if len(value) <= DISCORD_FIELD_VALUE_LIMIT:
        return value
    return value[: DISCORD_FIELD_VALUE_LIMIT - 3] + "..."


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _login(value: object) -> str:
    if not isinstance(value, Mapping):
        return "Unknown user"
    login = value.get("login")
    return str(login) if login else "Unknown user"


def run_action(
    env: Mapping[str, str],
    *,
    github: PullRequestEnricher | None,
    opener: Callable[..., Any] = urlopen,
    now: datetime | None = None,
) -> None:
    event_path = Path(_env(env, "GITHUB_EVENT_PATH"))
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("GitHub event payload must be an object")
    execution_value = env.get("EXECUTION_ATTEMPT", "").strip()
    execution = int(execution_value) if execution_value else None
    if execution is not None and execution < 1:
        raise ValueError("EXECUTION_ATTEMPT must be a positive integer")
    notification = build_notification(
        payload,
        terminal_reason=env.get("TERMINAL_REASON", "").strip(),
        execution_attempt=execution,
        github=github,
        now=now,
    )
    send_notification(_env(env, "DISCORD_WEBHOOK"), notification, opener=opener)
    print("Discord notification sent successfully")


def main() -> int:
    try:
        from .github import GitHubClient

        token = _env(os.environ, "GITHUB_TOKEN")
        run_action(os.environ, github=GitHubClient(token))
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        print(f"::error::Discord notification failed: {error}", file=sys.stderr)
        return 1
    return 0


def _env(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
