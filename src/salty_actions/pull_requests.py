from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, cast

from .github import REPOSITORY_RE


class BranchPullClient(Protocol):
    def list_branch_pulls(
        self, repository: str, head_repository: str, head_branch: str
    ) -> list[dict[str, object]]: ...

    def get_pull(self, repository: str, number: int) -> dict[str, object]: ...


def resolve_branch_pull(
    client: BranchPullClient, repository: str, workflow_run: Mapping[str, object]
) -> dict[str, object] | None:
    """Resolve one source PR conservatively when event and commit lookups are empty."""
    if workflow_run.get("event") != "pull_request":
        return None
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
    for pull in client.list_branch_pulls(repository, source_name, branch):
        match = matches(pull)
        if match is None:
            return None
        if match:
            candidates.append(pull)
    if len(candidates) != 1:
        return None
    number = cast(int, candidates[0]["number"])
    pull = client.get_pull(repository, number)
    return pull if pull.get("number") == number and matches(pull) is True else None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo is not None else None
