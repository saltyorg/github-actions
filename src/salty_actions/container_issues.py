"""Automation-owned vulnerability issues with reconciled, bounded writes."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Protocol
from urllib.parse import urlencode

from .container_findings import (
    APPLICATION_DISTRO,
    OS_PACKAGE_TYPES,
    finding,
    package_purl,
)
from .container_tracking import STATUSES, evolve, read_state, state_comment
from .github import GitHubClient
from .transport import AmbiguousRequestError, GitHubTransport

START = "<!-- salty-container-security:start -->"
END = "<!-- salty-container-security:end -->"
MARKER = re.compile(r"<!-- salty-container-security:(\{[^\n]*\}) -->")
BOT = "github-actions[bot]"


class IssueStore(Protocol):
    repository: str

    def list_issues(self) -> list[dict]: ...
    def closed_by_automation(self, number: int) -> bool: ...
    def write(self, action: dict) -> dict: ...


def issue_marker(issue: dict) -> dict | None:
    user = issue.get("user")
    if (
        "pull_request" in issue
        or not isinstance(user, dict)
        or user.get("login") != BOT
    ):
        return None
    body = issue.get("body") or ""
    if not isinstance(body, str):
        return None
    markers = MARKER.findall(body)
    if len(markers) != 1 or body.count(START) != 1 or body.count(END) != 1:
        return None
    try:
        marker = json.loads(markers[0])
    except ValueError:
        return None
    if (
        not isinstance(marker, dict)
        or set(marker) != {"schema", "scope", "key", "resolved"}
        or marker["schema"] != 1
        or type(marker["resolved"]) is not bool
        or not isinstance(marker["scope"], str)
        or not isinstance(marker["key"], str)
    ):
        return None
    return marker


def replace_managed_body(old: str, managed: str) -> str:
    first = old.index(START)
    last = old.index(END, first) + len(END)
    return old[:first] + managed + old[last:]


class IssueClient:
    def __init__(self, token: str, repository: str, *, transport=None):
        GitHubClient._validate(repository, 1)
        self.repository = repository
        self.transport = transport or GitHubTransport(token)

    def list_issues(self) -> list[dict]:
        results = []
        page = 1
        while True:
            query = urlencode(
                {
                    "state": "all",
                    "per_page": 100,
                    "page": page,
                    "sort": "created",
                    "direction": "asc",
                }
            )
            payload = self.transport.get_json(
                f"/repos/{self.repository}/issues?{query}"
            )
            if not isinstance(payload, list) or any(
                not isinstance(row, dict) for row in payload
            ):
                raise ValueError("GitHub issues response must be an array of objects")
            for row in payload:
                if "pull_request" in row:
                    continue
                if (
                    type(row.get("number")) is not int
                    or row["number"] < 1
                    or row.get("state") not in {"open", "closed"}
                    or (
                        row.get("body") is not None and not isinstance(row["body"], str)
                    )
                ):
                    raise ValueError(
                        "GitHub issue response has invalid identity, state, or body"
                    )
                results.append(row)
            if len(payload) < 100:
                return results
            page += 1

    def closed_by_automation(self, number: int) -> bool:
        page, last_closure = 1, None
        while True:
            payload = self.transport.get_json(
                f"/repos/{self.repository}/issues/{number}/events?per_page=100&page={page}"
            )
            if not isinstance(payload, list) or any(
                not isinstance(row, dict) for row in payload
            ):
                raise ValueError(
                    "GitHub issue events response must be an array of objects"
                )
            for event in payload:
                if event.get("event") == "closed":
                    actor = event.get("actor")
                    last_closure = (
                        actor.get("login") if isinstance(actor, dict) else None
                    )
            if len(payload) < 100:
                return last_closure == BOT
            page += 1

    def write(self, action: dict) -> dict:
        payload = action["payload"]
        number = action.get("number")
        path = f"/repos/{self.repository}/issues" + (f"/{number}" if number else "")
        method = "PATCH" if number else "POST"
        allowed_keys = {action["key"]}
        before_marker = None
        if number:
            before_marker = issue_marker(
                {"user": {"login": BOT}, "body": action["before_body"]}
            )
            if before_marker is None or before_marker["scope"] != action["scope"]:
                raise ValueError("issue ownership changed before write")
            allowed_keys.add(before_marker["key"])

        def validate_current() -> None:
            current = self.transport.get_json(path)
            current_marker = (
                issue_marker(current) if isinstance(current, dict) else None
            )
            if (
                not isinstance(current, dict)
                or type(current.get("number")) is not int
                or current.get("number") != number
                or current_marker != before_marker
                or any(
                    current.get(field) != action["before_" + field]
                    for field in ("body", "state", "title")
                )
            ):
                raise ValueError("issue changed before write; refusing to overwrite")

        for attempt in range(4):
            try:
                result = (
                    self.transport.send_json(
                        path, method, payload, before_attempt=validate_current
                    )
                    if number
                    else self.transport.send_json(path, method, payload)
                )
                if (
                    not isinstance(result, dict)
                    or type(result.get("number")) is not int
                    or result["number"] < 1
                    or any(
                        result.get(key) != value
                        for key, value in payload.items()
                        if key != "state_reason"
                    )
                ):
                    raise AmbiguousRequestError(
                        "GitHub issue write returned no issue number"
                    )
                return result
            except AmbiguousRequestError as error:
                # A POST is never blindly repeated, even after a server error.
                # Read retries handle temporarily unavailable reconciliation.
                matches = [
                    row
                    for row in self.list_issues()
                    if (marker := issue_marker(row))
                    and marker["key"] in allowed_keys
                    and marker["scope"] == action["scope"]
                ]
                if number:
                    matches = [row for row in matches if row.get("number") == number]
                if len(matches) == 1 and all(
                    matches[0].get(key) == value
                    for key, value in payload.items()
                    if key != "state_reason"
                ):
                    return matches[0]
                if not number or len(matches) != 1 or attempt == 3:
                    raise AmbiguousRequestError(
                        "Issue write could not be reconciled; no duplicate creation attempted: "
                        f"{error}"
                    ) from error
                # PATCH sets an exact desired state. Replay only after finding
                # the same owned issue, without an intervening body/state edit.
                current = matches[0]
                if (
                    current.get("body") != action["before_body"]
                    or current.get("state") != action["before_state"]
                    or current.get("title") != action["before_title"]
                ):
                    raise AmbiguousRequestError(
                        "Issue changed during reconciliation; refusing to overwrite"
                    )
                self.transport._sleep(2**attempt)
        raise AssertionError("unreachable")


def tracking_lines(tracking: dict, repository: str = "") -> list[str]:
    lines = ["", state_comment(tracking)]
    if tracking.get("verification"):
        lines.extend(["", "Published remediation evidence:"])
        for target in tracking["verification"]:
            lines.append(
                f"- {target['name']} / {target['platform']}: {target['reason']}; "
                f"`{target['image']}`; inventory `{target['inventory_sha256']}`."
            )
            for package in target.get("packages", []):
                lines.append(f"  Package `{package['name']}={package['version']}`.")
    evidence = tracking.get("evidence", {})
    if evidence.get("at"):
        lines.append(f"Evidence for this state change: {evidence['at']}.")
        if repository and evidence.get("run_id", "").isdigit():
            lines.append(
                f"[Assessment run](https://github.com/{repository}/actions/runs/{evidence['run_id']})."
            )
    if tracking.get("history"):
        lines.extend(["", "Recent tracking transitions:"])
        for entry in tracking["history"]:
            lines.append(f"- {entry['at'] or 'Legacy assessment'}: {entry['status']}.")
    return lines


def managed_body(
    scope: str,
    group: dict,
    *,
    resolved: bool = False,
    tracking: dict | None = None,
    repository: str = "",
) -> str:
    marker = {"schema": 1, "scope": scope, "key": group["key"], "resolved": resolved}
    lines = [
        START,
        "<!-- salty-container-security:"
        + json.dumps(marker, separators=(",", ":"))
        + " -->",
        f"## {group['id']} in {group['package']}",
        "",
        "Status: "
        + (
            STATUSES[tracking["status"]]
            if tracking
            else "No longer detected in the assessed published images."
            if resolved
            else "Detected in published images. Automated upgrades remain enabled."
        ),
        "",
    ]
    if tracking and tracking["status"] not in {"detected", "incomplete"}:
        lines.extend(["Last detected observations and availability at that time:", ""])
    elif tracking:
        targets = {(item["name"], item["platform"]) for item in group["observations"]}
        installable = {
            (item["name"], item["platform"])
            for item in group["observations"]
            if item.get("availability", {}).get("status") == "installable"
        }
        if installable:
            extent = (
                "all currently detected targets"
                if installable == targets
                else "some affected targets"
            )
            lines.extend(
                [
                    f"Package fixes are installable on {extent}. Build input updates and publication are still required.",
                    "",
                ]
            )
    lines.extend(
        [
            "| Image | Platform | Package version | Severity | Scanner | Advertised fix | Vendor fix | Availability / next action |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in group["observations"]:

        def cell(value):
            return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

        availability = item.get("availability", {})
        description = {
            "not_available": "Fix not yet in configured repositories",
            "blocked": "Upgrade blocked by pins, dependencies or base constraints",
            "installable": "Package fix installable; build input update pending",
            "fixed": "Vendor reports this package version fixed; scanner disagreement requires review",
            "unsupported": "Awaiting a fixed base image or application rebuild; availability unverified",
            "unknown": "Availability unknown; check assessment errors",
        }.get(
            availability.get("status"),
            "Fix advertised; availability unverified"
            if item["fix"]
            else "No fix reported",
        )
        if availability.get("candidates"):
            description += "; candidate: " + ", ".join(availability["candidates"])
        lines.append(
            "| "
            + " | ".join(
                [
                    *(
                        cell(item[key])
                        for key in ("name", "platform", "version", "severity")
                    ),
                    cell(
                        item["source"]
                        + (
                            ", last known"
                            if item.get("evidence_status") == "last known"
                            else ""
                        )
                    ),
                    cell(item["fix"]),
                    cell(
                        ", ".join(availability.get("versions", []))
                        if availability.get("source") == "Alpine secdb"
                        else ""
                    ),
                    cell(description),
                ]
            )
            + " |"
        )
    if group["kev"]:
        lines.extend(
            ["", "This finding is in CISA KEV and blocks candidate publication."]
        )
    lines.extend(
        [
            "",
            "Availability is verified only where explicitly stated. A clean scanner does not cancel another scanner's finding.",
            "",
            "Assessed image digests:",
        ]
    )
    for image in sorted(group["images"]):
        lines.append(f"- `{image}`")
    urls = sorted({item["url"] for item in group["observations"] if item["url"]})
    if urls:
        lines.extend(["", "Advisories:"] + [f"- {url}" for url in urls])
    # Only state transitions carry timestamps and run URLs; identical scans stay quiet.
    if tracking:
        lines.extend(tracking_lines(tracking, repository))
    lines.extend(
        [
            "",
            "Resolution requires published package evidence and two complete assessments at least six hours apart.",
            END,
        ]
    )
    body = "\n".join(lines)
    if len(body) > 60000:
        raise ValueError("vulnerability issue body exceeds supported size")
    return body


def application_finding(record: dict, *, distro: str = APPLICATION_DISTRO) -> dict:
    """Rebuild a language identity, including verified legacy distribution aliases."""
    return finding(
        record["id"],
        package_purl(record["package_type"], record["namespace"], record["package"]),
        record["version"],
        record["severity"],
        distro,
        record["source"],
        url=record["url"],
        fix=record["fix"],
        kev=record["kev"],
    )


def plan_issues(
    scope: str,
    groups: dict,
    issues: list[dict],
    *,
    complete: bool,
    client: IssueStore,
    assessment: dict | None = None,
) -> list[dict]:
    owned, previous_states = {}, {}
    legacy_aliases: dict[str, set[str]] = {}
    distros = {
        target["inventory"]["distro"]
        for target in (assessment or {}).get("targets", [])
        if target.get("inventory", {}).get("status") == "complete"
        and isinstance(target["inventory"].get("distro"), str)
        and target["inventory"]["distro"]
    }
    for key, group in groups.items():
        if (
            group["package_type"] not in OS_PACKAGE_TYPES
            and group["distro"] == APPLICATION_DISTRO
        ):
            for distro in distros:
                legacy_key = application_finding(group, distro=distro)["key"]
                legacy_aliases.setdefault(legacy_key, set()).add(key)
    unmatched_legacy = set()
    for issue in issues:
        marker = issue_marker(issue)
        if marker and marker["scope"] == scope:
            previous = read_state(issue["body"])
            baseline = previous.get("group") if previous else None
            key = marker["key"]
            if baseline:
                if baseline["key"] != key:
                    raise ValueError("tracking state does not match issue identity")
                if baseline["package_type"] not in OS_PACKAGE_TYPES:
                    canonical_key = application_finding(baseline)["key"]
                    if canonical_key in groups:
                        key = canonical_key
            elif key in legacy_aliases:
                matches = legacy_aliases[key]
                if len(matches) != 1:
                    raise ValueError(
                        "ambiguous legacy issue identities require manual reconciliation"
                    )
                key = next(iter(matches))
            elif key not in groups:
                unmatched_legacy.add(issue["number"])
            if key in owned:
                raise ValueError(
                    "duplicate owned vulnerability issues require manual reconciliation"
                )
            owned[key] = issue
            previous_states[key] = previous
    actions = []
    for key in sorted(set(groups) | set(owned)):
        group = groups.get(key)
        existing = owned.get(key)
        if existing is None and group is None:
            continue
        if group is None and (existing is None or existing.get("state") != "open"):
            continue
        if existing and existing.get("state") == "closed":
            marker = issue_marker(existing)
            if (
                not marker
                or not marker["resolved"]
                or not client.closed_by_automation(existing["number"])
            ):
                continue  # Human closure is an explicit opt-out.
        if existing is None and not any(
            item["kev"] or item["severity"] in {"HIGH", "CRITICAL"}
            for item in (group or {})["observations"]
        ):
            continue
        if (
            existing is None
            and group
            and group["package_type"] not in OS_PACKAGE_TYPES
            and unmatched_legacy
        ):
            raise ValueError(
                "unmatched legacy issues require manual reconciliation before "
                "creating application issues"
            )
        previous = deepcopy(previous_states.get(key))
        if (
            previous
            and existing
            and (issue_marker(existing) or {}).get("resolved")
            != (previous["status"] == "resolved")
        ):
            raise ValueError("tracking resolution state disagrees with issue marker")
        if previous and previous.get("group") and previous["group"]["key"] != key:
            baseline = previous["group"]
            if (
                group is None
                or baseline["package_type"] in OS_PACKAGE_TYPES
                or application_finding(baseline)["key"] != key
            ):
                raise ValueError("tracking state does not match issue identity")
            previous["group"] = {
                **baseline,
                **application_finding(baseline),
                "observations": [
                    {**record, **application_finding(record)}
                    for record in baseline["observations"]
                ],
            }
            previous["pending"] = None
            previous.pop("verification", None)
        if (
            existing
            and existing["state"] == "open"
            and (issue_marker(existing) or {}).get("resolved")
            and previous
            and group is None
        ):
            # A manually reopened issue must not immediately reclose from old proof.
            previous.update(status="review", pending=None, affected=[])
        tracking = evolve(previous, group, assessment, complete=complete)
        resolved = tracking["status"] == "resolved"
        rendered = tracking.get("group") or group
        title = (
            f"{rendered['id']}: {rendered['package']} ({rendered['distro']})"
            if rendered
            else (existing or {})["title"]
        )
        if rendered:
            body = managed_body(
                scope,
                rendered,
                resolved=resolved,
                tracking=tracking,
                repository=client.repository,
            )
        else:
            # Legacy issues without a trustworthy inventory remain open. Preserve
            # their original finding details until a new positive scan seeds state.
            original = (existing or {})["body"].split(START, 1)[1].split(END, 1)[0]
            original = re.sub(
                r"<!-- tracking-view:start -->.*?<!-- tracking-view:end -->",
                "",
                original,
                flags=re.DOTALL,
            ).rstrip()
            marker = {"schema": 1, "scope": scope, "key": key, "resolved": resolved}
            original = MARKER.sub(
                "<!-- salty-container-security:"
                + json.dumps(marker, separators=(",", ":"))
                + " -->",
                original,
            )
            original = re.sub(
                r"^Status:.*$",
                "Status: " + STATUSES[tracking["status"]],
                original,
                count=1,
                flags=re.MULTILINE,
            )
            if "Last detected observations:" not in original:
                original = original.replace(
                    "\n| Image |", "\nLast detected observations:\n\n| Image |", 1
                )
            body = (
                START
                + original
                + "\n<!-- tracking-view:start -->\n"
                + STATUSES[tracking["status"]]
                + "\n"
                + "\n".join(tracking_lines(tracking, client.repository))
                + "\n<!-- tracking-view:end -->\n"
                + END
            )
        if len(title) > 256:
            raise ValueError("vulnerability issue title exceeds supported size")
        payload = {"title": title, "body": body}
        if existing:
            marker = issue_marker(existing)
            if marker is None:
                raise ValueError("issue ownership changed during planning")
            if existing.get("state") == "closed":
                payload["state"] = "open"
                operation = "reopen"
            else:
                operation = "update"
                if resolved:
                    operation = "close"
                    payload.update(state="closed", state_reason="completed")
            payload["body"] = replace_managed_body(existing["body"], body)
            if all(existing.get(field) == value for field, value in payload.items()):
                continue
        else:
            operation = "create"
            if group and group.get("run_url"):
                payload["body"] += (
                    f"\n\nFirst detected in [this workflow run]({group['run_url']})."
                )
        if len(payload["body"]) > 60000:
            raise ValueError("vulnerability issue body exceeds supported size")
        actions.append(
            {
                "operation": operation,
                "key": key,
                "scope": scope,
                "number": existing["number"] if existing else None,
                "before_body": existing.get("body") if existing else None,
                "before_state": existing.get("state") if existing else None,
                "before_title": existing.get("title") if existing else None,
                "payload": payload,
            }
        )
    return actions
