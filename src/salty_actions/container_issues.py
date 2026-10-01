"""Automation-owned vulnerability issues with reconciled, bounded writes."""
from __future__ import annotations

import json
import re
from urllib.parse import urlencode

from .github import GitHubClient
from .transport import AmbiguousRequestError, GitHubTransport

START = "<!-- salty-container-security:start -->"
END = "<!-- salty-container-security:end -->"
MARKER = re.compile(r"<!-- salty-container-security:(\{[^\n]*\}) -->")
BOT = "github-actions[bot]"


def issue_marker(issue: dict) -> dict | None:
    user = issue.get("user")
    if "pull_request" in issue or not isinstance(user, dict) or user.get("login") != BOT:
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
    if (not isinstance(marker, dict) or set(marker) != {"schema", "scope", "key", "resolved"}
            or marker["schema"] != 1 or type(marker["resolved"]) is not bool
            or not isinstance(marker["scope"], str) or not isinstance(marker["key"], str)):
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
            query = urlencode({"state": "all", "per_page": 100, "page": page,
                               "sort": "created", "direction": "asc"})
            payload = self.transport.get_json(f"/repos/{self.repository}/issues?{query}")
            if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
                raise ValueError("GitHub issues response must be an array of objects")
            for row in payload:
                if "pull_request" in row:
                    continue
                if (type(row.get("number")) is not int or row["number"] < 1
                        or row.get("state") not in {"open", "closed"}
                        or (row.get("body") is not None and not isinstance(row["body"], str))):
                    raise ValueError("GitHub issue response has invalid identity, state, or body")
                results.append(row)
            if len(payload) < 100:
                return results
            page += 1

    def closed_by_automation(self, number: int) -> bool:
        page, last_closure = 1, None
        while True:
            payload = self.transport.get_json(
                f"/repos/{self.repository}/issues/{number}/events?per_page=100&page={page}")
            if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
                raise ValueError("GitHub issue events response must be an array of objects")
            for event in payload:
                if event.get("event") == "closed":
                    actor = event.get("actor")
                    last_closure = actor.get("login") if isinstance(actor, dict) else None
            if len(payload) < 100:
                return last_closure == BOT
            page += 1

    def write(self, action: dict) -> dict:
        payload = action["payload"]
        number = action.get("number")
        path = f"/repos/{self.repository}/issues" + (f"/{number}" if number else "")
        method = "PATCH" if number else "POST"
        for attempt in range(4):
            try:
                result = self.transport.send_json(path, method, payload)
                if (not isinstance(result, dict) or type(result.get("number")) is not int
                        or result["number"] < 1 or any(result.get(key) != value
                                                      for key, value in payload.items()
                                                      if key != "state_reason")):
                    raise AmbiguousRequestError("GitHub issue write returned no issue number")
                return result
            except AmbiguousRequestError:
                # A POST is never blindly repeated, even after a server error.
                # Read retries handle temporarily unavailable reconciliation.
                matches = [row for row in self.list_issues()
                           if (marker := issue_marker(row)) and marker["key"] == action["key"]
                           and marker["scope"] == action["scope"]]
                if number:
                    matches = [row for row in matches if row.get("number") == number]
                if len(matches) == 1 and all(matches[0].get(key) == value
                                            for key, value in payload.items()
                                            if key != "state_reason"):
                    return matches[0]
                if not number or len(matches) != 1 or attempt == 3:
                    raise AmbiguousRequestError(
                        "Issue write could not be reconciled; no duplicate creation attempted"
                    )
                # PATCH sets an exact desired state. Replay only after finding
                # the same owned issue, without an intervening body/state edit.
                current = matches[0]
                if (current.get("body") != action["before_body"] or current.get("state") != action["before_state"]
                        or current.get("title") != action["before_title"]):
                    raise AmbiguousRequestError("Issue changed during reconciliation; refusing to overwrite")
                self.transport._sleep(2 ** attempt)
        raise AssertionError("unreachable")


def managed_body(scope: str, group: dict, *, resolved: bool = False) -> str:
    marker = {"schema": 1, "scope": scope, "key": group["key"], "resolved": resolved}
    lines = [START, "<!-- salty-container-security:" + json.dumps(marker, separators=(",", ":")) + " -->",
             f"## {group['id']} in {group['package']}", "",
             "Status: " + ("No longer detected in the assessed published images." if resolved else
                            "Detected in published images. Automated upgrades remain enabled."), "",
             "| Image | Platform | Package version | Severity | Scanner | Advertised fix |",
             "| --- | --- | --- | --- | --- | --- |"]
    for item in group["observations"]:
        def cell(value):
            return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        lines.append("| " + " | ".join(cell(item[key]) for key in
                                       ("name", "platform", "version", "severity", "source", "fix")) + " |")
    if group["kev"]:
        lines.extend(["", "This finding is in CISA KEV and blocks candidate publication."])
    lines.extend(["", "Repository availability of advertised fixes is not verified by this report.", "",
                  "Assessed image digests:"])
    for image in sorted(group["images"]):
        lines.append(f"- `{image}`")
    urls = sorted({item["url"] for item in group["observations"] if item["url"]})
    if urls:
        lines.extend(["", "Advisories:"] + [f"- {url}" for url in urls])
    # Do not put scan timestamps/run URLs in the managed body: otherwise every
    # clean repeat scan would edit the issue. Those remain in report artifacts.
    lines.extend(["", "Only complete scans of this reporting scope can resolve this issue.", END])
    body = "\n".join(lines)
    if len(body) > 60000:
        raise ValueError("vulnerability issue body exceeds supported size")
    return body


def plan_issues(scope: str, groups: dict, issues: list[dict], *, complete: bool,
                client: IssueClient, resolution_images: list[str] | None = None) -> list[dict]:
    owned = {}
    for issue in issues:
        marker = issue_marker(issue)
        if marker and marker["scope"] == scope:
            if marker["key"] in owned:
                raise ValueError("duplicate owned vulnerability issues require manual reconciliation")
            owned[marker["key"]] = issue
    actions = []
    for key, group in sorted(groups.items()):
        existing = owned.get(key)
        body = managed_body(scope, group)
        title = f"{group['id']}: {group['package']} ({group['distro']})"
        if len(title) > 256:
            raise ValueError("vulnerability issue title exceeds supported size")
        payload = {"title": title, "body": body}
        if existing:
            marker = issue_marker(existing)
            if existing.get("state") == "closed":
                if not marker["resolved"] or not client.closed_by_automation(existing["number"]):
                    continue  # Human closure is an explicit opt-out.
                payload["state"] = "open"
                operation = "reopen"
            else:
                operation = "update"
            payload["body"] = replace_managed_body(existing["body"], body)
            if all(existing.get(field) == value for field, value in payload.items()):
                continue
        else:
            operation = "create"
            if group.get("run_url"):
                payload["body"] += f"\n\nFirst detected in [this workflow run]({group['run_url']})."
        actions.append({"operation": operation, "key": key, "scope": scope,
                        "number": existing["number"] if existing else None,
                        "before_body": existing.get("body") if existing else None,
                        "before_state": existing.get("state") if existing else None,
                        "before_title": existing.get("title") if existing else None,
                        "payload": payload})
    if complete:
        for key, existing in sorted(owned.items()):
            if key in groups or existing.get("state") != "open":
                continue
            marker = issue_marker(existing)
            marker["resolved"] = True
            body = MARKER.sub("<!-- salty-container-security:" + json.dumps(
                marker, separators=(",", ":")) + " -->", existing["body"])
            body = body.replace("Status: Detected in published images. Automated upgrades remain enabled.",
                                "Status: No longer detected in the assessed published images.")
            if resolution_images:
                evidence = "\n\nResolution verified against these current published images:\n" + "\n".join(
                    f"- `{image}`" for image in sorted(set(resolution_images))) + "\n"
                first, suffix = body.split(END, 1)
                body = first + evidence + END + suffix
            actions.append({"operation": "close", "key": key, "scope": scope,
                            "number": existing["number"], "before_body": existing["body"],
                            "before_state": existing["state"],
                            "before_title": existing.get("title"),
                            "payload": {"state": "closed", "state_reason": "completed", "body": body}})
    return actions
