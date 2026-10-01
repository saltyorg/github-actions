"""Aggregate a declared published image set and reconcile its issue reports."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from .container_findings import finding, obj, rows, text
from .container_issues import IssueClient, plan_issues
from .container_scan import DIGEST, boolean, validate_target
from .container_tools import CommandRunner, OperationError, safe_error


def expected_targets(payload: object) -> list[dict]:
    targets = rows(payload, "expected targets")
    if not targets:
        raise ValueError("expected targets must not be empty")
    validated, identities = [], set()
    for target in targets:
        target = obj(target, "expected target")
        if set(target) != {"name", "platform", "image", "tracking_reference"}:
            raise ValueError("expected target requires name, platform, image, tracking_reference")
        value = validate_target({key: target[key] for key in ("name", "platform", "image")}, published=True)
        tracking = text(target["tracking_reference"], "tracking reference")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", tracking):
            raise ValueError("invalid registry tracking reference")
        def repository(reference):
            last = reference.rsplit("/", 1)[-1]
            return reference.rsplit(":", 1)[0] if ":" in last else reference
        if repository(value["image"].split("@", 1)[0]) != repository(tracking):
            raise ValueError("tracking reference must name the assessed image repository")
        identity = (value["name"], value["platform"])
        if identity in identities:
            raise ValueError("duplicate expected target")
        identities.add(identity)
        value["tracking_reference"] = tracking
        validated.append(value)
    return validated


def aggregate(reports: list[dict], expected: list[dict], repository: str,
              *, run_id: str | None = None, run_attempt: str | None = None) -> dict:
    expected = expected_targets(expected)
    wanted = {(target["name"], target["platform"]): target for target in expected}
    seen, groups, errors = set(), {}, []
    for report in reports:
        report = obj(report, "scan report")
        if report.get("schema") != 1 or report.get("kind") != "published":
            raise ValueError("only schema 1 published-image reports may manage issues")
        if report.get("repository") != repository:
            raise ValueError("scan report belongs to a different repository")
        if ((run_id is not None and report.get("run_id") != run_id) or
                (run_attempt is not None and report.get("run_attempt") != run_attempt)):
            raise ValueError("scan report belongs to a different workflow run or attempt")
        target = validate_target(report.get("target"), published=True)
        identity = (target["name"], target["platform"])
        if identity not in wanted or identity in seen:
            raise ValueError("unexpected or duplicate scan target")
        seen.add(identity)
        if target["image"] != wanted[identity]["image"]:
            raise ValueError("scan report does not match expected published digest")
        statuses = obj(report.get("scanners"), "scanner outcomes")
        if any(key not in {"trivy", "scout", "kev"} or value not in {"complete", "error"}
               for key, value in statuses.items()):
            raise ValueError("invalid scanner outcomes")
        raw_errors = rows(report.get("errors"), "assessment errors")
        errors.extend(text(error, "assessment error") for error in raw_errors)
        complete = statuses == {"trivy": "complete", "scout": "complete", "kev": "complete"}
        if not complete or raw_errors or report.get("report_status") != "complete":
            errors.append(f"Incomplete assessment: {target['name']}/{target['platform']}")
        if complete and (not isinstance(report.get("image_id"), str) or
                         not DIGEST.fullmatch(report["image_id"])):
            raise ValueError("complete report has no immutable image ID")
        for item in rows(report.get("findings"), "findings"):
            item = obj(item, "finding")
            source = item.get("source")
            if source not in {"trivy", "scout"} or type(item.get("kev")) is not bool:
                raise ValueError("invalid finding source or KEV flag")
            if item["kev"] and source != "scout":
                raise ValueError("only the Scout KEV assessment supplies KEV findings")
            if statuses.get("kev" if item["kev"] else source) != "complete":
                raise ValueError("finding belongs to an unsuccessful scanner")
            namespace = text(item["namespace"], "package namespace") if item["namespace"] else ""
            purl = f"pkg:{text(item['package_type'], 'package type')}/" + (
                namespace + "/" if namespace else "") + text(item["package"], "package name")
            checked = finding(item["id"], purl, item["version"], item["severity"],
                              text(item["distro"], "distro"), source, url=item["url"],
                              fix=item["fix"], kev=item["kev"])
            if checked != item:
                raise ValueError("finding identity or schema does not match normalized data")
            if not item["kev"] and item["severity"] not in {"HIGH", "CRITICAL"}:
                raise ValueError("ordinary report contains a finding outside reporting severity")
            group = groups.setdefault(item["key"], {**item, "observations": [], "images": [],
                                                   "run_url": ""})
            observation = {**item, "name": target["name"], "platform": target["platform"]}
            if observation not in group["observations"]:
                group["observations"].append(observation)
            if target["image"] not in group["images"]:
                group["images"].append(target["image"])
            group["kev"] = group["kev"] or item["kev"]
            run_id = report.get("run_id", "")
            if isinstance(run_id, str) and run_id.isdigit():
                group["run_url"] = f"https://github.com/{repository}/actions/runs/{run_id}"
        if statuses.get("kev") == "complete":
            expected_kev = "found" if any(item["kev"] for item in report["findings"]) else "clear"
            if report.get("kev_status") != expected_kev:
                raise ValueError("KEV status does not match findings")
    for identity in wanted.keys() - seen:
        errors.append(f"Missing assessment: {identity[0]}/{identity[1]}")
    for group in groups.values():
        group["observations"].sort(key=lambda row: tuple(str(row[key]) for key in
                                                        ("name", "platform", "source", "version", "kev")))
    return {"schema": 1, "complete": not errors, "errors": errors, "groups": groups}


def check_current(expected: list[dict], runner) -> None:
    checked = {}
    for target in expected:
        reference = target["tracking_reference"]
        if reference not in checked:
            payload = obj(json.loads(runner(["docker", "buildx", "imagetools", "inspect",
                                             reference, "--format", "{{json .}}"])), "manifest inspection")
            manifest = obj(payload.get("manifest"), "registry manifest")
            digest = manifest.get("digest")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ValueError("registry inspection returned no manifest digest")
            checked[reference] = digest
        if target["image"].rsplit("@", 1)[1] != checked[reference]:
            raise ValueError(f"Published image changed since scan: {reference}")


def ensure_trusted_write(env: dict) -> None:
    if env.get("GITHUB_EVENT_NAME") not in {"schedule", "push", "workflow_dispatch"}:
        raise ValueError("issue writes require a trusted scheduled, push, or manual event")
    event = obj(json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text()), "workflow event")
    repository = obj(event.get("repository"), "event repository")
    if repository.get("full_name") != env.get("GITHUB_REPOSITORY"):
        raise ValueError("event repository does not match issue repository")
    branch = text(repository.get("default_branch"), "default branch")
    if env.get("GITHUB_REF") != f"refs/heads/{branch}":
        raise ValueError("issue writes require the default branch")


def reconcile(reports: list[dict], expected: list[dict], scope: str, client: IssueClient,
              *, dry_run: bool = True, runner=None) -> dict:
    scope = text(scope, "reporting scope")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", scope):
        raise ValueError("reporting scope must be a short identifier")
    expected = expected_targets(expected)
    result = aggregate(reports, expected, client.repository,
                       run_id=os.environ.get("GITHUB_RUN_ID"),
                       run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"))
    # Stale evidence must not create, update, or resolve deployed-image issues.
    check_current(expected, runner or CommandRunner())
    issues = client.list_issues()
    actions = plan_issues(scope, result["groups"], issues,
                         complete=result["complete"], client=client,
                         resolution_images=[target["image"] for target in expected])
    result["actions"] = actions
    result["dry_run"] = dry_run
    result["applied"] = []
    if not dry_run:
        for action in actions:
            # Callers must serialize this reporting scope with publication.
            # Recheck before each write to catch a superseding publication.
            try:
                check_current(expected, runner or CommandRunner())
                issue = client.write(action)
                result["applied"].append({"operation": action["operation"], "number": issue["number"],
                                          "url": issue.get("html_url", "")})
            except (OSError, ValueError, RuntimeError) as error:
                result["complete"] = False
                result["errors"].append(safe_error(str(error)))
                break  # Preserve prior successful writes; never hide partial reconciliation.
    return result


def main() -> int:
    env = os.environ
    output = Path(env.get("SECURITY_REPORT_OUTPUT", "container-security-report.json"))
    result = {"schema": 1, "complete": False, "errors": [], "actions": [], "applied": []}
    status = 2
    try:
        text(str(output), "aggregate output path")
        dry_run = boolean(env.get("SECURITY_DRY_RUN", "true"))
        if not dry_run:
            ensure_trusted_write(env)
        expected = expected_targets(json.loads(Path(env["SECURITY_EXPECTED_TARGETS"]).read_text()))
        root = Path(env["SECURITY_REPORTS"])
        reports = [json.loads(path.read_text()) for path in sorted(root.rglob("report.json"))]
        client = IssueClient(env.get("GITHUB_TOKEN", ""), env.get("GITHUB_REPOSITORY", ""))
        result = reconcile(reports, expected, env.get("SECURITY_SCOPE", ""), client, dry_run=dry_run)
        status = 0 if result["complete"] else 2
    except (KeyError, OSError, ValueError, RuntimeError) as error:
        result["errors"].append(safe_error(str(error)))
        print(f"Container reporting failed: {safe_error(str(error))}", file=sys.stderr)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        if env.get("GITHUB_OUTPUT"):
            with Path(env["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write(f"report-path={output.resolve()}\n")
                stream.write(f"report-status={'complete' if result['complete'] else 'incomplete'}\n")
        if env.get("GITHUB_STEP_SUMMARY"):
            with Path(env["GITHUB_STEP_SUMMARY"]).open("a") as stream:
                stream.write("\nContainer vulnerability reporting: " + (
                    "complete" if result["complete"] else "incomplete") + ".\n")
                for action in result["actions"]:
                    stream.write(f"\n- {action['operation']}: {action['payload'].get('title', action['key'])}\n")
                for issue in result["applied"]:
                    stream.write(f"\n- {issue['operation']}: {issue['url']}\n")
                for error in result["errors"]:
                    stream.write(f"\nAssessment error: {error}\n")
    except (OSError, ValueError) as error:
        print(f"Could not retain container report: {safe_error(str(error))}", file=sys.stderr)
        return 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
