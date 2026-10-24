"""Persist bounded evidence for issue transitions across ephemeral runners."""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime

from .container_findings import OS_PACKAGE_TYPES, finding, package_purl
from .container_packages import digest

STATE = re.compile(r"<!-- salty-container-tracking:([^\n]+) -->")
STATUSES = {
    "detected": "Detected in published images.",
    "incomplete": "Assessment incomplete. Last known exposure is retained.",
    "pending": "Not detected. Awaiting a second complete assessment at least six hours later.",
    "review": "Not detected. Remediation is unverified; review is required.",
    "resolved": "Fixed package or package removal verified in published images.",
}


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("assessment timestamps require a timezone")
    return parsed.astimezone(UTC)


def read_state(body: str) -> dict | None:
    matches = STATE.findall(body)
    if not matches:
        if "<!-- salty-container-tracking:" in body:
            raise ValueError("malformed container tracking state")
        return None
    if len(matches) != 1 or len(matches[0]) > 40000:
        raise ValueError("duplicate or oversized container tracking state")
    value = json.loads(matches[0])
    if (
        not isinstance(value, dict)
        or not {
            "schema",
            "group",
            "affected",
            "scope",
            "status",
            "pending",
            "history",
            "evidence",
        }.issubset(value)
        or value.get("schema") != 1
        or value.get("status") not in STATUSES
        or not isinstance(value.get("affected"), list)
        or not isinstance(value.get("scope"), list)
        or not isinstance(value.get("history"), list)
        or len(value["history"]) > 5
    ):
        raise ValueError("invalid container tracking state")
    for entry in [value["evidence"], *value["history"]]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("at"), str)
            or not isinstance(entry.get("run_id"), str)
            or (entry["run_id"] and not entry["run_id"].isdigit())
            or ("status" in entry and entry["status"] not in STATUSES)
        ):
            raise ValueError("invalid tracking transition evidence")
        if entry["at"]:
            instant(entry["at"])
    group = value.get("group")
    if group is not None and (
        not isinstance(group, dict)
        or not isinstance(group.get("key"), str)
        or not isinstance(group.get("observations"), list)
    ):
        raise ValueError("invalid tracked finding baseline")
    if group is not None:
        try:
            for record in [group, *group["observations"]]:
                purl = package_purl(
                    record["package_type"], record["namespace"], record["package"]
                )
                normalized = finding(
                    record["id"],
                    purl,
                    record["version"],
                    record["severity"],
                    record["distro"],
                    record["source"],
                    url=record["url"],
                    fix=record["fix"],
                    kev=record["kev"],
                )
                if normalized["key"] != group["key"] or record["key"] != group["key"]:
                    raise ValueError("stored finding identity mismatch")
                if record.get("evidence_status") not in {None, "last known"}:
                    raise ValueError("invalid stored evidence status")
                availability = record.get("availability", {})
                if not isinstance(availability, dict) or any(
                    not isinstance(availability.get(key, []), list)
                    or any(not isinstance(v, str) for v in availability.get(key, []))
                    for key in ("versions", "candidates")
                ):
                    raise ValueError("invalid stored fix availability")
            if not isinstance(group.get("images"), list) or not all(
                isinstance(v, str) for v in group["images"]
            ):
                raise ValueError("invalid stored image evidence")
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("invalid tracked finding baseline") from error
    for target in value["affected"]:
        if (
            not isinstance(target, dict)
            or set(target) != {"name", "platform", "packages"}
            or not isinstance(target["name"], str)
            or not isinstance(target["platform"], str)
            or not isinstance(target["packages"], list)
            or any(
                not isinstance(p, dict)
                or set(p) != {"name", "version"}
                or not all(isinstance(v, str) for v in p.values())
                for p in target["packages"]
            )
        ):
            raise ValueError("invalid tracked package baseline")
    for target in value["scope"]:
        if (
            not isinstance(target, dict)
            or set(target) != {"name", "platform"}
            or not all(isinstance(v, str) for v in target.values())
        ):
            raise ValueError("invalid tracked scope")
    pending = value.get("pending")
    if pending is not None:
        if (
            not isinstance(pending, dict)
            or set(pending) != {"run_id", "at", "baseline"}
            or not all(isinstance(v, str) for v in pending.values())
            or not pending["run_id"].isdigit()
        ):
            raise ValueError("invalid clean confirmation")
        instant(pending["at"])
    if value["status"] == "resolved" and (
        not group or not pending or not value.get("verification")
    ):
        raise ValueError("resolved tracking state lacks confirmation evidence")
    verification = value.get("verification", [])
    if not isinstance(verification, list):
        # Stored JSON validation shares the scanner/report ValueError contract.
        raise ValueError("invalid published remediation evidence")  # noqa: TRY004
    for target in verification:
        if (
            not isinstance(target, dict)
            or not all(
                isinstance(target.get(k), str)
                for k in ("name", "platform", "image", "inventory_sha256", "reason")
            )
            or target["reason"]
            not in {"package removed", "vendor fixed version installed"}
            or not isinstance(target.get("packages", []), list)
            or any(
                not isinstance(p, dict)
                or not all(isinstance(p.get(k), str) for k in ("name", "version"))
                for p in target.get("packages", [])
            )
        ):
            raise ValueError("invalid published remediation evidence")
    return value


def state_comment(state: dict) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"))
    # Prevent scanner/package strings from terminating the hidden HTML comment.
    encoded = encoded.replace("--", "\\u002d\\u002d")
    if len(encoded) > 40000:
        raise ValueError("container tracking state exceeds supported size")
    return "<!-- salty-container-tracking:" + encoded + " -->"


def matching_packages(group: dict, inventory: dict) -> list[dict]:
    if (
        inventory.get("status") != "complete"
        or inventory.get("distro") != group["distro"]
        or group["package_type"] not in OS_PACKAGE_TYPES
    ):
        return []
    return [
        p
        for p in inventory["packages"]
        if group["package"] in {p["name"], p["source_name"]}
    ]


def remediation(previous: dict, assessment: dict) -> list[dict] | None:
    group = previous.get("group")
    if not group or not previous["affected"]:
        return None
    targets = {(t["name"], t["platform"]): t for t in assessment["targets"]}
    proof = []
    for affected in previous["affected"]:
        target = targets.get((affected["name"], affected["platform"]))
        if target is None or not affected["packages"]:
            return None
        inventory = target.get("inventory", {})
        if (
            inventory.get("status") != "complete"
            or inventory.get("distro") != group["distro"]
            or inventory.get("eosl")
        ):
            return None
        evidence = {
            "name": affected["name"],
            "platform": affected["platform"],
            "image": target["image"],
            "inventory_sha256": inventory["sha256"],
        }
        current = matching_packages(group, inventory)
        if not current:
            # Require absence of both the binary names and the advisory source.
            names = {p["name"] for p in inventory["packages"]}
            if any(p["name"] in names for p in affected["packages"]):
                return None
            proof.append({**evidence, "reason": "package removed"})
            continue
        old = {p["name"]: p["version"] for p in affected["packages"]}
        if any(old.get(p["name"]) == p["version"] for p in current):
            return None
        availability = target.get("availability", {})
        if availability.get("status") != "complete" or group[
            "key"
        ] not in availability.get("remediated", []):
            return None
        proof.append(
            {
                **evidence,
                "reason": "vendor fixed version installed",
                "packages": [
                    {"name": p["name"], "version": p["version"]} for p in current
                ],
            }
        )
    return proof


def retain_unassessed(
    previous: dict | None, group: dict | None, assessment: dict
) -> dict | None:
    """Keep last known observations only where current scanner coverage is absent."""
    if group is not None:
        merged = copy.deepcopy(group)
    elif previous is not None:
        merged = copy.deepcopy(previous)
    else:
        return None
    targets = {(t["name"], t["platform"]): t for t in assessment["targets"]}

    def current_fields(row):
        return {key: value for key, value in row.items() if key != "evidence_status"}

    def identity(row):
        return json.dumps(current_fields(row), sort_keys=True, separators=(",", ":"))

    observations = {
        identity(row): current_fields(row)
        for row in (group or {}).get("observations", [])
    }
    retained = False
    for row in (previous or {}).get("observations", []):
        target = targets.get((row["name"], row["platform"]), {})
        scanners = target.get("scanners")
        scanner = "kev" if row["kev"] else row["source"]
        if isinstance(scanners, dict) and scanners.get(scanner) == "complete":
            continue
        key = identity(row)
        if key not in observations:
            observations[key] = {**row, "evidence_status": "last known"}
            retained = True
    merged["observations"] = sorted(
        observations.values(),
        key=lambda row: (
            *(
                str(row[key])
                for key in ("name", "platform", "source", "version", "kev")
            ),
            identity(row),
        ),
    )
    images = set((group or {}).get("images", []))
    if retained:
        # Older normalized observations have no per-row image digest mapping.
        images.update((previous or {}).get("images", []))
    merged["images"] = sorted(images)
    merged["kev"] = any(row["kev"] for row in merged["observations"])
    merged.pop("run_url", None)
    return merged


def evolve(
    previous: dict | None,
    group: dict | None,
    assessment: dict | None,
    *,
    complete: bool,
) -> dict:
    previous = copy.deepcopy(previous)
    state = (
        copy.deepcopy(previous)
        if previous
        else {
            "schema": 1,
            "group": None,
            "affected": [],
            "scope": [],
            "status": "review",
            "pending": None,
            "history": [],
        }
    )
    assessment = assessment or {"targets": [], "run_id": "", "at": ""}
    scope = sorted(
        ({"name": t["name"], "platform": t["platform"]} for t in assessment["targets"]),
        key=lambda t: (t["name"], t["platform"]),
    )
    if group is not None:
        # Routine scan run URLs/timestamps are not substantive issue changes.
        state["group"] = (
            {key: value for key, value in group.items() if key != "run_url"}
            if complete
            else retain_unassessed(state["group"], group, assessment)
        )
        known = {(t["name"], t["platform"]): t for t in state["affected"]}
        for observation in group["observations"]:
            identity = observation["name"], observation["platform"]
            target: dict = next(
                (
                    t
                    for t in assessment["targets"]
                    if (t["name"], t["platform"]) == identity
                ),
                {},
            )
            packages = matching_packages(group, target.get("inventory", {}))
            # A missing inventory must not erase an earlier trustworthy baseline.
            if packages or identity not in known:
                known[identity] = {
                    "name": identity[0],
                    "platform": identity[1],
                    "packages": [
                        {"name": p["name"], "version": p["version"]} for p in packages
                    ],
                }
        state["affected"] = [known[key] for key in sorted(known)]
        if complete and scope:
            state["scope"] = scope
        state["status"] = "detected" if complete else "incomplete"
        state["pending"] = None
        state.pop("verification", None)
    elif not complete:
        state["group"] = retain_unassessed(state["group"], None, assessment)
        state["status"], state["pending"] = "incomplete", None
        state.pop("verification", None)
    elif state["status"] != "resolved":
        state["status"] = "review"
        eligible = bool(
            assessment["run_id"] and assessment["at"] and scope == state["scope"]
        )
        if eligible:
            age = (datetime.now(UTC) - instant(assessment["at"])).total_seconds()
            eligible = 0 <= age <= 86400
        proof = remediation(state, assessment) if eligible else None
        if proof:
            state["verification"] = proof
            baseline = digest(
                [
                    {
                        "name": t["name"],
                        "platform": t["platform"],
                        "image_id": t.get("image_id"),
                        "inventory_sha256": t.get("inventory", {}).get("sha256"),
                        "configuration": {
                            k: t.get("provenance", {}).get(k)
                            for k in (
                                "trivy_version",
                                "scout_version",
                                "configuration_sha256",
                            )
                        },
                    }
                    for t in sorted(
                        assessment["targets"], key=lambda t: (t["name"], t["platform"])
                    )
                ]
            )
            pending = state["pending"]
            if pending is None or pending["baseline"] != baseline:
                state["pending"] = {
                    "run_id": assessment["run_id"],
                    "at": assessment["at"],
                    "baseline": baseline,
                }
                state["status"] = "pending"
            elif (
                pending["run_id"] != assessment["run_id"]
                and (instant(assessment["at"]) - instant(pending["at"])).total_seconds()
                >= 21600
            ):
                state["status"] = "resolved"
            else:
                state["status"] = "pending"
        else:
            state["pending"] = None
            state.pop("verification", None)

    def substantive(s):
        return {k: v for k, v in s.items() if k not in {"history", "evidence"}}

    if previous is None or substantive(previous) != substantive(state):
        state["evidence"] = {"at": assessment["at"], "run_id": assessment["run_id"]}
        transition = {"status": state["status"], **state["evidence"]}
        state["history"] = [*state["history"], transition][-5:]
    return state
