"""Persist bounded evidence for issue transitions across ephemeral runners."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone

from .container_findings import OS_PACKAGE_TYPES, finding, package_purl
from .container_packages import (
    APPLICATION_TYPES,
    application_fixed,
    application_version,
    digest,
)

STATE = re.compile(r"<!-- salty-container-tracking:([^\n]+) -->")
STATUSES = {
    "detected": "Detected in published images.",
    "incomplete": "Assessment incomplete. Last known exposure is retained.",
    "pending": "Not detected. Awaiting a second complete assessment at least six hours later.",
    "review": "Not detected. Remediation is unverified; review is required.",
    "resolved": "Fixed package or package removal verified in published images.",
}
OS_REASONS = frozenset({"package removed", "vendor fixed version installed"})
APPLICATION_REASONS = frozenset(
    {"application package removed", "fixed application version installed"}
)
COMPLETE_SCANNERS = {"trivy": "complete", "scout": "complete", "kev": "complete"}


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("assessment timestamps require a timezone")
    return parsed.astimezone(timezone.utc)


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
            or set(target) - {"sources"} != {"name", "platform", "packages"}
            or not isinstance(target["name"], str)
            or not isinstance(target["platform"], str)
            or not isinstance(target["packages"], list)
            or any(
                not isinstance(p, dict)
                or set(p) != {"name", "version"}
                or not all(isinstance(v, str) for v in p.values())
                for p in target["packages"]
            )
            # Application language results that listed the package; older
            # states have none and so cannot prove removal.
            or not isinstance(target.get("sources", []), list)
            or any(
                not isinstance(source, dict)
                or set(source) != {"type", "target"}
                or not all(isinstance(v, str) for v in source.values())
                for source in target.get("sources", [])
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
    reasons = (
        OS_REASONS | APPLICATION_REASONS
        if group is None
        else OS_REASONS
        if group["package_type"] in OS_PACKAGE_TYPES
        else APPLICATION_REASONS
    )
    for target in verification:
        if (
            not isinstance(target, dict)
            or not all(
                isinstance(target.get(k), str)
                for k in ("name", "platform", "image", "inventory_sha256", "reason")
            )
            or target["reason"] not in reasons
            or not isinstance(target.get("packages", []), list)
            or any(
                not isinstance(p, dict)
                or not all(isinstance(p.get(k), str) for k in ("name", "version"))
                for p in target.get("packages", [])
            )
            # An installed application fix names its packages; removal has none.
            or (
                target["reason"] in APPLICATION_REASONS
                and (target["reason"] == "fixed application version installed")
                != bool(target.get("packages"))
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


def application_name(group: dict) -> str:
    """The package name Trivy lists for an application finding's PURL identity."""
    if group["namespace"]:
        return group["namespace"] + "/" + group["package"]
    return group["package"]


def application_matches(
    group: dict, inventory: dict
) -> tuple[list[dict], list[dict]] | None:
    """Every listed instance of an application finding's package, and the
    language results (type and target) that list it.

    None means the inventory cannot support a proof: it is incomplete, the
    ecosystem is unsupported, or another ecosystem lists the same name.
    Names compare case-insensitively, which can only add instances.
    """
    kinds = APPLICATION_TYPES.get(group["package_type"])
    applications = inventory.get("applications") or {}
    if kinds is None or applications.get("status") != "complete":
        return None
    name = application_name(group).casefold()
    found, sources = set(), set()
    for result in applications["results"]:
        for package in result["packages"]:
            if package["name"].casefold() != name:
                continue
            if result["type"] not in kinds:
                return None
            found.add((package["name"], package["version"]))
            sources.add((result["type"], result["target"]))
    return (
        [{"name": n, "version": v} for n, v in sorted(found)],
        [{"type": t, "target": path} for t, path in sorted(sources)],
    )


def application_packages(group: dict, inventory: dict) -> list[dict] | None:
    matches = application_matches(group, inventory)
    return None if matches is None else matches[0]


def application_removed(group: dict, affected: dict, inventory: dict) -> bool:
    """Removal needs the same analysed results, which no longer list the package.

    A binary that Trivy no longer analyses, or a state that recorded no
    results, would make the package only look absent.
    """
    kinds = APPLICATION_TYPES.get(group["package_type"], frozenset())
    sources = affected.get("sources", [])
    current = {
        (result["type"], result["target"]): result
        for result in inventory["applications"]["results"]
    }
    name = application_name(group).casefold()
    return bool(sources) and all(
        source["type"] in kinds
        and (source["type"], source["target"]) in current
        and not any(
            package["name"].casefold() == name
            for package in current[source["type"], source["target"]]["packages"]
        )
        for source in sources
    )


def application_baseline(group: dict) -> list[dict]:
    """Vulnerable application packages, including states with no package list.

    Older states recorded application targets without packages, so the
    scanner observations supply the affected name and versions.
    """
    versions = {group["version"], *(row["version"] for row in group["observations"])}
    return [{"name": application_name(group), "version": v} for v in sorted(versions)]


def application_remediation(group: dict, affected: dict, target: dict) -> dict | None:
    if target.get("scanners") != COMPLETE_SCANNERS:
        return None
    inventory = target.get("inventory", {})
    current = application_packages(group, inventory)
    if current is None or not isinstance(inventory.get("sha256"), str):
        return None
    evidence = {
        "name": affected["name"],
        "platform": affected["platform"],
        "image": target["image"],
        "inventory_sha256": inventory["sha256"],
    }
    if not current:
        if not application_removed(group, affected, inventory):
            return None
        return {**evidence, "reason": "application package removed"}
    package_type = group["package_type"]
    advisories = [group["fix"], *(row["fix"] for row in group["observations"])]
    baseline = application_baseline(group)
    # A detected version that the advisories call fixed means the version
    # scheme or advisory data is inconsistent, so nothing can be proven.
    if (
        any(application_version(package_type, p["version"]) is None for p in baseline)
        or any(
            application_fixed(package_type, p["version"], advisories) for p in baseline
        )
        or not all(
            application_fixed(package_type, p["version"], advisories) for p in current
        )
    ):
        return None
    return {
        **evidence,
        "reason": "fixed application version installed",
        "packages": current,
    }


def matching_packages(group: dict, inventory: dict) -> list[dict]:
    if group["package_type"] not in OS_PACKAGE_TYPES:
        return application_packages(group, inventory) or []
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
        if target is not None and group["package_type"] not in OS_PACKAGE_TYPES:
            item = application_remediation(group, affected, target)
            if item is None:
                return None
            proof.append(item)
            continue
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


def tracked_targets(state: dict) -> set[tuple[str, str]]:
    """Every published target an issue's closure must cover."""
    rows = [
        *state["scope"],
        *state["affected"],
        *(state.get("group") or {}).get("observations", []),
    ]
    return {(row["name"], row["platform"]) for row in rows}


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
    assessed = {(t["name"], t["platform"]) for t in assessment["targets"]}
    # Current exposure on targets outside this run's image set stays visible.
    exposure_elsewhere = state["status"] in {"detected", "incomplete"} and any(
        (row["name"], row["platform"]) not in assessed
        for row in (state["group"] or {}).get("observations", [])
    )
    if group is not None:
        # Routine scan run URLs/timestamps are not substantive issue changes.
        state["group"] = (
            {key: value for key, value in group.items() if key != "run_url"}
            if complete and not exposure_elsewhere
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
                if packages and group["package_type"] not in OS_PACKAGE_TYPES:
                    matches = application_matches(group, target["inventory"])
                    if matches is not None:
                        known[identity]["sources"] = matches[1]
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
    elif exposure_elsewhere:
        # A partial image set cannot clear targets it did not assess: their rows
        # stay as last known while the assessed, now clean targets drop out.
        state["group"] = retain_unassessed(state["group"], None, assessment)
        state["status"], state["pending"] = "detected", None
        state.pop("verification", None)
    elif state["status"] in {"review", "pending"} and not (
        tracked_targets(state) <= assessed
    ):
        pass  # Says nothing about the tracked targets; keep their confirmation.
    elif state["status"] != "resolved":
        state["status"] = "review"
        eligible = bool(
            assessment["run_id"]
            and assessment["at"]
            and tracked_targets(state) <= assessed
        )
        if eligible:
            age = (
                datetime.now(timezone.utc) - instant(assessment["at"])
            ).total_seconds()
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
