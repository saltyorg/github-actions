"""Inventory and verify Alpine fixes without modifying published images."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .container_findings import distro_name, finding, obj, rows, text
from .container_tools import OperationError, safe_error

PACKAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,255}\Z")
VERSION = re.compile(r"[0-9][a-zA-Z0-9+_.:~-]{0,127}\Z")


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def inventory(payload: dict) -> dict:
    """Require an explicit complete OS package list, including source identities."""
    os_data = obj(obj(payload.get("Metadata"), "Trivy metadata").get("OS"), "OS")
    family = text(os_data.get("Family"), "OS family")
    distro = distro_name(family, text(os_data.get("Name"), "OS release"))
    packages = []
    covered = False
    for result in rows(payload.get("Results", []), "Trivy results"):
        if result.get("Class") != "os-pkgs" or result.get("Type") != family:
            continue
        if not isinstance(result.get("Packages"), list):
            continue
        covered = True
        for raw in result["Packages"]:
            name, version = (
                text(raw.get("Name"), "package name"),
                text(raw.get("Version"), "package version"),
            )
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "source_name": raw.get("SrcName") or name,
                    "source_version": raw.get("SrcVersion") or version,
                }
            )
    packages.sort(key=lambda item: (item["name"], item["version"]))
    if len({item["name"] for item in packages}) != len(packages):
        raise ValueError("duplicate installed OS package identity")
    result = {
        "status": "complete" if covered else "unknown",
        "distro": distro,
        "packages": packages,
        "eosl": os_data.get("EOSL", False),
    }
    return {**result, "sha256": digest(result)}


def vendor_fixes(payload: object, branch: str, repository: str) -> dict:
    data = obj(payload, "Alpine secdb")
    if data.get("distroversion") != "v" + branch or data.get("reponame") != repository:
        raise ValueError(
            "Alpine advisory database belongs to another branch/repository"
        )
    result: dict = {}
    for item in rows(data.get("packages"), "secdb packages"):
        package = obj(obj(item, "secdb entry").get("pkg"), "secdb package")
        name = text(package.get("name"), "source package")
        for version, identifiers in obj(package.get("secfixes"), "secfixes").items():
            if version == "0":  # Alpine uses zero for unfixed advisories.
                continue
            if not VERSION.fullmatch(version):
                raise ValueError("unsupported vendor fixed version")
            for identifier in rows(identifiers, "secfix identifiers"):
                # Some entries also carry aliases after a CVE identifier.
                for cve in re.findall(
                    r"\bCVE-\d{4}-\d+\b", text(identifier, "secfix identifier")
                ):
                    result.setdefault(name, {}).setdefault(cve, set()).add(version)
    return result


# Run only in a disposable container, with the application entrypoint bypassed.
# All dynamic data is passed as validated positional arguments, never shell code.
PROBE = r"""
set -eu
test "$(apk --print-arch)" = "$1"
shift
printf 'APK\t%s\n' "$(apk --version)"
cache=/tmp/salty-apk-indexes
mkdir -p "$cache"
if ! refresh=$(apk --cache-dir "$cache" update 2>&1); then
    printf 'ERROR\trepository refresh failed\n'
    exit 0
fi
case "$refresh" in *WARNING:*|*ERROR:*) printf 'ERROR\trepository refresh incomplete\n'; exit 0 ;; esac
# Retain hashes rather than repository URLs, which can contain credentials.
for path in /etc/apk/repositories /etc/apk/world /etc/apk/repositories.d/* "$cache"/*; do
    if test -f "$path"; then sha256sum "$path"; fi
done | while read -r sum path; do printf 'INPUT\t%s\t%s\n' "$sum" "$path"; done
while test "$#" -gt 0; do
    key=$1 package=$2 installed=$3 fixed=$4
    shift 4
    if ! apk --cache-dir "$cache" --no-network info --installed "$package=$installed" >/dev/null 2>&1; then
        printf 'ERROR\tinstalled package inventory mismatch\n'; exit 0
    fi
    comparison=$(apk version -t "$installed" "$fixed")
    case "$comparison" in '<'|'='|'>') ;; *) exit 1 ;; esac
    candidate=''
    # policy includes the installed database; it is not a repository candidate.
    if ! policy=$(apk --cache-dir "$cache" --no-network policy "$package" 2>&1); then
        printf 'ERROR\trepository policy unavailable\n'; exit 0
    fi
    case "$policy" in *WARNING:*|*ERROR:*) printf 'ERROR\trepository policy incomplete\n'; exit 0 ;; esac
    versions=$(printf '%s\n' "$policy" | awk '
        /^  [^ ]+:/ {v=$1; sub(/:$/, "", v)}
        /^    / && !/lib\/apk\/db\/installed/ {if (v != "") print v}')
    for version in $versions; do
        case "$(apk version -t "$version" "$fixed")" in '='|'>') candidate=$version ;; esac
    done
    status=not_available
    if test "$comparison" != '<'; then
        status=fixed
    elif test -n "$candidate"; then
        status=blocked
        if simulation=$(apk --cache-dir "$cache" --no-network upgrade --simulate "$package" 2>/dev/null); then
            selected=$(printf '%s\n' "$simulation" | awk -v p="$package" '
                $2 == "Upgrading" && $3 == p {v=$NF; sub(/\)$/, "", v); print v}')
            if test -n "$selected"; then
                case "$(apk version -t "$selected" "$fixed")" in '='|'>') status=installable ;; esac
            fi
        fi
    fi
    printf 'CHECK\t%s\t%s\t%s\t%s\t%s\n' "$key" "$fixed" "$comparison" "$candidate" "$status"
done
"""


def assess(
    packages: dict,
    findings: list[dict],
    target: dict,
    image_id: str,
    output: Path,
    runner,
) -> dict:
    """Keep enrichment errors separate from scanner and KEV outcomes."""
    result: dict = {
        "status": "unknown",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "errors": [],
        "fixes": {},
        "remediated": [],
        "inputs": [],
    }
    distro = packages.get("distro", "")
    if packages.get("status") != "complete":
        result["errors"].append("Complete supported OS package inventory unavailable")
        return result
    if not distro.startswith("alpine/"):
        result["status"] = "unsupported"
        return result
    if packages.get("eosl"):
        result["errors"].append("Complete supported OS package inventory unavailable")
        return result
    branch = distro.removeprefix("alpine/")
    if not re.fullmatch(r"\d+\.\d+", branch):
        raise ValueError("invalid Alpine branch")
    vendor: dict = {}
    for repository in ("main", "community"):
        path = output / f"alpine-{repository}.json"
        try:
            runner(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "30",
                    "--max-filesize",
                    "8388608",
                    "--output",
                    str(path),
                    f"https://secdb.alpinelinux.org/v{branch}/{repository}.json",
                ],
                timeout=40,
            )
            for name, fixes in vendor_fixes(
                json.loads(path.read_text()), branch, repository
            ).items():
                for identifier, versions in fixes.items():
                    vendor.setdefault(name, {}).setdefault(identifier, set()).update(
                        versions
                    )
            result["inputs"].append(
                {
                    "source": f"alpine-secdb/{repository}",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        except (OperationError, OSError, ValueError) as error:
            result["errors"].append(f"Alpine advisory lookup: {safe_error(str(error))}")
    requests: dict = {}
    by_name = {item["name"]: item for item in packages["packages"]}
    for package in packages["packages"]:
        for identifier, versions in vendor.get(package["source_name"], {}).items():
            for name in {package["name"], package["source_name"]}:
                item = finding(
                    identifier,
                    "pkg:apk/alpine/" + name,
                    package["version"],
                    "UNKNOWN",
                    distro,
                    "trivy",
                )
                request = requests.setdefault(
                    item["key"],
                    {
                        "packages": set(),
                        "versions": set(),
                        "source": "Alpine secdb",
                        "vendor": True,
                    },
                )
                request["packages"].add(package["name"])
                request["versions"].update(versions)
    for item in findings:
        if item["package_type"] != "apk" or item["distro"] != distro:
            continue
        matching = {
            p["name"]
            for p in packages["packages"]
            if item["package"] in {p["name"], p["source_name"]}
        }
        if not matching:
            continue
        request = requests.setdefault(
            item["key"],
            {
                "packages": matching,
                "versions": set(),
                "source": "scanner",
                "vendor": False,
            },
        )
        if not request["vendor"] and item["fix"]:
            request["versions"].add(item["fix"])
    arguments = []
    expected = set()
    owners = {}
    for key, request in requests.items():
        for name in sorted(request["packages"]):
            package = by_name[name]
            if (
                not PACKAGE.fullmatch(name)
                or not VERSION.fullmatch(package["version"])
                or package["source_version"] != package["version"]
            ):
                continue  # Unsupported source/binary version mapping cannot prove a fix.
            probe_key = digest([key, name])
            owners[probe_key] = key
            for version in sorted(request["versions"]):
                if not VERSION.fullmatch(version):
                    continue
                expected.add((probe_key, version))
                arguments.extend([probe_key, name, package["version"], version])
    if len(expected) > 2000:
        result["errors"].append("Alpine fix assessment exceeds supported request count")
        return result
    architecture = {
        "linux/amd64": "x86_64",
        "linux/arm64": "aarch64",
        "linux/arm64/v8": "aarch64",
        "linux/arm/v7": "armv7",
    }[target["platform"]]
    container_name = "salty-apk-fix-" + uuid4().hex
    try:
        raw = runner(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--pull=never",
                "--platform",
                target["platform"],
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--entrypoint",
                "/bin/sh",
                image_id,
                "-ec",
                PROBE,
                "apk-fix-probe",
                architecture,
                *arguments,
            ],
            timeout=240,
        )
        (output / "apk-fix-probe.txt").write_text(raw)
        checked = {}
        for line in raw.splitlines():
            fields = line.split("\t")
            if fields[0] == "ERROR":
                raise ValueError("Alpine repository refresh failed")
            if fields[0] == "APK" and len(fields) == 2:
                result["apk_version"] = fields[1]
            if fields[0] == "INPUT" and len(fields) == 3:
                result["inputs"].append({"source": fields[2], "sha256": fields[1]})
            if fields[0] != "CHECK":
                continue
            if (
                len(fields) != 6
                or (fields[1], fields[2]) not in expected
                or fields[3] not in {"<", "=", ">"}
                or fields[5] not in {"fixed", "not_available", "blocked", "installable"}
                or (fields[4] and not VERSION.fullmatch(fields[4]))
                or (fields[5] == "fixed") != (fields[3] in {"=", ">"})
                or (fields[1], fields[2]) in checked
            ):
                raise ValueError("invalid Alpine probe response")
            checked[fields[1], fields[2]] = fields
        if set(checked) != expected or "apk_version" not in result:
            raise ValueError("incomplete Alpine probe response")
        for key, request in requests.items():
            evidence = [
                value
                for (identity, _), value in checked.items()
                if owners[identity] == key
            ]
            if (
                len(evidence) != len(request["packages"]) * len(request["versions"])
                or not evidence
            ):
                continue
            statuses = {value[5] for value in evidence}
            status = next(
                (
                    value
                    for value in ("not_available", "blocked", "installable", "fixed")
                    if value in statuses
                )
            )
            result["fixes"][key] = {
                "status": status,
                "source": request["source"],
                "versions": sorted(request["versions"]),
                "candidates": sorted({value[4] for value in evidence if value[4]}),
            }
            if request["vendor"] and statuses == {"fixed"}:
                result["remediated"].append(key)
        result["remediated"].sort()
        result["status"] = "complete" if not result["errors"] else "unknown"
    except (OperationError, OSError, ValueError) as error:
        result["errors"].append(f"Alpine package assessment: {safe_error(str(error))}")
    finally:
        # A timed-out Docker client can leave its container running on the daemon.
        try:
            runner(["docker", "rm", "--force", container_name], timeout=20)
        except (OperationError, OSError) as error:
            if "No such container" not in str(error):
                result["status"] = "unknown"
                result["errors"].append(f"Probe cleanup: {safe_error(str(error))}")
    return result
