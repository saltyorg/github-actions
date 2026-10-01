"""Scan immutable image bytes; ordinary findings are advisory."""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from .container_findings import obj, scout_findings, text, trivy_findings
from .container_tools import CommandRunner, OperationError, install_tool, safe_error
from .container_sarif import code_scanning_report

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PLATFORM = re.compile(r"linux/(?:amd64|arm64(?:/v8)?|arm/v7)\Z")


def boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("boolean input must be true or false")
    return value == "true"


def validate_target(target: object, *, published: bool) -> dict:
    target = obj(target, "target")
    if set(target) != {"name", "platform", "image"}:
        raise ValueError("target requires exactly name, platform, and image")
    name = text(target["name"], "image name")
    platform = text(target["platform"], "platform")
    image = text(target["image"], "image reference")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        raise ValueError("image name must be a short identifier")
    if not PLATFORM.fullmatch(platform):
        raise ValueError("unsupported image platform")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]*", image):
        raise ValueError("invalid Docker image reference")
    if published and ("@" not in image or not DIGEST.fullmatch(image.rsplit("@", 1)[1])):
        raise ValueError("published scans require a digest-pinned image reference")
    return {"name": name, "platform": platform, "image": image}


def sarif_report(findings: list[dict]) -> dict:
    rules = {}
    results = []
    for item in findings:
        rule_id = f"{item['source']}/{item['key']}"
        rules[rule_id] = {"id": rule_id, "name": item["id"],
                          "shortDescription": {"text": f"{item['id']} in {item['package']}"},
                          "properties": {"security-severity": {
                              "CRITICAL": "9.0", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0",
                          }.get(item["severity"], "0.0")}}
        if item["url"]:
            rules[rule_id]["helpUri"] = item["url"]
        results.append({"ruleId": rule_id, "level": "warning", "message": {
            "text": f"{item['severity']} {item['id']}: {item['package']} {item['version']}; "
                    f"fix: {item['fix'] or 'not provided by scanner'}"},
            "locations": [{"logicalLocations": [{"name": item["package"], "kind": "module"}]}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Salty container security",
                                         "rules": list(rules.values())}}, "results": results}]}


def scan(target: dict, kind: str, output: Path, *, runner=None,
         installer=install_tool, architecture: str = "X64",
         trivy_version: str = "v0.74.0", scout_version: str = "v1.26.0",
         scout_enabled: bool = True) -> dict:
    if kind not in {"candidate", "published"}:
        raise ValueError("scan kind must be candidate or published")
    target = validate_target(target, published=kind == "published")
    if kind == "published" and not scout_enabled:
        raise ValueError("published assessments require Scout and KEV coverage")
    text(str(output), "output directory")
    output.mkdir(parents=True, exist_ok=True)
    runner = runner or CommandRunner()
    report = {"schema": 1, "kind": kind, "target": target,
              "repository": os.environ.get("GITHUB_REPOSITORY", ""),
              "run_id": os.environ.get("GITHUB_RUN_ID", ""),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
              "scanned_at": datetime.now(timezone.utc).isoformat(),
              "image_id": "", "scanners": {}, "findings": [], "errors": [],
              "kev_status": "unknown", "report_status": "incomplete"}
    with TemporaryDirectory(prefix="image-", dir=output) as temporary:
        work = Path(temporary)
        try:
            if kind == "published":
                runner(["docker", "pull", "--platform", target["platform"], target["image"]])
            metadata = json.loads(runner(["docker", "image", "inspect", target["image"],
                                          "--format", "{{json .}}"] ))
            metadata = obj(metadata, "image metadata")
            image_id = metadata.get("Id")
            if not isinstance(image_id, str) or not DIGEST.fullmatch(image_id):
                raise ValueError("image inspection returned no immutable image ID")
            actual = f"{metadata.get('Os')}/{metadata.get('Architecture')}"
            variant = metadata.get("Variant")
            if variant:
                actual += f"/{variant}"
            equivalent = {target["platform"]}
            if target["platform"] in {"linux/arm64", "linux/arm64/v8"}:
                equivalent.update({"linux/arm64", "linux/arm64/v8"})
            if actual not in equivalent:
                raise ValueError(f"image platform {actual} does not match {target['platform']}")
            report["image_id"] = image_id
            archive = work / "image.tar"
            runner(["docker", "image", "save", "--output", str(archive), image_id])
            # Both scanners and KEV evaluation read the same exported image.
            for engine, version in (("trivy", trivy_version), ("scout", scout_version)):
                if engine == "scout" and not scout_enabled:
                    report["scanners"].update({"scout": "error", "kev": "error"})
                    report["errors"].append("Scout and KEV coverage disabled for this candidate run")
                    continue
                try:
                    binary = installer(engine, version, architecture, work / engine, runner)
                except (OperationError, OSError, ValueError) as error:
                    report["scanners"][engine] = "error"
                    report["errors"].append(f"{engine} setup: {safe_error(str(error))}")
                    if engine == "scout":
                        report["scanners"]["kev"] = "error"
                    continue
                modes = ("trivy",) if engine == "trivy" else ("scout", "kev")
                for mode in modes:
                    destination = output / f"{mode}.{'json' if mode == 'trivy' else 'sarif'}"
                    destination.unlink(missing_ok=True)
                    try:
                        if engine == "trivy":
                            command = [str(binary), "image", "--quiet", "--scanners", "vuln",
                                       "--format", "json", "--output", str(destination),
                                       "--input", str(archive)]
                        else:
                            command = [str(binary), "cves", "--format", "sarif", "--output",
                                       str(destination), "--platform", target["platform"]]
                            if mode == "kev":
                                command.append("--only-cisa-kev")
                            command.append(f"archive://{archive}")
                        runner(command)
                        payload = json.loads(destination.read_text())
                        findings = trivy_findings(payload) if engine == "trivy" else scout_findings(
                            payload, kev=mode == "kev")
                        if mode == "scout":
                            compatible = output / "scout-code-scanning.sarif"
                            compatible.write_text(json.dumps(code_scanning_report(payload), indent=2) + "\n")
                        report["findings"].extend(findings)
                        report["scanners"][mode] = "complete"
                        if mode == "kev":
                            report["kev_status"] = "found" if findings else "clear"
                    except (OperationError, OSError, ValueError) as error:
                        report["scanners"][mode] = "error"
                        report["errors"].append(f"{mode}: {safe_error(str(error))}")
        except (OperationError, OSError, ValueError) as error:
            report["errors"].append(f"image snapshot: {safe_error(str(error))}")
    if report["scanners"] == {"trivy": "complete", "scout": "complete", "kev": "complete"}:
        report["report_status"] = "complete"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "findings.sarif").write_text(json.dumps(sarif_report(report["findings"]), indent=2) + "\n")
    return report


def main() -> int:
    try:
        env = os.environ
        enforce = boolean(env.get("SECURITY_ENFORCE_KEV", "true"))
        if env.get("RUNNER_OS", "Linux") != "Linux":
            raise ValueError("container scanning requires a Linux runner")
        target = {"name": env.get("SECURITY_NAME", ""), "platform": env.get("SECURITY_PLATFORM", ""),
                  "image": env.get("SECURITY_IMAGE", "")}
        output = Path(env.get("SECURITY_OUTPUT", "container-security"))
        report = scan(target, env.get("SECURITY_KIND", "candidate"), output,
                      architecture=env.get("RUNNER_ARCH", "X64"),
                      trivy_version=env.get("TRIVY_VERSION", ""),
                      scout_version=env.get("SCOUT_VERSION", ""),
                      scout_enabled=boolean(env.get("SECURITY_SCOUT_ENABLED", "true")))
        if env.get("GITHUB_OUTPUT"):
            with Path(env["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write(f"report-directory={output.resolve()}\n")
                stream.write(f"report-status={report['report_status']}\nkev-status={report['kev_status']}\n")
        if env.get("GITHUB_STEP_SUMMARY"):
            with Path(env["GITHUB_STEP_SUMMARY"]).open("a") as stream:
                stream.write(f"\nContainer scan `{target['name']}` / `{target['platform']}`: "
                             f"{report['report_status']}; KEV: {report['kev_status']}; "
                             f"{len(report['findings'])} scanner findings.\n")
                for error in report["errors"]:
                    stream.write(f"\nAssessment error: {error}\n")
        if enforce and report["kev_status"] != "clear":
            print(f"KEV assessment blocks publication: {report['kev_status']}", file=sys.stderr)
            return 1 if report["kev_status"] == "found" else 2
        return 0
    except (OSError, ValueError, OperationError) as error:
        print(f"Container scan failed: {safe_error(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
