"""Freeze the complete published-image set before parallel scanning."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .container_findings import obj, rows, text
from .container_report import expected_targets
from .container_scan import DIGEST, validate_target
from .container_tools import CommandRunner, OperationError, safe_error


def freeze_targets(targets: object, *, runner=None) -> list[dict]:
    targets = rows(targets, "published targets")
    if not targets:
        raise ValueError("published targets must not be empty")
    runner = runner or CommandRunner()
    snapshots, digests = [], {}
    for target in targets:
        target = validate_target(target, published=False)
        reference = target["image"]
        if "@" in reference:
            raise ValueError("snapshot inputs must identify mutable published tags")
        if reference not in digests:
            metadata = obj(json.loads(runner(["docker", "buildx", "imagetools", "inspect",
                                               reference, "--format", "{{json .}}"])), "image inspection")
            manifest = obj(metadata.get("manifest"), "published manifest")
            digest = manifest.get("digest")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ValueError("published manifest has no supported digest")
            digests[reference] = digest
        last = reference.rsplit("/", 1)[-1]
        repository = reference.rsplit(":", 1)[0] if ":" in last else reference
        snapshots.append({"name": target["name"], "platform": target["platform"],
                          "image": repository + "@" + digests[reference],
                          "tracking_reference": reference})
    return expected_targets(snapshots)


def main() -> int:
    try:
        output = Path(os.environ.get("SECURITY_SNAPSHOT_OUTPUT", "expected-targets.json"))
        text(str(output), "snapshot output path")
        targets = freeze_targets(json.loads(os.environ.get("SECURITY_TARGETS", "")))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(targets, indent=2) + "\n")
        architectures = {"linux/amd64": "x86_64", "linux/arm64": "aarch64",
                         "linux/arm64/v8": "aarch64", "linux/arm/v7": "armv7l"}
        matrix = {"include": [{**target, "slug": target["platform"].replace("/", "-"),
                               "architecture": architectures[target["platform"]]}
                              for target in targets]}
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
                stream.write(f"expected-targets={output.resolve()}\n")
        return 0
    except (OSError, ValueError, OperationError) as error:
        print(f"Container snapshot failed: {safe_error(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
