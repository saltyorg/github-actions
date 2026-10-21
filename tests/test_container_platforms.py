"""Platform selection must survive Docker's multi-platform image store."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from .test_container_security import (
    IMAGE_ID,
    TARGET,
    CommandRunner,
    scan,
    scan_main,
    scout_report,
    trivy_report,
)


class PlatformTests(unittest.TestCase):
    def test_scan_selects_platform_for_inspection_and_export(self):
        for kind in ("candidate", "published"):
            for platform in (
                "linux/amd64",
                "linux/arm64",
                "linux/arm64/v8",
                "linux/arm/v7",
            ):
                with self.subTest(kind=kind, platform=platform):
                    calls: list[list[str]] = []

                    def runner(command, *, calls=calls, **kwargs):
                        calls.append(command)
                        if command[:3] == ["docker", "image", "inspect"]:
                            # A foreign-only index has no default-platform config.
                            metadata = {"Id": IMAGE_ID, "Os": "", "Architecture": ""}
                            if "--platform" in command:
                                metadata["Id"] = "sha256:" + "c" * 64
                                selected = command[command.index("--platform") + 1]
                                parts = selected.split("/")
                                metadata.update(Os=parts[0], Architecture=parts[1])
                                if len(parts) == 3:
                                    metadata["Variant"] = parts[2]
                            return json.dumps(metadata)
                        if command[0] in {"trivy", "scout"}:
                            path = Path(command[command.index("--output") + 1])
                            payload = (
                                trivy_report()
                                if command[0] == "trivy"
                                else scout_report(clean=True)
                            )
                            path.write_text(json.dumps(payload))
                        return ""

                    with tempfile.TemporaryDirectory() as directory:
                        report = scan(
                            {**TARGET, "platform": platform},
                            kind,
                            Path(directory),
                            runner=runner,
                            installer=lambda name, *args: Path(name),
                            check_fix_availability=False,
                        )
                    self.assertEqual(report["errors"], [])
                    self.assertEqual(report["report_status"], "complete")
                    self.assertEqual(report["kev_status"], "clear")
                    for operation in ("inspect", "save"):
                        command = next(
                            call
                            for call in calls
                            if call[:3] == ["docker", "image", operation]
                            and "--platform" in call
                        )
                        self.assertIn("--platform", command)
                        self.assertEqual(
                            command[command.index("--platform") + 1], platform
                        )
                    saved = next(
                        call
                        for call in calls
                        if call[:3] == ["docker", "image", "save"]
                    )
                    self.assertEqual(saved[-1], report["image_id"])
                    self.assertEqual(report["image_id"], IMAGE_ID)
                    pulls = [call for call in calls if call[:2] == ["docker", "pull"]]
                    self.assertEqual(
                        pulls,
                        [["docker", "pull", "--platform", platform, TARGET["image"]]]
                        if kind == "published"
                        else [],
                    )

    def test_assessment_errors_are_logged_with_secrets_redacted(self):
        stderr = io.StringIO()
        canary = uuid4().hex
        report = {
            "errors": [f"image snapshot: missing platform {canary}"],
            "kev_status": "unknown",
        }
        with (
            patch.dict(os.environ, {"GH_TOKEN": canary}, clear=True),
            patch("salty_actions.container_scan.scan", return_value=report),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(scan_main(), 2)
        self.assertIn("image snapshot: missing platform ***", stderr.getvalue())
        self.assertNotIn(canary, stderr.getvalue())


def image_fixture(path: Path, reference: str) -> None:
    """Build a tiny OCI index without downloads, builds, or foreign execution."""
    blobs: dict[str, bytes] = {}

    def blob(payload: dict, media_type: str) -> dict:
        data = json.dumps(payload).encode()
        checksum = hashlib.sha256(data).hexdigest()
        blobs[f"blobs/sha256/{checksum}"] = data
        return {
            "mediaType": media_type,
            "digest": f"sha256:{checksum}",
            "size": len(data),
        }

    manifests = []
    for architecture, variant in (("amd64", ""), ("arm64", "v8"), ("arm", "v7")):
        platform = {"os": "linux", "architecture": architecture}
        if variant:
            platform["variant"] = variant
        config = blob(
            {**platform, "config": {}, "rootfs": {"type": "layers", "diff_ids": []}},
            "application/vnd.oci.image.config.v1+json",
        )
        manifest = blob(
            {"schemaVersion": 2, "config": config, "layers": []},
            "application/vnd.oci.image.manifest.v1+json",
        )
        manifests.append({**manifest, "platform": platform})
    index = blob(
        {"schemaVersion": 2, "manifests": manifests},
        "application/vnd.oci.image.index.v1+json",
    )
    index["annotations"] = {
        "io.containerd.image.name": reference,
        "org.opencontainers.image.ref.name": reference,
    }
    blobs["index.json"] = json.dumps(
        {"schemaVersion": 2, "manifests": [index]}
    ).encode()
    blobs["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    with tarfile.open(path, "w") as archive:
        for name, data in blobs.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@unittest.skipUnless(
    os.environ.get("SALTY_ACTIONS_DOCKER_TEST") == "1",
    "set SALTY_ACTIONS_DOCKER_TEST=1 with a containerd Docker daemon",
)
class DockerPlatformTests(unittest.TestCase):
    def test_foreign_only_and_cached_platform_archives(self):
        docker = CommandRunner()
        reference = (
            f"docker.io/library/salty-actions-platform-test-{uuid4().hex}:fixture"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.tar"
            image_fixture(fixture, reference)
            # Only load the foreign platform first, as in the failed runner.
            docker(
                [
                    "docker",
                    "image",
                    "load",
                    "--platform",
                    "linux/arm64",
                    "-i",
                    str(fixture),
                ]
            )
            try:
                for cached in (False, True):
                    if cached:
                        docker(["docker", "image", "load", "-i", str(fixture)])
                    platforms = (
                        ("linux/amd64", "linux/arm64", "linux/arm64/v8", "linux/arm/v7")
                        if cached
                        else ("linux/arm64",)
                    )
                    for platform in platforms:
                        with self.subTest(cached=cached, platform=platform):
                            scanned: list[str] = []

                            def runner(
                                command, *, platform=platform, scanned=scanned, **kwargs
                            ):
                                if command[0] == "docker":
                                    return docker(command, **kwargs)
                                archive_path = (
                                    command[command.index("--input") + 1]
                                    if command[0] == "trivy"
                                    else command[-1].removeprefix("archive://")
                                )
                                with tarfile.open(archive_path) as archive:
                                    manifest_file = archive.extractfile("manifest.json")
                                    if manifest_file is None:
                                        raise ValueError("export lacks manifest.json")
                                    manifests = json.load(manifest_file)
                                    self.assertEqual(len(manifests), 1)
                                    config_file = archive.extractfile(
                                        manifests[0]["Config"]
                                    )
                                    if config_file is None:
                                        raise ValueError("export lacks image config")
                                    config = json.load(config_file)
                                parts = platform.split("/")
                                self.assertEqual(config["os"], parts[0])
                                self.assertEqual(config["architecture"], parts[1])
                                if len(parts) == 3:
                                    self.assertEqual(config["variant"], parts[2])
                                scanned.append(
                                    hashlib.sha256(
                                        Path(archive_path).read_bytes()
                                    ).hexdigest()
                                )
                                payload = (
                                    trivy_report()
                                    if command[0] == "trivy"
                                    else scout_report(clean=True)
                                )
                                Path(command[command.index("--output") + 1]).write_text(
                                    json.dumps(payload)
                                )
                                return ""

                            report = scan(
                                {**TARGET, "platform": platform, "image": reference},
                                "candidate",
                                root / f"scan-{cached}-{platform.replace('/', '-')}",
                                runner=runner,
                                installer=lambda name, *args: Path(name),
                            )
                            self.assertEqual(report["errors"], [])
                            self.assertEqual(report["report_status"], "complete")
                            self.assertEqual(report["kev_status"], "clear")
                            self.assertEqual(len(scanned), 3)
                            self.assertEqual(len(set(scanned)), 1)
            finally:
                docker(["docker", "image", "rm", reference])


if __name__ == "__main__":
    unittest.main()
