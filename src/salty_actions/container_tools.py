"""Read-only subprocess operations and verified scanner release installation."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path
from tempfile import TemporaryDirectory


class OperationError(RuntimeError):
    pass


TRANSIENT = re.compile(
    r"timeout|timed out|connection (?:reset|refused)|temporary failure|"
    r"temporary error|unexpected eof|i/o timeout|tls handshake timeout|"
    r"http(?: status)?[ :=]*(?:408|429|5\d\d)|too many requests|"
    r"rate limit|service unavailable|bad gateway|gateway timeout|"
    r"network is unreachable|no such host", re.IGNORECASE,
)
PERMANENT = re.compile(
    r"unauthorized|authentication required|permission denied|access denied|"
    r"manifest unknown|not found|certificate verify|x509:|unknown flag|"
    r"invalid reference|checksum", re.IGNORECASE,
)


def safe_error(message: str) -> str:
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "DOCKER_SCOUT_HUB_PASSWORD",
                "DOCKER_SCOUT_REGISTRY_PASSWORD", "DOCKER_SCOUT_REGISTRY_TOKEN"):
        value = os.environ.get(key)
        if value:
            message = message.replace(value, "***")
    message = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", message)
    return " ".join(message.split())[-2000:]


class CommandRunner:
    def __init__(self, *, execute=subprocess.run, sleep=time.sleep):
        self.execute = execute
        self.sleep = sleep

    def __call__(self, command: list[str], *, timeout: int = 600) -> str:
        for attempt in range(4):
            try:
                result = self.execute(command, capture_output=True, text=True,
                                      check=False, timeout=timeout)
                if result.returncode == 0:
                    return result.stdout
                detail = safe_error(result.stderr or result.stdout or
                                    f"exit status {result.returncode}")
                retry = bool(TRANSIENT.search(detail) and not PERMANENT.search(detail))
            except subprocess.TimeoutExpired:
                detail, retry = f"operation timed out after {timeout} seconds", True
            except OSError as error:
                raise OperationError(f"could not start {command[0]}: {error.strerror}") from error
            if not retry or attempt == 3:
                raise OperationError(f"{Path(command[0]).name}: {detail}")
            retry_after = re.search(r"retry[- ]after\s*[:=]?\s*(\d+)", detail, re.I)
            delay = int(retry_after[1]) if retry_after else (60 if re.search(
                r"429|rate limit|too many requests", detail, re.I) else 2 ** attempt)
            print(f"Transient {Path(command[0]).name} failure; retrying in {delay}s", flush=True)
            self.sleep(delay)
        raise AssertionError("unreachable")


def install_tool(name: str, version: str, architecture: str, directory: Path,
                 runner: CommandRunner) -> Path:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version):
        raise ValueError("scanner version must be an exact stable release tag")
    if architecture not in {"X64", "ARM64"}:
        raise ValueError("scanner installation supports Linux X64 and ARM64 runners")
    if name == "trivy":
        repository = "aquasecurity/trivy"
        platform = {"X64": "Linux-64bit", "ARM64": "Linux-ARM64"}[architecture]
        prefix, binary_name = "trivy", "trivy"
    elif name == "scout":
        repository = "docker/scout-cli"
        platform = {"X64": "linux_amd64", "ARM64": "linux_arm64"}[architecture]
        prefix, binary_name = "docker-scout", "docker-scout"
    else:
        raise ValueError("unknown scanner")
    archive_name = f"{prefix}_{version[1:]}_{platform}.tar.gz"
    checksums_name = f"{prefix}_{version[1:]}_checksums.txt"
    directory.mkdir(parents=True, exist_ok=True)
    # Use gh's authenticated release download; credentials never enter argv.
    with TemporaryDirectory(prefix=f"{name}-", dir=directory) as temporary:
        download = Path(temporary)
        runner(["gh", "release", "download", version, "--repo", repository,
                "--pattern", archive_name, "--pattern", checksums_name,
                "--dir", str(download), "--clobber"], timeout=300)
        archive = download / archive_name
        checksums = (download / checksums_name).read_text().splitlines()
        expected = [row.split()[0] for row in checksums
                    if len(row.split()) == 2 and row.split()[1].lstrip("*") == archive_name]
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected != [actual]:
            raise OperationError(f"{name} release checksum does not match")
        destination = directory / binary_name
        try:
            with tarfile.open(archive, "r:gz") as release:
                binaries = [member for member in release
                            if member.isfile() and Path(member.name).name == binary_name]
                if len(binaries) != 1 or binaries[0].size > 256 * 1024 * 1024:
                    raise OperationError(f"{name} archive has no unique supported binary")
                with release.extractfile(binaries[0]) as stream:
                    # Copy only the named binary, never extract arbitrary archive paths.
                    destination.write_bytes(stream.read())
        except tarfile.TarError as error:
            raise OperationError(f"{name} release archive is malformed") from error
        destination.chmod(0o755)
        return destination
