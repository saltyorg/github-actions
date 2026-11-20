"""Read-only subprocess operations and verified scanner release installation."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import ssl

# Calls use argv without a shell; callers validate dynamic arguments.
import subprocess  # nosec B404
import tarfile
import time
from collections.abc import Callable, Mapping
from http.client import IncompleteRead
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .transport import http_retry_delay


class Runner(Protocol):
    def __call__(self, command: list[str], *, timeout: int = 600) -> str: ...


class OperationError(RuntimeError):
    pass


# Workflow tokens never reach scanner or Docker processes. None of them needs
# one, and Trivy sends GITHUB_TOKEN to api.github.com for GitHub-hosted content
# such as its VEX hub, where an organization IP allow list rejects it.
GITHUB_CREDENTIALS = frozenset({"GH_TOKEN", "GITHUB_TOKEN"})


def without_github_credentials(environment: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in environment.items()
        if name not in GITHUB_CREDENTIALS
    }


TRANSIENT = re.compile(
    r"timeout|timed out|connection (?:reset|refused)|temporary failure|"
    r"temporary error|unexpected eof|i/o timeout|tls handshake timeout|"
    r"http(?: status)?[ :=]*(?:408|429|5\d\d)|too many requests|"
    r"rate limit|service unavailable|bad gateway|gateway timeout|"
    r"network is unreachable|no such host",
    re.IGNORECASE,
)
PERMANENT = re.compile(
    r"unauthorized|authentication required|permission denied|access denied|"
    r"manifest unknown|not found|certificate verify|x509:|unknown flag|"
    r"invalid reference|checksum",
    re.IGNORECASE,
)


def safe_error(message: str) -> str:
    for key in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "DOCKER_SCOUT_HUB_PASSWORD",
        "DOCKER_SCOUT_REGISTRY_PASSWORD",
        "DOCKER_SCOUT_REGISTRY_TOKEN",
    ):
        value = os.environ.get(key)
        if value:
            message = message.replace(value, "***")
    message = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", message)
    return " ".join(message.split())[-2000:]


class CommandRunner:
    def __init__(
        self,
        *,
        execute=subprocess.run,
        sleep=time.sleep,
        environment: Mapping[str, str] | None = None,
    ):
        self.execute = execute
        self.sleep = sleep
        # None inherits this process's environment unchanged.
        self.environment = None if environment is None else dict(environment)

    def __call__(
        self, command: list[str], *, timeout: int = 600, attempts: int = 4
    ) -> str:
        if not 1 <= attempts <= 4:
            raise ValueError("operation attempts must be between one and four")
        for attempt in range(attempts):
            options: dict[str, Any] = {}
            if self.environment is not None:
                options["env"] = self.environment
            try:
                result = self.execute(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout,
                    **options,
                )
                if result.returncode == 0:
                    return result.stdout
                detail = safe_error(
                    result.stderr or result.stdout or f"exit status {result.returncode}"
                )
                retry = bool(TRANSIENT.search(detail) and not PERMANENT.search(detail))
            except subprocess.TimeoutExpired:
                detail, retry = f"operation timed out after {timeout} seconds", True
            except OSError as error:
                raise OperationError(
                    f"could not start {command[0]}: {error.strerror}"
                ) from error
            if not retry or attempt == attempts - 1:
                raise OperationError(f"{Path(command[0]).name}: {detail}")
            retry_after = re.search(
                r"retry[- ]after\s*[:=]?\s*(\d+)", detail, re.IGNORECASE
            )
            delay = (
                int(retry_after[1])
                if retry_after
                else (
                    60
                    if re.search(
                        r"429|rate limit|too many requests", detail, re.IGNORECASE
                    )
                    else 2**attempt
                )
            )
            print(
                f"Transient {Path(command[0]).name} failure; retrying in {delay}s",
                flush=True,
            )
            self.sleep(delay)
        raise AssertionError("unreachable")


RELEASE_URL = "https://github.com/{repository}/releases/download/{tag}/{asset}"
DOWNLOAD_ATTEMPTS = 4
# One attempt, including every redirect and the whole body, must end in time.
DOWNLOAD_SECONDS = 300
SOCKET_TIMEOUT = 60
MAX_REDIRECTS = 5
CHECKSUMS_LIMIT = 1024 * 1024
ARCHIVE_LIMIT = 256 * 1024 * 1024
BINARY_LIMIT = 256 * 1024 * 1024
CHUNK = 1024 * 1024
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "saltyorg/github-actions"


class _RedirectsAsErrors(HTTPRedirectHandler):
    """Hand redirects back to the installer, which builds every hop afresh."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def release_opener() -> Callable[..., Any]:
    # No cookie, password or proxy-authentication handlers are installed, so
    # release downloads stay anonymous.
    return build_opener(_RedirectsAsErrors).open


class _Retry(Exception):
    def __init__(self, reason: str, delay: float | None = None) -> None:
        super().__init__(reason)
        self.delay = delay


def _public(url: str) -> str:
    """Drop the query, which holds signed storage parameters, from messages."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname or ''}{parts.path}"


def _check_location(url: str) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = -1
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.password is not None
        or port not in {None, 443}
        or not (host == "github.com" or host.endswith(".githubusercontent.com"))
    ):
        raise OperationError(
            f"release download refused untrusted location {_public(url)}"
        )


def _receive(
    response: Any,
    destination: Path,
    limit: int,
    deadline: float,
    clock: Callable[[], float],
) -> None:
    declared = response.headers.get("Content-Length") if response.headers else None
    expected = int(declared) if declared and declared.isdigit() else None
    if expected is not None and expected > limit:
        raise OperationError(f"{destination.name} exceeds {limit} bytes")
    received = 0
    with destination.open("wb") as stream:
        while chunk := response.read(CHUNK):
            received += len(chunk)
            if received > limit:
                raise OperationError(f"{destination.name} exceeds {limit} bytes")
            if clock() > deadline:
                raise _Retry(f"download timed out after {DOWNLOAD_SECONDS} seconds")
            stream.write(chunk)
    if expected is not None and received != expected:
        raise _Retry(f"{destination.name} ended after {received} of {expected} bytes")


def _fetch(
    url: str,
    destination: Path,
    limit: int,
    attempt: int,
    *,
    opener: Callable[..., Any],
    clock: Callable[[], float],
    now: Callable[[], float],
) -> None:
    deadline = clock() + DOWNLOAD_SECONDS
    for _hop in range(MAX_REDIRECTS + 1):
        _check_location(url)
        if clock() > deadline:
            raise _Retry(f"download timed out after {DOWNLOAD_SECONDS} seconds")
        # Every hop is a new request with fixed headers, so a redirect never
        # inherits a header, and no request carries credentials.
        request = Request(
            url,
            headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT},
        )
        try:
            with opener(request, timeout=SOCKET_TIMEOUT) as response:
                if response.status != 200:
                    raise OperationError(
                        f"{_public(url)} returned HTTP {response.status}"
                    )
                _receive(response, destination, limit, deadline, clock)
                return
        except HTTPError as error:
            # The error owns the response body; close it once inspected.
            with error:
                if error.code in REDIRECT_CODES:
                    location = error.headers.get("Location") if error.headers else None
                    if not location:
                        raise OperationError(
                            f"{_public(url)} redirected without a location"
                        ) from error
                    url = urljoin(url, location)
                    continue
                detail = f"{_public(url)} returned HTTP {error.code}"
                delay = http_retry_delay(error, attempt, now())
                if delay is None:
                    raise OperationError(detail) from error
                raise _Retry(detail, delay) from error
        except (
            URLError,
            TimeoutError,
            ConnectionError,
            IncompleteRead,
            ssl.SSLError,
        ) as error:
            reason = error.reason if isinstance(error, URLError) else error
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise OperationError(
                    "release download TLS certificate verification failed"
                ) from error
            raise _Retry(f"{_public(url)}: {safe_error(str(reason))}") from error
    raise OperationError(f"release download exceeded {MAX_REDIRECTS} redirects")


def _download(
    url: str,
    destination: Path,
    limit: int,
    label: str,
    *,
    opener: Callable[..., Any],
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    now: Callable[[], float],
) -> None:
    for attempt in range(DOWNLOAD_ATTEMPTS):
        try:
            _fetch(
                url,
                destination,
                limit,
                attempt,
                opener=opener,
                clock=clock,
                now=now,
            )
            return
        except _Retry as error:
            destination.unlink(missing_ok=True)
            if attempt == DOWNLOAD_ATTEMPTS - 1:
                raise OperationError(
                    f"{label} download failed after {DOWNLOAD_ATTEMPTS} attempts: "
                    f"{error}"
                ) from error
            delay = 2**attempt if error.delay is None else error.delay
            print(
                f"Transient {label} download failure ({error}); retrying in {delay}s",
                flush=True,
            )
            sleep(delay)
        except BaseException:
            # Never leave a partial asset behind, whatever ended the download.
            destination.unlink(missing_ok=True)
            raise
    raise AssertionError("unreachable")


def install_tool(
    name: str,
    version: str,
    architecture: str,
    directory: Path,
    *,
    opener: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], float] = time.time,
) -> Path:
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
    opener = opener or release_opener()
    directory.mkdir(parents=True, exist_ok=True)
    # Public release assets are downloaded anonymously. An authenticated
    # request is subject to the publishing organization's IP allow list, and
    # the published checksums file verifies the archive either way.
    with TemporaryDirectory(prefix=f"{name}-", dir=directory) as temporary:
        download = Path(temporary)
        archive = download / archive_name
        checksums_path = download / checksums_name
        for asset, path, limit in (
            (checksums_name, checksums_path, CHECKSUMS_LIMIT),
            (archive_name, archive, ARCHIVE_LIMIT),
        ):
            _download(
                RELEASE_URL.format(repository=repository, tag=version, asset=asset),
                path,
                limit,
                name,
                opener=opener,
                sleep=sleep,
                clock=clock,
                now=now,
            )
        try:
            checksums = checksums_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise OperationError(f"{name} release checksums are not text") from error
        expected = [
            row.split()[0]
            for row in checksums
            if len(row.split()) == 2 and row.split()[1].lstrip("*") == archive_name
        ]
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            # hashlib.file_digest is unavailable before Python 3.11.
            for chunk in iter(lambda: stream.read(CHUNK), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if expected != [actual]:
            raise OperationError(f"{name} release checksum does not match")
        staged = download / f"{binary_name}.staged"
        try:
            with tarfile.open(archive, "r:gz") as release:
                binaries = [
                    member
                    for member in release
                    if member.isfile() and Path(member.name).name == binary_name
                ]
                if len(binaries) != 1 or binaries[0].size > BINARY_LIMIT:
                    raise OperationError(
                        f"{name} archive has no unique supported binary"
                    )
                binary_stream = release.extractfile(binaries[0])
                if binary_stream is None:
                    raise OperationError(f"{name} archive binary cannot be read")
                with binary_stream, staged.open("wb") as output:
                    # Copy only the named binary, never extract arbitrary archive paths.
                    shutil.copyfileobj(binary_stream, output, CHUNK)
        except tarfile.TarError as error:
            raise OperationError(f"{name} release archive is malformed") from error
        staged.chmod(0o755)
        destination = directory / binary_name
        # The binary appears only once it is complete.
        os.replace(staged, destination)
        return destination
