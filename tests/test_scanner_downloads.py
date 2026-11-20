"""Scanner releases download anonymously; scanners never see GitHub tokens."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re

# Used only to run repository-owned fixtures and the downloaded scanners.
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import threading
import unittest
from collections.abc import Callable
from email.message import Message
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from salty_actions import container_tools
from salty_actions.container_scan import scan
from salty_actions.container_tools import (
    CommandRunner,
    OperationError,
    install_tool,
    release_opener,
    without_github_credentials,
)

if TYPE_CHECKING:
    # typing.Self needs Python 3.11; annotations are never evaluated at runtime.
    from typing_extensions import Self

ROOT = Path(__file__).resolve().parents[1]
# Deliberately fake credentials: any request or process that receives one fails.
TOKENS = {
    "GH_TOKEN": "ghp_fakeGhTokenNeverSentAnywhere000000000",  # nosec B105
    "GITHUB_TOKEN": "ghs_fakeGithubTokenNeverSentAnywhere0000",  # nosec B105
}
RELEASES = "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/"
ARCHIVE = "trivy_0.76.2_Linux-64bit.tar.gz"
CHECKSUMS = "trivy_0.76.2_checksums.txt"
STORAGE = (
    "https://release-assets.githubusercontent.com/github-production-release-asset/"
)


def release_archive(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as release:
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            release.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def checksums_for(archive: bytes, name: str = ARCHIVE) -> bytes:
    digest = hashlib.sha256(archive).hexdigest()
    return f"{'0' * 64}  other.tar.gz\n{digest}  {name}\n".encode()


def headers(values: dict[str, str]) -> Message:
    message = Message()
    for name, value in values.items():
        message[name] = value
    return message


class BodyResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        length: int | None = None,
        fail_after: int | None = None,
    ) -> None:
        self.status = status
        declared = len(body) if length is None else length
        self.headers = headers(
            {"Content-Length": str(declared)} if declared >= 0 else {}
        )
        self._body = io.BytesIO(body)
        self._fail_after = fail_after

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if self._fail_after is not None and self._body.tell() >= self._fail_after:
            raise IncompleteRead(b"", 1)
        if self._fail_after is not None:
            size = min(size, self._fail_after - self._body.tell())
        return self._body.read(size)


def redirect(url: str, location: str, code: int = 302) -> HTTPError:
    return HTTPError(url, code, "Found", headers({"Location": location}), io.BytesIO())


def failure(url: str, code: int, values: dict[str, str] | None = None) -> HTTPError:
    body = json.dumps({"message": f"HTTP {code} from fixture"}).encode()
    return HTTPError(url, code, "failed", headers(values or {}), io.BytesIO(body))


class ReleaseOpener:
    """Serve queued responses per URL and record every request, with no network."""

    def __init__(
        self,
        routes: dict[str, list[object]],
        on_request: Callable[[Request], None] | None = None,
    ) -> None:
        self.routes = routes
        self.requests: list[Request] = []
        self.timeouts: list[float] = []
        self.on_request = on_request

    def __call__(self, request: Request, timeout: float) -> object:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.on_request is not None:
            self.on_request(request)
        queue = self.routes.get(request.full_url)
        if not queue:
            raise AssertionError(f"unexpected request {request.full_url}")
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    @property
    def urls(self) -> list[str]:
        return [request.full_url for request in self.requests]


def trivy_routes(archive: bytes, checksums: bytes | None = None) -> dict[str, list]:
    return {
        RELEASES + CHECKSUMS: [BodyResponse(checksums or checksums_for(archive))],
        RELEASES + ARCHIVE: [BodyResponse(archive)],
    }


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "trivy"
        self.sleeps: list[float] = []
        environment = patch.dict(os.environ, TOKENS)
        environment.start()
        self.addCleanup(environment.stop)

    def install(self, opener: ReleaseOpener, name: str = "trivy", **options: Any):
        options.setdefault("sleep", self.sleeps.append)
        return install_tool(
            name,
            "v0.76.2" if name == "trivy" else "v1.29.0",
            "X64",
            self.directory,
            opener=opener,
            **options,
        )

    def assert_anonymous(self, opener: ReleaseOpener) -> None:
        self.assertTrue(opener.requests)
        for request in opener.requests:
            sent = {**request.headers, **request.unredirected_hdrs}
            self.assertEqual(
                sorted(name.casefold() for name in sent), ["accept", "user-agent"]
            )
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.data)
            for token in TOKENS.values():
                self.assertNotIn(token, request.full_url + repr(sent))

    def assert_nothing_left(self) -> None:
        if self.directory.exists():
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_installs_verified_binary_from_release_download_urls(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary", "README.md": b"docs"})
        opener = ReleaseOpener(trivy_routes(archive))

        binary = self.install(opener)

        self.assertEqual(binary, self.directory / "trivy")
        self.assertEqual(binary.read_bytes(), b"trivy-binary")
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        # Only the binary remains: the downloads and staging file are removed.
        self.assertEqual(list(self.directory.iterdir()), [binary])
        self.assertEqual(opener.urls, [RELEASES + CHECKSUMS, RELEASES + ARCHIVE])
        self.assertEqual(opener.timeouts, [60, 60])
        self.assert_anonymous(opener)
        self.assertEqual(self.sleeps, [])

    def test_scout_uses_its_own_repository_and_asset_names(self) -> None:
        releases = "https://github.com/docker/scout-cli/releases/download/v1.29.0/"
        name = "docker-scout_1.29.0_linux_amd64.tar.gz"
        archive = release_archive({"docker-scout": b"scout-binary"})
        opener = ReleaseOpener(
            {
                releases + "docker-scout_1.29.0_checksums.txt": [
                    BodyResponse(checksums_for(archive, name))
                ],
                releases + name: [BodyResponse(archive)],
            }
        )

        binary = self.install(opener, "scout")

        self.assertEqual(binary.read_bytes(), b"scout-binary")
        self.assert_anonymous(opener)

    def test_redirects_are_rebuilt_without_credentials(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary"})
        storage = STORAGE + "1?sp=r&sig=signed-storage-parameter"
        objects = "https://objects.githubusercontent.com/asset/2?X-Amz-Signature=s"
        opener = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [redirect(RELEASES + CHECKSUMS, objects, 301)],
                objects: [BodyResponse(checksums_for(archive))],
                RELEASES + ARCHIVE: [redirect(RELEASES + ARCHIVE, storage, 302)],
                storage: [redirect(storage, "/second-hop?sig=s2", 307)],
                "https://release-assets.githubusercontent.com/second-hop?sig=s2": [
                    BodyResponse(archive)
                ],
            }
        )

        self.assertEqual(self.install(opener).read_bytes(), b"trivy-binary")

        self.assertEqual(
            opener.urls,
            [
                RELEASES + CHECKSUMS,
                objects,
                RELEASES + ARCHIVE,
                storage,
                "https://release-assets.githubusercontent.com/second-hop?sig=s2",
            ],
        )
        self.assert_anonymous(opener)

    def test_untrusted_redirects_are_refused_before_any_request(self) -> None:
        for location in (
            "http://release-assets.githubusercontent.com/asset",
            "https://example.com/asset",
            "https://githubusercontent.com.example.com/asset",
            "https://user:secret@release-assets.githubusercontent.com/asset",
            "https://release-assets.githubusercontent.com:8443/asset",
            "https://release-assets.githubusercontent.com:bad/asset",
        ):
            with self.subTest(location=location):
                opener = ReleaseOpener(
                    {RELEASES + CHECKSUMS: [redirect(RELEASES + CHECKSUMS, location)]}
                )
                with self.assertRaisesRegex(OperationError, "untrusted location"):
                    self.install(opener)
                self.assertEqual(opener.urls, [RELEASES + CHECKSUMS])
                self.assertNotIn("secret", str(opener.requests))
                self.assert_nothing_left()

    def test_redirect_loops_and_missing_locations_fail(self) -> None:
        loop = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [
                    redirect(RELEASES + CHECKSUMS, RELEASES + CHECKSUMS)
                    for _ in range(6)
                ]
            }
        )
        with self.assertRaisesRegex(OperationError, "exceeded 5 redirects"):
            self.install(loop)
        self.assertEqual(len(loop.requests), 6)
        missing = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [
                    HTTPError(
                        RELEASES + CHECKSUMS, 302, "Found", Message(), io.BytesIO()
                    )
                ]
            }
        )
        with self.assertRaisesRegex(OperationError, "without a location"):
            self.install(missing)
        self.assertEqual(self.sleeps, [])

    def test_checksum_mismatch_installs_nothing(self) -> None:
        archive = release_archive({"trivy": b"tampered"})
        for checksums in (
            checksums_for(release_archive({"trivy": b"published"})),
            b"",
            # A duplicate entry is ambiguous even when one row matches.
            checksums_for(archive) + checksums_for(archive),
        ):
            with self.subTest(checksums=checksums):
                opener = ReleaseOpener(trivy_routes(archive, checksums or b"\n"))
                with self.assertRaisesRegex(OperationError, "checksum does not match"):
                    self.install(opener)
                self.assert_nothing_left()
        self.assertEqual(self.sleeps, [])

    def test_transient_failures_retry_without_leaving_partial_downloads(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary" * 1000})
        partials: list[list[Path]] = []

        def record_partials(request: Request) -> None:
            partials.append(sorted(self.directory.glob(f"trivy-*/{ARCHIVE}")))

        opener = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [
                    URLError(ConnectionResetError(104, "Connection reset by peer")),
                    BodyResponse(checksums_for(archive)),
                ],
                RELEASES + ARCHIVE: [
                    # The body stops halfway, so a partial archive is written.
                    BodyResponse(archive, fail_after=len(archive) // 2),
                    failure(RELEASES + ARCHIVE, 503),
                    failure(RELEASES + ARCHIVE, 429, {"Retry-After": "7"}),
                    BodyResponse(archive),
                ],
            },
            on_request=record_partials,
        )

        binary = self.install(opener)

        self.assertEqual(binary.read_bytes(), b"trivy-binary" * 1000)
        self.assertEqual(self.sleeps, [1, 1, 2, 7])
        self.assertEqual(len(opener.requests), 6)
        # Every retry starts without the previous attempt's partial file.
        self.assertEqual(partials, [[]] * 6)
        self.assert_anonymous(opener)

    def test_short_body_is_retried(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary"})
        opener = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [BodyResponse(checksums_for(archive))],
                RELEASES + ARCHIVE: [
                    BodyResponse(archive[:10], length=len(archive)),
                    BodyResponse(archive),
                ],
            }
        )
        self.assertEqual(self.install(opener).read_bytes(), b"trivy-binary")
        self.assertEqual(self.sleeps, [1])

    def test_transient_failures_stop_after_four_attempts(self) -> None:
        opener = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [
                    failure(RELEASES + CHECKSUMS, 502) for _ in range(4)
                ]
            }
        )
        with self.assertRaisesRegex(
            OperationError, r"trivy download failed after 4 attempts: .*HTTP 502"
        ):
            self.install(opener)
        self.assertEqual(self.sleeps, [1, 2, 4])
        self.assertEqual(len(opener.requests), 4)
        self.assert_nothing_left()

    def test_stalled_download_times_out_and_retries(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary"})
        ticks = iter([0, 1, 0, 1, 2, 1000, 0, 1, 2, 3, 4])
        opener = ReleaseOpener(
            {
                RELEASES + CHECKSUMS: [BodyResponse(checksums_for(archive))],
                RELEASES + ARCHIVE: [BodyResponse(archive), BodyResponse(archive)],
            }
        )
        binary = self.install(opener, clock=lambda: next(ticks))
        self.assertEqual(binary.read_bytes(), b"trivy-binary")
        self.assertEqual(self.sleeps, [1])

    def test_permanent_http_errors_are_not_retried(self) -> None:
        allow_list = (
            "Although you appear to have the correct authorization credentials, "
            "the `aquasecurity` organization has an IP allow list enabled"
        )
        for code, url in ((403, RELEASES + CHECKSUMS), (404, RELEASES + ARCHIVE)):
            with self.subTest(code=code):
                archive = release_archive({"trivy": b"trivy-binary"})
                routes = trivy_routes(archive)
                error = HTTPError(
                    url,
                    code,
                    "failed",
                    headers({}),
                    io.BytesIO(json.dumps({"message": allow_list}).encode()),
                )
                routes[url] = [error]
                opener = ReleaseOpener(routes)
                with self.assertRaisesRegex(OperationError, f"returned HTTP {code}"):
                    self.install(opener)
                self.assertEqual(opener.urls[-1], url)
                self.assertEqual(opener.urls.count(url), 1)
                self.assert_nothing_left()
        self.assertEqual(self.sleeps, [])

    def test_rate_limited_403_is_retried(self) -> None:
        archive = release_archive({"trivy": b"trivy-binary"})
        routes = trivy_routes(archive)
        routes[RELEASES + CHECKSUMS].insert(
            0,
            failure(
                RELEASES + CHECKSUMS,
                403,
                {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1030"},
            ),
        )
        binary = self.install(ReleaseOpener(routes), now=lambda: 1000.0)
        self.assertEqual(binary.read_bytes(), b"trivy-binary")
        self.assertEqual(self.sleeps, [30])

    def test_tls_verification_failure_is_not_retried(self) -> None:
        import ssl

        opener = ReleaseOpener(
            {RELEASES + CHECKSUMS: [URLError(ssl.SSLCertVerificationError("bad"))]}
        )
        with self.assertRaisesRegex(OperationError, "TLS certificate verification"):
            self.install(opener)
        self.assertEqual(self.sleeps, [])

    def test_size_cap_applies_to_declared_and_streamed_bodies(self) -> None:
        archive = release_archive({"trivy": os.urandom(4096)})
        with patch.object(container_tools, "ARCHIVE_LIMIT", len(archive) - 1):
            declared = ReleaseOpener(trivy_routes(archive))
            with self.assertRaisesRegex(OperationError, "exceeds"):
                self.install(declared)
            self.assert_nothing_left()
            # Without a declared length the stream is cut off at the limit.
            undeclared = trivy_routes(archive)
            undeclared[RELEASES + ARCHIVE] = [BodyResponse(archive, length=-1)]
            with self.assertRaisesRegex(OperationError, "exceeds"):
                self.install(ReleaseOpener(undeclared))
            self.assert_nothing_left()
        oversized = ReleaseOpener(
            {RELEASES + CHECKSUMS: [BodyResponse(b"x" * (1024 * 1024 + 1))]}
        )
        with self.assertRaisesRegex(OperationError, "exceeds"):
            self.install(oversized)
        self.assertEqual(self.sleeps, [])

    def test_binary_size_cap_and_unique_binary(self) -> None:
        with patch.object(container_tools, "BINARY_LIMIT", 3):
            archive = release_archive({"trivy": b"four"})
            with self.assertRaisesRegex(OperationError, "no unique supported binary"):
                self.install(ReleaseOpener(trivy_routes(archive)))
        archive = release_archive({"a/trivy": b"one", "b/trivy": b"two"})
        with self.assertRaisesRegex(OperationError, "no unique supported binary"):
            self.install(ReleaseOpener(trivy_routes(archive)))
        archive = b"not a gzip archive"
        with self.assertRaisesRegex(OperationError, "malformed"):
            self.install(ReleaseOpener(trivy_routes(archive)))
        self.assert_nothing_left()

    def test_extracts_only_the_named_binary(self) -> None:
        archive = release_archive(
            {"../../trivy": b"binary", "../../escaped-file": b"x", "trivy.sh": b"y"}
        )
        binary = self.install(ReleaseOpener(trivy_routes(archive)))
        self.assertEqual(binary.read_bytes(), b"binary")
        self.assertEqual(list(self.directory.iterdir()), [binary])
        self.assertFalse((self.directory.parent / "escaped-file").exists())
        self.assertFalse((self.directory.parent.parent / "escaped-file").exists())

    def test_invalid_requests_fail_before_any_download(self) -> None:
        opener = ReleaseOpener({})
        for name, version, architecture in (
            ("trivy", "main", "X64"),
            ("trivy", "v0.76.2-rc1", "X64"),
            ("trivy", "v0.76.2", "ARM"),
            ("other", "v0.76.2", "X64"),
        ):
            with (
                self.subTest(name=name, version=version),
                self.assertRaises(ValueError),
            ):
                install_tool(name, version, architecture, self.directory, opener=opener)
        self.assertEqual(opener.requests, [])


class _RedirectingHandler(BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).seen.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/followed")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return None


class ReleaseOpenerTests(unittest.TestCase):
    def test_real_opener_returns_redirects_instead_of_following_them(self) -> None:
        # Loopback only: the redirect handler is exercised without the network.
        _RedirectingHandler.seen = []
        server = HTTPServer(("127.0.0.1", 0), _RedirectingHandler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        self.addCleanup(thread.join)
        with patch.dict(
            os.environ,
            {"no_proxy": "*", "NO_PROXY": "*", "http_proxy": "", "HTTP_PROXY": ""},
        ):
            opener = release_opener()
        url = f"http://127.0.0.1:{server.server_address[1]}/asset"
        with self.assertRaises(HTTPError) as caught:
            opener(Request(url), timeout=10)
        with caught.exception as error:
            self.assertEqual(error.code, 302)
            self.assertEqual(error.headers["Location"], "/followed")
        thread.join()
        self.assertEqual(_RedirectingHandler.seen, ["/asset"])


class ScannerEnvironmentTests(unittest.TestCase):
    def test_github_credentials_are_removed_and_scanner_settings_kept(self) -> None:
        environment = {
            **TOKENS,
            "PATH": "/usr/bin",
            "DOCKER_SCOUT_HUB_USER": "scout-user",
            "DOCKER_SCOUT_HUB_PASSWORD": "scout-password",  # nosec B105
            "DOCKER_CONFIG": "/runner/.docker",
            "GITHUB_REPOSITORY": "saltyorg/autoscan",
        }
        self.assertEqual(
            without_github_credentials(environment),
            {
                key: value
                for key, value in environment.items()
                if key not in {"GH_TOKEN", "GITHUB_TOKEN"}
            },
        )

    def test_command_runner_passes_the_environment_to_real_processes(self) -> None:
        source = {**os.environ, **TOKENS, "DOCKER_SCOUT_HUB_USER": "scout-user"}
        runner = CommandRunner(environment=without_github_credentials(source))
        seen = json.loads(
            runner(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import json, os; print(json.dumps(dict(os.environ)))",
                ]
            )
        )
        self.assertNotIn("GH_TOKEN", seen)
        self.assertNotIn("GITHUB_TOKEN", seen)
        self.assertEqual(seen["DOCKER_SCOUT_HUB_USER"], "scout-user")
        for token in TOKENS.values():
            self.assertNotIn(token, json.dumps(seen))

    def test_command_runner_without_environment_inherits(self) -> None:
        execute = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        CommandRunner(execute=execute)(["docker", "version"])
        self.assertNotIn("env", execute.call_args.kwargs)

    def test_scan_runs_docker_and_scanners_without_github_credentials(self) -> None:
        created: list[dict] = []

        class StoppingRunner:
            def __init__(self, **options: Any) -> None:
                created.append(options)

            def __call__(self, command: list[str], **kwargs: Any) -> str:
                raise OperationError("stop after the first command")

        environment = {
            **TOKENS,
            "DOCKER_SCOUT_HUB_USER": "scout-user",
            "DOCKER_SCOUT_HUB_PASSWORD": "scout-password",  # nosec B105
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, environment),
            patch("salty_actions.container_scan.CommandRunner", StoppingRunner),
        ):
            report = scan(
                {"name": "base", "platform": "linux/amd64", "image": "local/base"},
                "candidate",
                Path(directory),
                installer=lambda *args: self.fail("installer"),
            )
        self.assertEqual(report["report_status"], "incomplete")
        [options] = created
        self.assertNotIn("GH_TOKEN", options["environment"])
        self.assertNotIn("GITHUB_TOKEN", options["environment"])
        self.assertEqual(options["environment"]["DOCKER_SCOUT_HUB_USER"], "scout-user")
        self.assertEqual(
            options["environment"]["DOCKER_SCOUT_HUB_PASSWORD"], "scout-password"
        )

    def test_action_no_longer_hands_the_token_to_the_scan_step(self) -> None:
        action = (ROOT / "container-scan/action.yml").read_text()
        self.assertNotIn("GH_TOKEN", action)
        self.assertNotIn("GITHUB_TOKEN", action)
        self.assertNotIn("github.token", action)


def pinned_version(name: str) -> str:
    action = (ROOT / "container-scan/action.yml").read_text()
    match = re.search(rf"^\s+{name}: (v\d+\.\d+\.\d+)$", action, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{name} is not pinned in container-scan/action.yml")
    return match[1]


@unittest.skipUnless(
    os.environ.get("SALTY_NETWORK_TESTS") == "1",
    "set SALTY_NETWORK_TESTS=1 to download the pinned scanner releases",
)
class NetworkInstallTests(unittest.TestCase):
    """Install the pinned releases anonymously from github.com."""

    def test_pinned_scanners_install_anonymously(self) -> None:
        architecture = {"x86_64": "X64", "aarch64": "ARM64"}[platform.machine()]
        real = release_opener()
        for name, variable, command in (
            ("trivy", "TRIVY_VERSION", ["--version"]),
            ("scout", "SCOUT_VERSION", ["version"]),
        ):
            version = pinned_version(variable)
            with self.subTest(name=name, version=version):
                requests: list[Request] = []

                def recording(request: Request, timeout: float, requests=requests):
                    requests.append(request)
                    return real(request, timeout=timeout)

                with tempfile.TemporaryDirectory() as directory:
                    binary = install_tool(
                        name, version, architecture, Path(directory), opener=recording
                    )
                    result = subprocess.run(  # nosec B603
                        [str(binary), *command],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=60,
                        env=without_github_credentials(os.environ),
                    )
                    output = result.stdout + result.stderr
                    [reported] = [
                        line.strip()
                        for line in output.splitlines()
                        if line.strip().lower().startswith("version:")
                    ]
                    self.assertIn(version.lstrip("v"), reported)
                    size = binary.stat().st_size
                hosts = []
                for request in requests:
                    self.assertIsNone(request.get_header("Authorization"))
                    hosts.append(request.host)
                self.assertEqual(hosts.count("github.com"), 2)
                print(
                    f"\n{name} {version} {architecture}: {size} bytes; "
                    f"hosts {' -> '.join(hosts)}; {binary.name} reports {reported!r}",
                    flush=True,
                )
