"""Shell-boundary tests for the packaged Saltbox Lint composite action."""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import threading
import unittest


ACTION = Path(__file__).resolve().parents[1] / "saltbox-lint"
VERSION = "v1.2.3"
ARCHIVE = "saltbox-lint_1.2.3_linux_amd64.tar.gz"
RECORDER = b"#!/usr/bin/env python3\nimport sys\nif sys.argv[1:] == ['--version']:\n    print('saltbox-lint version 1.2.3')\n"
FINDING = (
    b"# Examples that the linter should fix:\n"
    b"dockhand_role_docker_envs_dns_result_order: \"{{ 'verbatim' if (dns_ipv4_enabled and dns_ipv6_enabled)\n"
    b"                                             else 'ipv6first'\n"
    b"                                                  if dns_ipv6_enabled\n"
    b"                                                  else omit }}\"\n"
)


def archive(binary: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        member = tarfile.TarInfo("saltbox-lint")
        member.mode = 0o755
        member.size = len(binary)
        bundle.addfile(member, io.BytesIO(binary))
    return output.getvalue()


class ReleaseServer:
    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.requests: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(self.path)
                body = outer.files.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"


def release_files(binary: bytes, name: str = ARCHIVE) -> dict[str, bytes]:
    data = archive(binary)
    return {
        f"/{VERSION}/{name}": data,
        f"/{VERSION}/checksums.txt": f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode(),
    }


def action_command(index: int) -> str:
    metadata = (ACTION / "action.yml").read_text()
    commands = re.findall(r"^\s+run: (.+)$", metadata, re.MULTILINE)
    if len(commands) != 2:
        raise AssertionError(f"expected two packaged commands, got {commands!r}")
    return commands[index]


def shell(index: int, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", action_command(index)],
        env={**os.environ, "ACTION_PATH": str(ACTION), **env},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=15,
    )


def install_env(runner: str, server: ReleaseServer, **overrides: str) -> dict[str, str]:
    return {
        "INPUT_VERSION": VERSION,
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "RUNNER_TEMP": runner,
        "GITHUB_OUTPUT": str(Path(runner) / "output"),
        "SALTBOX_LINT_DOWNLOAD_BASE_URL": server.url,
        **overrides,
    }


class SaltboxLintActionTests(unittest.TestCase):
    def test_packaged_installer_emits_exact_binary_bytes(self):
        with tempfile.TemporaryDirectory(prefix="runner space ") as runner, ReleaseServer(
            release_files(RECORDER)
        ) as server:
            output = Path(runner) / "output"
            result = shell(0, install_env(runner, server))
            self.assertEqual(result.returncode, 0, result.stdout)
            installed = Path(output.read_text().removeprefix("binary=").strip())
            self.assertEqual(installed.read_bytes(), RECORDER)
            self.assertTrue(installed.is_relative_to(runner))

    def test_packaged_wrapper_preserves_literal_paths(self):
        with tempfile.TemporaryDirectory() as workspace:
            binary = Path(workspace) / "recorder"
            record = Path(workspace) / "argv"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['ARGV_RECORD'], 'w') as f:\n"
                "    json.dump([os.getcwd(), *sys.argv[1:]], f)\n"
            )
            binary.chmod(0o755)
            result = shell(1, {
                "SALTBOX_LINT_BINARY": str(binary),
                "GITHUB_WORKSPACE": workspace,
                "INPUT_WORKING_DIRECTORY": ".",
                "INPUT_PATHS": "a file.yml\n--fix\n$(touch injected).yml",
                "ARGV_RECORD": str(record),
            })
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(
                json.loads(record.read_text()),
                [workspace, "check", "--format", "github", "--", "a file.yml", "--fix", "$(touch injected).yml"],
            )
            self.assertFalse((Path(workspace) / "injected").exists())

    def test_installer_supports_arm64(self):
        name = "saltbox-lint_1.2.3_linux_arm64.tar.gz"
        with tempfile.TemporaryDirectory() as runner, ReleaseServer(
            release_files(RECORDER, name)
        ) as server:
            result = shell(0, install_env(runner, server, RUNNER_ARCH="ARM64"))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(server.requests, [f"/{VERSION}/{name}", f"/{VERSION}/checksums.txt"])

    def test_invalid_version_and_platform_fail_before_download(self):
        cases = [
            {"INPUT_VERSION": ""},
            {"INPUT_VERSION": "latest"},
            {"INPUT_VERSION": "v1.2"},
            {"INPUT_VERSION": "1.2.3"},
            {"INPUT_VERSION": "v01.2.3"},
            {"INPUT_VERSION": "v1.2.3; touch injected"},
            {"RUNNER_OS": "Windows"},
            {"RUNNER_ARCH": "X86"},
            {"RUNNER_TEMP": "/path/that/does/not/exist"},
            {"GITHUB_OUTPUT": ""},
        ]
        with tempfile.TemporaryDirectory() as runner, ReleaseServer(
            release_files(RECORDER)
        ) as server:
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    result = shell(0, install_env(runner, server, **overrides))
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertFalse((Path(runner) / "output").exists())
                    self.assertEqual(server.requests, [])

    def test_installer_rejects_invalid_download_override_before_request(self):
        overrides = [
            "http://localhost:1234", "http://127.0.0.1:1234/path",
            "https://127.0.0.1:1234", "http://127.0.0.1:1234; touch injected",
            "http://192.168.1.1:1234",
        ]
        with tempfile.TemporaryDirectory() as runner, ReleaseServer(
            release_files(RECORDER)
        ) as server:
            for url in overrides:
                with self.subTest(url=url):
                    result = shell(0, install_env(runner, server, SALTBOX_LINT_DOWNLOAD_BASE_URL=url))
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertEqual(server.requests, [])
                    self.assertFalse((Path(runner) / "output").exists())

    def test_installer_rejects_bad_checksums_archives_and_versions(self):
        good = release_files(RECORDER)
        checksum_path = f"/{VERSION}/checksums.txt"
        archive_path = f"/{VERSION}/{ARCHIVE}"
        checksum = good[checksum_path]
        malformed = b"not gzip"
        wrong_version = archive(RECORDER.replace(b"1.2.3", b"1.2.4"))
        cases = {
            "missing checksum": {**good, checksum_path: b""},
            "suffix checksum": {**good, checksum_path: checksum.replace(ARCHIVE.encode(), b"prefix-" + ARCHIVE.encode())},
            "duplicate checksum": {**good, checksum_path: checksum + checksum},
            "invalid checksum": {**good, checksum_path: b"not-a-checksum  " + ARCHIVE.encode() + b"\n"},
            "checksum mismatch": {**good, archive_path: b"damaged"},
            "missing archive": {checksum_path: checksum},
            "malformed archive": {**good, archive_path: malformed, checksum_path: f"{hashlib.sha256(malformed).hexdigest()}  {ARCHIVE}\n".encode()},
            "wrong binary version": {**good, archive_path: wrong_version, checksum_path: f"{hashlib.sha256(wrong_version).hexdigest()}  {ARCHIVE}\n".encode()},
        }
        for name, files in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as runner, ReleaseServer(files) as server:
                result = shell(0, install_env(runner, server))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse((Path(runner) / "output").exists())
                self.assertEqual(list(Path(runner).glob("saltbox-lint.*")), [])

    def test_wrapper_defaults_and_preserves_crlf_multiple_and_metacharacters(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            working = root / "directory with spaces"
            working.mkdir()
            binary = root / "recorder"
            record = root / "argv"
            binary.write_text(
                "#!/usr/bin/env python3\nimport json, os, sys\n"
                "with open(os.environ['ARGV_RECORD'], 'w') as f:\n"
                "    json.dump([os.getcwd(), *sys.argv[1:]], f)\n"
            )
            binary.chmod(0o755)
            base = {"SALTBOX_LINT_BINARY": str(binary), "GITHUB_WORKSPACE": workspace, "ARGV_RECORD": str(record)}
            for paths, expected in [
                ("", ["."]),
                ("a file.yml\r\nsecond.yml\r\n", ["a file.yml", "second.yml"]),
                ("`touch injected`.yml\nsemi; touch injected.yml\n--report.yml", ["`touch injected`.yml", "semi; touch injected.yml", "--report.yml"]),
                ("\n\r\n", ["."]),
            ]:
                with self.subTest(paths=paths):
                    result = shell(1, {**base, "INPUT_WORKING_DIRECTORY": "directory with spaces", "INPUT_PATHS": paths})
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(json.loads(record.read_text()), [str(working), "check", "--format", "github", "--", *expected])
            self.assertFalse((working / "injected").exists())

    def test_wrapper_preserves_cli_status_and_maps_launch_failures(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            executable = root / "fixture"
            base = {"GITHUB_WORKSPACE": workspace, "SALTBOX_LINT_BINARY": str(executable)}
            for status in (0, 1, 2, 17):
                with self.subTest(status=status):
                    executable.write_text(f"#!/usr/bin/env bash\nexit {status}\n")
                    executable.chmod(0o755)
                    result = shell(1, base)
                    self.assertEqual(result.returncode, status if status < 3 else 2, result.stdout)
            for kind in ("missing", "non-executable", "missing interpreter"):
                with self.subTest(kind=kind):
                    executable.unlink(missing_ok=True)
                    if kind != "missing":
                        executable.write_text("#!/missing/interpreter\n")
                        executable.chmod(0o755 if kind == "missing interpreter" else 0o644)
                    result = shell(1, base)
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertIn("unable to start check", result.stdout)
            executable.write_text("#!/usr/bin/env bash\nexit 0\n")
            executable.chmod(0o755)
            result = shell(1, {**base, "INPUT_WORKING_DIRECTORY": "missing"})
            self.assertEqual(result.returncode, 2, result.stdout)

    @unittest.skipUnless(os.environ.get("SALTBOX_LINT_TEST_BINARY"), "set SALTBOX_LINT_TEST_BINARY for real CLI integration")
    def test_real_binary_install_and_check_annotations_without_implicit_fix(self):
        binary = Path(os.environ["SALTBOX_LINT_TEST_BINARY"]).read_bytes()
        with tempfile.TemporaryDirectory() as runner, ReleaseServer(release_files(binary)) as server:
            result = shell(0, install_env(runner, server))
            self.assertEqual(result.returncode, 0, result.stdout)
            installed = Path((Path(runner) / "output").read_text().removeprefix("binary=").strip())
            self.assertEqual(installed.read_bytes(), binary)
            with tempfile.TemporaryDirectory() as workspace:
                root = Path(workspace) / "sandbox with spaces"
                root.mkdir()
                (root / "sandbox.yml").write_text("[]\n")
                finding = root / "finding.yml"
                finding.write_bytes(FINDING)
                for name in ("--fix", "--format=json"):
                    (root / name).mkdir()
                    (root / name / "inventory.yml").write_text("v: true\n")
                summary = Path(workspace) / "summary"
                for option_like in ("--fix", "--format=json"):
                    with self.subTest(option_like=option_like):
                        result = shell(1, {
                            "SALTBOX_LINT_BINARY": str(installed),
                            "GITHUB_WORKSPACE": workspace,
                            "GITHUB_STEP_SUMMARY": str(summary),
                            "INPUT_WORKING_DIRECTORY": "sandbox with spaces",
                            "INPUT_PATHS": f"finding.yml\n{option_like}",
                        })
                        self.assertEqual(result.returncode, 1, result.stdout)
                        self.assertIn("::error file=sandbox with spaces/finding.yml", result.stdout)
                        self.assertIn("Saltbox Lint", summary.read_text())
                        self.assertEqual(finding.read_bytes(), FINDING)


if __name__ == "__main__":
    unittest.main()
