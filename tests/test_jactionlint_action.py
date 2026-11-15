"""Shell-boundary tests for the packaged jactionlint composite action."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess  # nosec B404 - runs only the packaged Bash entrypoints
import tarfile
import tempfile
import unittest
from pathlib import Path

from .test_saltbox_lint_action import ReleaseServer

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "jactionlint"
CONFIG_HOME = ACTION / "config"
VERSION = "v1.2.3"
ARCHIVE = "jactionlint_1.2.3_linux_amd64.tar.gz"
CHECKSUMS = "jactionlint_1.2.3_checksums.txt"
# jactionlint reports its bare version on the first line of --version.
RECORDER = (
    b"#!/usr/bin/env python3\n"
    b"import sys\n"
    b"if sys.argv[1:] == ['--version']:\n"
    b"    print('1.2.3')\n"
    b"    print('installed by downloading from release page')\n"
    b"    print('built with go1.26.0 compiler for linux/amd64')\n"
)
ARGV_RECORDER = (
    "#!/usr/bin/env python3\n"
    "import json, os, sys\n"
    "with open(os.environ['ARGV_RECORD'], 'w') as f:\n"
    "    json.dump([os.getcwd(), os.environ['XDG_CONFIG_HOME'], *sys.argv[1:]], f)\n"
)


def archive(binary: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        member = tarfile.TarInfo("jactionlint")
        member.mode = 0o755
        member.size = len(binary)
        bundle.addfile(member, io.BytesIO(binary))
    return output.getvalue()


def release_files(binary: bytes, name: str = ARCHIVE) -> dict[str, bytes]:
    data = archive(binary)
    return {
        f"/{VERSION}/{name}": data,
        f"/{VERSION}/{CHECKSUMS}": f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode(),
    }


def action_command(index: int) -> str:
    metadata = (ACTION / "action.yml").read_text()
    commands = re.findall(r"^\s+run: (.+)$", metadata, re.MULTILINE)
    if len(commands) != 2:
        raise AssertionError(f"expected two packaged commands, got {commands!r}")
    return commands[index]


def shell(index: int, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # The argv is fixed: Bash from PATH, as on a runner, and the action's own
    # run line. Fixture values reach it only through the environment.
    return subprocess.run(  # nosec B603 B607
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
        "JACTIONLINT_VERSION": VERSION,
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "RUNNER_TEMP": runner,
        "GITHUB_OUTPUT": str(Path(runner) / "output"),
        "JACTIONLINT_DOWNLOAD_BASE_URL": server.url,
        **overrides,
    }


class JactionlintActionTests(unittest.TestCase):
    def test_packaged_installer_emits_exact_binary_bytes(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="runner space ") as runner,
            ReleaseServer(release_files(RECORDER)) as server,
        ):
            output = Path(runner) / "output"
            result = shell(0, install_env(runner, server))
            self.assertEqual(result.returncode, 0, result.stdout)
            installed = Path(output.read_text().removeprefix("binary=").strip())
            self.assertEqual(installed.read_bytes(), RECORDER)
            self.assertTrue(installed.is_relative_to(runner))
            self.assertEqual(
                server.requests, [f"/{VERSION}/{ARCHIVE}", f"/{VERSION}/{CHECKSUMS}"]
            )

    def test_installer_supports_arm64(self) -> None:
        name = "jactionlint_1.2.3_linux_arm64.tar.gz"
        with (
            tempfile.TemporaryDirectory() as runner,
            ReleaseServer(release_files(RECORDER, name)) as server,
        ):
            result = shell(0, install_env(runner, server, RUNNER_ARCH="ARM64"))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(
                server.requests, [f"/{VERSION}/{name}", f"/{VERSION}/{CHECKSUMS}"]
            )

    def test_invalid_version_and_platform_fail_before_download(self) -> None:
        cases = [
            {"JACTIONLINT_VERSION": ""},
            {"JACTIONLINT_VERSION": "latest"},
            {"JACTIONLINT_VERSION": "v1.2"},
            {"JACTIONLINT_VERSION": "1.2.3"},
            {"JACTIONLINT_VERSION": "v01.2.3"},
            {"JACTIONLINT_VERSION": "v1.2.3; touch injected"},
            {"RUNNER_OS": "Windows"},
            {"RUNNER_ARCH": "X86"},
            {"RUNNER_TEMP": "/path/that/does/not/exist"},
            {"GITHUB_OUTPUT": ""},
        ]
        with (
            tempfile.TemporaryDirectory() as runner,
            ReleaseServer(release_files(RECORDER)) as server,
        ):
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    result = shell(0, install_env(runner, server, **overrides))
                    self.assertEqual(result.returncode, 3, result.stdout)
                    self.assertFalse((Path(runner) / "output").exists())
                    self.assertEqual(server.requests, [])

    def test_installer_rejects_invalid_download_override_before_request(self) -> None:
        overrides = [
            "http://localhost:1234",
            "http://127.0.0.1:1234/path",
            "https://127.0.0.1:1234",
            "http://127.0.0.1:1234; touch injected",
            "http://192.168.1.1:1234",
        ]
        with (
            tempfile.TemporaryDirectory() as runner,
            ReleaseServer(release_files(RECORDER)) as server,
        ):
            for url in overrides:
                with self.subTest(url=url):
                    result = shell(
                        0,
                        install_env(runner, server, JACTIONLINT_DOWNLOAD_BASE_URL=url),
                    )
                    self.assertEqual(result.returncode, 3, result.stdout)
                    self.assertEqual(server.requests, [])
                    self.assertFalse((Path(runner) / "output").exists())

    def test_installer_rejects_bad_checksums_archives_and_versions(self) -> None:
        good = release_files(RECORDER)
        checksum_path = f"/{VERSION}/{CHECKSUMS}"
        archive_path = f"/{VERSION}/{ARCHIVE}"
        checksum = good[checksum_path]
        name = ARCHIVE.encode()
        malformed = b"not gzip"
        wrong_version = archive(RECORDER.replace(b"'1.2.3'", b"'1.2.4'"))
        # A version that only appears after the first line is not the release.
        late_version = archive(
            RECORDER.replace(b"print('1.2.3')", b"print('dev')\n    print('1.2.3')")
        )

        def checksums_for(data: bytes) -> bytes:
            return f"{hashlib.sha256(data).hexdigest()}  {ARCHIVE}\n".encode()

        cases = {
            "missing checksum": {**good, checksum_path: b""},
            "suffix checksum": {
                **good,
                checksum_path: checksum.replace(name, b"prefix-" + name),
            },
            "duplicate checksum": {**good, checksum_path: checksum + checksum},
            "invalid checksum": {
                **good,
                checksum_path: b"not-a-checksum  " + name + b"\n",
            },
            "checksum mismatch": {**good, archive_path: b"damaged"},
            "missing archive": {checksum_path: checksum},
            "malformed archive": {
                **good,
                archive_path: malformed,
                checksum_path: checksums_for(malformed),
            },
            "wrong binary version": {
                **good,
                archive_path: wrong_version,
                checksum_path: checksums_for(wrong_version),
            },
            "version not on first line": {
                **good,
                archive_path: late_version,
                checksum_path: checksums_for(late_version),
            },
        }
        for case, files in cases.items():
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as runner,
                ReleaseServer(files) as server,
            ):
                result = shell(0, install_env(runner, server))
                self.assertEqual(result.returncode, 3, result.stdout)
                self.assertFalse((Path(runner) / "output").exists())
                self.assertEqual(list(Path(runner).glob("jactionlint.*")), [])

    def test_wrapper_checks_repository_or_literal_files_with_organization_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            working = root / "directory with spaces"
            working.mkdir()
            binary = root / "recorder"
            record = root / "argv"
            binary.write_text(ARGV_RECORDER)
            binary.chmod(0o755)
            base = {
                "JACTIONLINT_BINARY": str(binary),
                "GITHUB_WORKSPACE": workspace,
                "INPUT_WORKING_DIRECTORY": "directory with spaces",
                "ARGV_RECORD": str(record),
                # A caller-level value must not replace the packaged defaults.
                "XDG_CONFIG_HOME": str(root / "caller-config"),
            }
            for files, expected in [
                ("", []),
                ("\n\r\n", []),
                ("a file.yml\r\nsecond.yml\r\n", ["--", "a file.yml", "second.yml"]),
                (
                    "`touch injected`.yml\nsemi; touch injected.yml\n--fix\n$(touch injected).yml",
                    [
                        "--",
                        "`touch injected`.yml",
                        "semi; touch injected.yml",
                        "--fix",
                        "$(touch injected).yml",
                    ],
                ),
            ]:
                with self.subTest(files=files):
                    result = shell(1, {**base, "INPUT_FILES": files})
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(
                        json.loads(record.read_text()),
                        [
                            str(working),
                            str(CONFIG_HOME),
                            "--format",
                            "github",
                            *expected,
                        ],
                    )
            self.assertFalse((working / "injected").exists())

    def test_wrapper_defaults_to_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            binary = Path(workspace) / "recorder"
            record = Path(workspace) / "argv"
            binary.write_text(ARGV_RECORDER)
            binary.chmod(0o755)
            result = shell(
                1,
                {
                    "JACTIONLINT_BINARY": str(binary),
                    "GITHUB_WORKSPACE": workspace,
                    "ARGV_RECORD": str(record),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(
                json.loads(record.read_text()),
                [workspace, str(CONFIG_HOME), "--format", "github"],
            )

    def test_wrapper_preserves_cli_status_and_maps_launch_failures(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            executable = root / "fixture"
            base = {
                "GITHUB_WORKSPACE": workspace,
                "JACTIONLINT_BINARY": str(executable),
            }
            for status in (0, 1, 2, 3, 17):
                with self.subTest(status=status):
                    executable.write_text(f"#!/usr/bin/env bash\nexit {status}\n")
                    executable.chmod(0o755)
                    result = shell(1, base)
                    self.assertEqual(
                        result.returncode, status if status < 4 else 3, result.stdout
                    )
            for kind in ("missing", "non-executable", "missing interpreter"):
                with self.subTest(kind=kind):
                    executable.unlink(missing_ok=True)
                    if kind != "missing":
                        executable.write_text("#!/missing/interpreter\n")
                        executable.chmod(
                            0o755 if kind == "missing interpreter" else 0o644
                        )
                    result = shell(1, base)
                    self.assertEqual(result.returncode, 3, result.stdout)
                    self.assertIn("unable to start check", result.stdout)
            executable.write_text("#!/usr/bin/env bash\nexit 0\n")
            executable.chmod(0o755)
            result = shell(1, {**base, "INPUT_WORKING_DIRECTORY": "missing"})
            self.assertEqual(result.returncode, 3, result.stdout)

    def test_organization_config_is_where_jactionlint_reads_user_defaults(self) -> None:
        # jactionlint reads $XDG_CONFIG_HOME/jactionlint/jactionlint.yaml for a
        # repository without a config file of its own.
        config = (CONFIG_HOME / "jactionlint" / "jactionlint.yaml").read_text()
        settings = [
            line for line in config.splitlines() if not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            settings,
            [
                "profile: default",
                "rules:",
                "  unpinned-uses:",
                "    policies:",
                "      saltyorg/*: ref-pin",
            ],
        )

    def test_pinned_release_is_exact_and_updated_by_renovate(self) -> None:
        metadata = (ACTION / "action.yml").read_text()
        renovate = json.loads((ROOT / ".github" / "renovate.json").read_text())
        managers = [
            manager
            for manager in renovate["customManagers"]
            if any(
                re.search(pattern.strip("/"), "jactionlint/action.yml")
                for pattern in manager["managerFilePatterns"]
            )
        ]
        self.assertEqual(len(managers), 1)
        # Renovate's named groups use the JavaScript spelling.
        pattern = managers[0]["matchStrings"][0].replace("(?<", "(?P<")
        matches = [match.groupdict() for match in re.finditer(pattern, metadata)]
        self.assertEqual(len(matches), 1, matches)
        self.assertEqual(matches[0]["datasource"], "github-releases")
        self.assertEqual(matches[0]["depName"], "jdx/jactionlint")
        self.assertRegex(matches[0]["currentValue"], r"^v\d+\.\d+\.\d+$")
        self.assertIn(f"JACTIONLINT_VERSION: {matches[0]['currentValue']}\n", metadata)


if __name__ == "__main__":
    unittest.main()
