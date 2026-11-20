"""Run every module and action command on the interpreter running the tests.

The actions execute on the runner's own ``python3``. These checks start each
module and each action's packaged ``run:`` command in a fresh interpreter with
warnings as errors and development mode, so an import-time deprecation, a
syntax feature newer than the supported floor or a leaked resource fails here.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
PACKAGE = SOURCE / "salty_actions"
STRICT_ENV = {"PYTHONWARNINGS": "error", "PYTHONDEVMODE": "1"}

# Each action run with no inputs must reach its own error handling, which
# proves the entry point loaded and ran without needing credentials or network.
ACTION_FAILURES = {
    "container-report": (2, "Container reporting failed"),
    "container-scan": (2, "Container scan failed"),
    "container-snapshot": (2, "Container snapshot failed"),
    "notify": (1, "::error::Discord notification failed"),
    "retry": (1, "::error::Retry orchestration failed"),
}


def python_actions() -> dict[str, str]:
    commands = {}
    for metadata in sorted(ROOT.glob("*/action.yml")):
        for line in metadata.read_text(encoding="utf-8").splitlines():
            command = line.strip().removeprefix("run: ")
            if "python3 " in command:
                commands[metadata.parent.name] = command
    return commands


class ModuleImportTests(unittest.TestCase):
    def test_every_module_imports_cleanly(self) -> None:
        modules = sorted(path.stem for path in PACKAGE.glob("*.py"))
        self.assertIn("transport", modules)
        for module in modules:
            name = (
                "salty_actions" if module == "__init__" else f"salty_actions.{module}"
            )
            with self.subTest(module=name), tempfile.TemporaryDirectory() as cwd:
                # The interpreter is this test's own and the module name is a
                # repository file name.
                result = subprocess.run(  # nosec B603
                    [
                        sys.executable,
                        "-W",
                        "error",
                        "-X",
                        "dev",
                        "-c",
                        f"import {name}",
                    ],
                    cwd=cwd,
                    env={**os.environ, **STRICT_ENV, "PYTHONPATH": str(SOURCE)},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")


class ActionCommandTests(unittest.TestCase):
    def test_every_python_action_has_an_expected_outcome(self) -> None:
        self.assertEqual(sorted(python_actions()), sorted(ACTION_FAILURES))

    def test_action_commands_run_on_this_interpreter(self) -> None:
        for action, command in python_actions().items():
            status, message = ACTION_FAILURES[action]
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory() as cwd,
                tempfile.TemporaryDirectory() as bin_directory,
            ):
                # The packaged command calls `python3`; point it at the
                # interpreter under test rather than whatever PATH provides.
                (Path(bin_directory) / "python3").symlink_to(sys.executable)
                env = {
                    "PATH": f"{bin_directory}{os.pathsep}{os.environ['PATH']}",
                    "GITHUB_ACTION_PATH": str(ROOT / action),
                    **STRICT_ENV,
                }
                # The command comes from this repository's trusted action metadata.
                result = subprocess.run(  # nosec B603
                    ["/bin/bash", "-c", command],
                    cwd=cwd,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn(message, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn("Warning", result.stderr)

    def test_action_command_uses_the_interpreter_under_test(self) -> None:
        with tempfile.TemporaryDirectory() as bin_directory:
            (Path(bin_directory) / "python3").symlink_to(sys.executable)
            # Fixed command; only PATH is redirected to the interpreter under test.
            result = subprocess.run(  # nosec B603
                [
                    "/bin/bash",
                    "-c",
                    "python3 -c 'import sys; print(sys.version_info[:2])'",
                ],
                env={"PATH": f"{bin_directory}{os.pathsep}{os.environ['PATH']}"},
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertEqual(result.stdout.strip(), str(sys.version_info[:2]))


if __name__ == "__main__":
    unittest.main()
