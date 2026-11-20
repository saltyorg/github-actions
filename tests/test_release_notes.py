"""Release notes built from a real temporary git history."""

from __future__ import annotations

import io
import os
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from salty_actions.release_notes import (
    ReleaseNotesError,
    main,
    previous_tag,
    release_notes,
)

REPOSITORY = "example/actions"
BASE = f"https://github.com/{REPOSITORY}"
HUMAN = ("Alice Example", "alice@example.com")
OTHER = ("Bob Example", "bob@example.com")
RENOVATE = ("renovate[bot]", "29139614+renovate[bot]@users.noreply.github.com")
# Git reads no user or system configuration, so signing, hooks and aliases on
# the machine running the tests cannot change the history or its output.
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class History:
    """A git repository whose commits get fixed, increasing timestamps."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.time = 1_700_000_000
        self.git("init", "--quiet", "--initial-branch=main")
        self.short: dict[str, str] = {}
        self.full: dict[str, str] = {}

    def git(self, *arguments: str, author: tuple[str, str] = HUMAN) -> str:
        self.time += 60
        date = f"@{self.time} +0000"
        env = {
            **os.environ,
            **GIT_ENV,
            "GIT_AUTHOR_NAME": author[0],
            "GIT_AUTHOR_EMAIL": author[1],
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_NAME": HUMAN[0],
            "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_COMMITTER_DATE": date,
        }
        # Fixed git arguments written in this test module.
        result = subprocess.run(  # nosec B603 B607
            ["git", *arguments],
            cwd=self.path,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def commit(
        self, key: str, message: str, *, author: tuple[str, str] = HUMAN
    ) -> None:
        self.git("commit", "--quiet", "--allow-empty", "-m", message, author=author)
        self.full[key] = self.git("rev-parse", "HEAD")
        self.short[key] = self.git("rev-parse", "--short", "HEAD")

    def entry(self, key: str, text: str, author: str = HUMAN[0]) -> str:
        return (
            f"- {text} ([`{self.short[key]}`]({BASE}/commit/{self.full[key]})) "
            f"by {author}"
        )


def build_history(path: Path) -> History:
    history = History(path)
    history.commit("first", "feat: add the first action")
    history.commit("readme", "Add a README")
    history.git("tag", "--annotate", "--message", "v0.9.0", "v0.9.0")

    history.commit("feat", "feat(retry): retry cancelled runs (#12)")
    history.commit("fix", "fix(transport): close http error responses")
    history.commit("fix-unscoped", "fix: support python 3.10")
    # Non-semver tags inside the range must not be taken as the previous release.
    history.git("tag", "v0.10.0-rc.1")
    history.git("tag", "v1")
    history.git("tag", "latest")
    history.commit("perf", "perf(scan): reuse the image inventory")
    history.commit("revert", 'revert: "feat: add a cache"')
    history.commit("ci", "ci: test every hosted runner")
    history.commit("docs", "docs: state the supported python range")
    history.commit("test", "test: run every module under strict warnings")
    history.commit("build", "build: ship the scanner checksums")
    history.commit("chore", "chore(notify): name the pinned release")
    history.commit("refactor", "refactor: share the http client")
    history.commit("style", "style: format with ruff")
    history.commit(
        "renovate",
        "chore(deps): update dependency aquasecurity/trivy to v0.76.2 (#40)",
        author=RENOVATE,
    )
    history.commit(
        "renovate-plain", "Update actions/checkout action to v7", author=RENOVATE
    )
    history.commit("deps-fix", "fix(deps): pin the scanner digest", author=OTHER)
    history.commit("bang", "feat(api)!: drop the v1 inputs")
    history.commit(
        "footer",
        "refactor(inputs): rename the token input\n\n"
        "Callers must update their workflows.\n\n"
        "BREAKING CHANGE: the `token` input is now\n"
        "`github-token`.\nRefs: #7",
    )
    history.commit("unknown", "wip: sketch the report layout")
    history.commit("plain", "Tidy the workflow comments")

    # A merged side branch: its commit is listed and the merge commit is not.
    history.git("switch", "--quiet", "--create", "side")
    history.commit("side", "fix(side): handle the side case")
    history.git("switch", "--quiet", "main")
    history.commit("main-after", "docs: note the side case")
    history.git("merge", "--quiet", "--no-ff", "--no-edit", "side")
    history.full["merge"] = history.git("rev-parse", "HEAD")
    history.git("tag", "--annotate", "--message", "v0.10.0", "v0.10.0")

    # A release tag on an unmerged branch is not reachable from later tags.
    history.git("switch", "--quiet", "--create", "hotfix")
    history.commit("hotfix", "fix: hot fix")
    history.git("tag", "v0.10.5")
    history.git("switch", "--quiet", "main")

    history.commit("next", "fix(report): sort findings by severity")
    history.git("tag", "v0.11.0")
    history.git("tag", "v0.11.1")
    return history


class ReleaseNotesTests(unittest.TestCase):
    history: History

    @classmethod
    def setUpClass(cls) -> None:
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.history = build_history(Path(directory.name))

    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, GIT_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def notes(self, tag: str, previous: str | None = None) -> str:
        return release_notes(REPOSITORY, tag, previous, self.history.path)

    def test_groups_every_commit_since_the_previous_release(self) -> None:
        h = self.history
        footer_note = "  - the `token` input is now `github-token`."
        self.assertEqual(
            self.notes("v0.10.0"),
            "\n".join(
                [
                    "## What's Changed",
                    "",
                    "### Breaking changes",
                    "",
                    h.entry("footer", "**inputs:** rename the token input"),
                    footer_note,
                    h.entry("bang", "**api:** drop the v1 inputs"),
                    "",
                    "### Features",
                    "",
                    h.entry(
                        "feat",
                        f"**retry:** retry cancelled runs ([#12]({BASE}/pull/12))",
                    ),
                    "",
                    "### Fixes",
                    "",
                    h.entry("side", "**side:** handle the side case"),
                    h.entry("fix-unscoped", "support python 3.10"),
                    h.entry("fix", "**transport:** close http error responses"),
                    "",
                    "### Performance",
                    "",
                    h.entry("perf", "**scan:** reuse the image inventory"),
                    "",
                    "### Reverts",
                    "",
                    h.entry("revert", '"feat: add a cache"'),
                    "",
                    "### Dependencies",
                    "",
                    h.entry("deps-fix", "pin the scanner digest", OTHER[0]),
                    h.entry(
                        "renovate-plain",
                        "Update actions/checkout action to v7",
                        RENOVATE[0],
                    ),
                    h.entry(
                        "renovate",
                        "update dependency aquasecurity/trivy to v0.76.2 "
                        f"([#40]({BASE}/pull/40))",
                        RENOVATE[0],
                    ),
                    "",
                    "### CI",
                    "",
                    h.entry("ci", "test every hosted runner"),
                    "",
                    "### Docs",
                    "",
                    h.entry("main-after", "note the side case"),
                    h.entry("docs", "state the supported python range"),
                    "",
                    "### Tests",
                    "",
                    h.entry("test", "run every module under strict warnings"),
                    "",
                    "### Maintenance",
                    "",
                    h.entry("style", "format with ruff"),
                    h.entry("refactor", "share the http client"),
                    h.entry("chore", "**notify:** name the pinned release"),
                    h.entry("build", "ship the scanner checksums"),
                    "",
                    "### Other",
                    "",
                    h.entry("plain", "Tidy the workflow comments"),
                    h.entry("unknown", "wip: sketch the report layout"),
                    "",
                    f"**Full Changelog**: {BASE}/compare/v0.9.0...v0.10.0",
                    "",
                ]
            ),
        )

    def test_lists_each_non_merge_commit_exactly_once(self) -> None:
        notes = self.notes("v0.10.0")
        listed = [key for key, sha in self.history.full.items() if sha in notes]
        self.assertEqual(
            sorted(listed),
            sorted(
                set(self.history.full) - {"first", "readme", "merge", "hotfix", "next"}
            ),
        )
        for key in listed:
            self.assertEqual(notes.count(f"/commit/{self.history.full[key]})"), 1)
        self.assertNotIn(self.history.full["merge"], notes)
        self.assertNotIn("Merge branch", notes)

    def test_first_release_lists_all_commits(self) -> None:
        h = self.history
        self.assertIsNone(previous_tag(h.path, "v0.9.0"))
        self.assertEqual(
            self.notes("v0.9.0"),
            "\n".join(
                [
                    "## What's Changed",
                    "",
                    "### Features",
                    "",
                    h.entry("first", "add the first action"),
                    "",
                    "### Other",
                    "",
                    h.entry("readme", "Add a README"),
                    "",
                    f"**Full Changelog**: {BASE}/commits/v0.9.0",
                    "",
                ]
            ),
        )

    def test_previous_release_is_the_highest_reachable_semver_tag(self) -> None:
        path = self.history.path
        # v0.9.0 sorts after v0.10.0 as text; v0.10.5 is on an unmerged branch.
        self.assertEqual(previous_tag(path, "v0.11.0"), "v0.10.0")
        self.assertEqual(previous_tag(path, "v0.10.0"), "v0.9.0")
        self.assertEqual(previous_tag(path, "v0.10.0-rc.1"), "v0.9.0")
        self.assertEqual(previous_tag(path, "v0.10.5"), "v0.10.0")
        self.assertEqual(previous_tag(path, "v0.11.1"), "v0.11.0")
        self.assertEqual(previous_tag(path, "latest"), "v0.9.0")

    def test_lists_a_single_commit_release(self) -> None:
        h = self.history
        self.assertEqual(
            self.notes("v0.11.0"),
            "## What's Changed\n\n### Fixes\n\n"
            + h.entry("next", "**report:** sort findings by severity")
            + f"\n\n**Full Changelog**: {BASE}/compare/v0.10.0...v0.11.0\n",
        )

    def test_release_without_changes_says_so(self) -> None:
        self.assertEqual(
            self.notes("v0.11.1"),
            "## What's Changed\n\nNo changes since the previous release.\n\n"
            f"**Full Changelog**: {BASE}/compare/v0.11.0...v0.11.1\n",
        )

    def test_explicit_previous_tag_sets_the_range(self) -> None:
        notes = self.notes("v0.11.0", previous="v0.10.0-rc.1")
        self.assertIn(self.history.full["next"], notes)
        self.assertIn(self.history.full["perf"], notes)
        self.assertNotIn(self.history.full["fix"], notes)
        self.assertTrue(
            notes.endswith(f"{BASE}/compare/v0.10.0-rc.1...v0.11.0\n"), notes
        )

    def test_missing_tag_fails_clearly(self) -> None:
        with self.assertRaisesRegex(ReleaseNotesError, r"^tag 'v9\.9\.9' does not"):
            self.notes("v9.9.9")
        with self.assertRaisesRegex(ReleaseNotesError, r"^tag 'v0\.0\.1' does not"):
            self.notes("v0.10.0", previous="v0.0.1")
        # A branch of that name is not a release tag.
        with self.assertRaisesRegex(ReleaseNotesError, r"^tag 'main' does not"):
            self.notes("main")
        with self.assertRaisesRegex(ReleaseNotesError, r"^tag '--all' does not"):
            self.notes("--all")

    def test_rejects_a_repository_that_is_not_owner_and_name(self) -> None:
        for repository in ("", "example", "example/actions/extra", "../x/y"):
            with (
                self.subTest(repository=repository),
                self.assertRaisesRegex(ReleaseNotesError, "is not OWNER/NAME"),
            ):
                release_notes(repository, "v0.10.0", path=self.history.path)

    def test_shallow_clone_fails_instead_of_listing_too_much(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone"
            # Fixed arguments; the source is this test's own repository.
            subprocess.run(  # nosec B603 B607
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--depth=1",
                    "--branch=v0.11.0",
                    f"file://{self.history.path}",
                    str(clone),
                ],
                env={**os.environ, **GIT_ENV},
                capture_output=True,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseNotesError, "shallow clone"):
                release_notes(REPOSITORY, "v0.11.0", path=clone)

    def test_main_writes_the_output_file(self) -> None:
        cwd = Path.cwd()
        os.chdir(self.history.path)
        self.addCleanup(os.chdir, cwd)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "notes.md"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "--tag",
                        "v0.11.0",
                        "--repository",
                        REPOSITORY,
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(output.read_text(encoding="utf-8"), self.notes("v0.11.0"))

    def test_main_prints_notes_for_the_github_repository(self) -> None:
        cwd = Path.cwd()
        os.chdir(self.history.path)
        self.addCleanup(os.chdir, cwd)
        stdout = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPOSITORY}),
            redirect_stdout(stdout),
        ):
            status = main(["--tag", "v0.11.0"])
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), self.notes("v0.11.0"))

    def test_main_reports_a_missing_tag(self) -> None:
        cwd = Path.cwd()
        os.chdir(self.history.path)
        self.addCleanup(os.chdir, cwd)
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()) as stdout:
            status = main(
                ["--tag", "v9.9.9", "--repository", REPOSITORY],
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("::error::Release notes failed: tag 'v9.9.9'", stderr.getvalue())

    def test_module_runs_as_a_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "notes.md"
            # The interpreter is this test's own; the arguments are fixed.
            result = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    "-m",
                    "salty_actions.release_notes",
                    "--tag",
                    "v0.10.0",
                    "--output",
                    str(output),
                ],
                cwd=self.history.path,
                env={
                    **os.environ,
                    "PYTHONPATH": str(ROOT / "src"),
                    "GITHUB_REPOSITORY": REPOSITORY,
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(output.read_text(encoding="utf-8"), self.notes("v0.10.0"))


if __name__ == "__main__":
    unittest.main()
