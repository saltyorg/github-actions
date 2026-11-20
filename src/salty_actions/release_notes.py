"""Write release notes listing every commit since the previous release tag.

GitHub's generated notes list only merged pull requests, so commits pushed
directly to the default branch are left out. These notes come from the git
history instead: every non-merge commit between the previous ``vX.Y.Z`` tag
reachable from the release tag and the release tag itself, grouped by its
Conventional Commit type. Git is the only data source; nothing is fetched.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

SEMVER_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+")
CONVENTIONAL = re.compile(
    r"(?P<type>[A-Za-z]+)(?:\((?P<scope>[^()]+)\))?(?P<breaking>!)?: (?P<text>.+)"
)
BREAKING_FOOTER = re.compile(r"BREAKING[ -]CHANGE: ?(?P<text>.*)")
# A git trailer or Conventional Commits footer line, such as "Refs: #7".
TRAILER = re.compile(r"(?:[A-Za-z][A-Za-z-]*|BREAKING CHANGE)(?:: | #)")
PULL_REQUEST = re.compile(r"\(#([0-9]+)\)")
RENOVATE_AUTHOR = re.compile(r"renovate(?:\[bot\]|[- ]bot)?", re.IGNORECASE)
FIELD = "\x1f"
RECORD = "\x1e"

BREAKING = "Breaking changes"
DEPENDENCIES = "Dependencies"
OTHER = "Other"
SECTIONS = (
    BREAKING,
    "Features",
    "Fixes",
    "Performance",
    "Reverts",
    DEPENDENCIES,
    "CI",
    "Docs",
    "Tests",
    "Maintenance",
    OTHER,
)
TYPE_SECTIONS = {
    "feat": "Features",
    "fix": "Fixes",
    "perf": "Performance",
    "revert": "Reverts",
    "ci": "CI",
    "docs": "Docs",
    "test": "Tests",
    "build": "Maintenance",
    "chore": "Maintenance",
    "refactor": "Maintenance",
    "style": "Maintenance",
}


class ReleaseNotesError(RuntimeError):
    """Raised when the history cannot be turned into release notes."""


@dataclass(frozen=True)
class Commit:
    sha: str
    short_sha: str
    author: str
    subject: str
    body: str


def _run_git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    # Fixed git subcommands; tag names only reach git after a refs/tags/ prefix
    # or as resolved object IDs, so none can be read as an option.
    try:
        return subprocess.run(  # nosec B603 B607
            ["git", *arguments],
            cwd=repository,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        raise ReleaseNotesError(f"cannot run git: {error}") from None


def _git(repository: Path, *arguments: str) -> str:
    result = _run_git(repository, *arguments)
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise ReleaseNotesError(f"git {arguments[0]} failed: {detail}")
    return result.stdout


def _tag_commit(repository: Path, tag: str) -> str:
    """Return the commit a tag points to, failing clearly when it is missing."""
    reference = f"refs/tags/{tag}^{{commit}}"
    result = _run_git(repository, "rev-parse", "--verify", "--quiet", reference)
    if result.returncode == 1 and not result.stderr.strip():
        raise ReleaseNotesError(f"tag {tag!r} does not exist")
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise ReleaseNotesError(f"git rev-parse failed: {detail}")
    return result.stdout.strip()


def _version(tag: str) -> tuple[int, int, int] | None:
    match = SEMVER_TAG.fullmatch(tag)
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def previous_tag(repository: Path, tag: str) -> str | None:
    """Return the highest vX.Y.Z tag reachable from ``tag`` other than itself."""
    commit = _tag_commit(repository, tag)
    current = _version(tag)
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for name in _git(
        repository, "tag", "--list", "--merged", commit, "--format=%(refname:strip=2)"
    ).splitlines():
        version = _version(name)
        # A release tag is never older than itself, so it is skipped here too.
        if version is None or (current is not None and version >= current):
            continue
        candidates.append((version, name))
    return max(candidates)[1] if candidates else None


def commits(repository: Path, tag: str, previous: str | None) -> list[Commit]:
    """Return the non-merge commits in ``previous..tag``, newest first."""
    if _git(repository, "rev-parse", "--is-shallow-repository").strip() == "true":
        raise ReleaseNotesError(
            "the repository is a shallow clone; fetch the full history and tags"
        )
    revisions = [_tag_commit(repository, tag)]
    if previous is not None:
        revisions.insert(0, "^" + _tag_commit(repository, previous))
    output = _git(
        repository,
        "log",
        "--no-merges",
        "--no-show-signature",
        f"--format=%H{FIELD}%h{FIELD}%an{FIELD}%s{FIELD}%b{RECORD}",
        *revisions,
        "--",
    )
    found = []
    for record in output.split(RECORD):
        record = record.strip("\n")
        if not record:
            continue
        sha, short_sha, author, subject, body = record.split(FIELD, 4)
        found.append(Commit(sha, short_sha, author, subject, body))
    return found


def _breaking_note(body: str) -> str | None:
    """Return the BREAKING CHANGE footer text, or None without that footer."""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        footer = BREAKING_FOOTER.fullmatch(line)
        if footer is None:
            continue
        text = [footer["text"]]
        # The footer value runs on until a blank line or the next footer.
        for following in lines[index + 1 :]:
            if not following.strip() or TRAILER.match(following):
                break
            text.append(following)
        return " ".join(" ".join(text).split())
    return None


def _section(commit: Commit) -> tuple[str, str, str | None]:
    """Return the section, display text and breaking-change note of a commit."""
    match = CONVENTIONAL.fullmatch(commit.subject)
    note = _breaking_note(commit.body)
    footer = note is not None
    renovate = RENOVATE_AUTHOR.fullmatch(commit.author) is not None
    if match is None:
        if footer:
            return BREAKING, commit.subject, note
        return (DEPENDENCIES if renovate else OTHER), commit.subject, None
    scope = match["scope"]
    text = f"**{scope}:** {match['text']}" if scope else match["text"]
    if match["breaking"] or footer:
        return BREAKING, text, note
    if scope == "deps":
        return DEPENDENCIES, match["text"], None
    if renovate:
        return DEPENDENCIES, text, None
    section = TYPE_SECTIONS.get(match["type"].casefold())
    if section is None:
        return OTHER, commit.subject, None
    return section, text, None


def render(
    repository: str, tag: str, previous: str | None, history: Sequence[Commit]
) -> str:
    """Return the Markdown release notes for ``history``."""
    base = f"https://github.com/{repository}"
    grouped: dict[str, list[str]] = {name: [] for name in SECTIONS}
    for commit in history:
        section, text, note = _section(commit)
        text = PULL_REQUEST.sub(
            lambda pull: f"([#{pull[1]}]({base}/pull/{pull[1]}))", text
        )
        entry = (
            f"- {text} ([`{commit.short_sha}`]({base}/commit/{commit.sha})) "
            f"by {commit.author}"
        )
        if note:
            entry += f"\n  - {note}"
        grouped[section].append(entry)
    lines = ["## What's Changed", ""]
    if not history:
        lines += ["No changes since the previous release.", ""]
    for name in SECTIONS:
        if grouped[name]:
            lines += [f"### {name}", "", *grouped[name], ""]
    if previous is None:
        changelog = f"{base}/commits/{quote(tag, safe='')}"
    else:
        changelog = f"{base}/compare/{quote(previous, safe='')}...{quote(tag, safe='')}"
    lines.append(f"**Full Changelog**: {changelog}")
    return "\n".join(lines) + "\n"


def release_notes(
    repository: str, tag: str, previous: str | None = None, path: Path | None = None
) -> str:
    """Return the release notes for ``tag`` from the git repository at ``path``."""
    if not REPOSITORY.fullmatch(repository):
        raise ReleaseNotesError(f"repository {repository!r} is not OWNER/NAME")
    checkout = Path.cwd() if path is None else path
    _tag_commit(checkout, tag)
    if previous is None:
        previous = previous_tag(checkout, tag)
    return render(repository, tag, previous, commits(checkout, tag, previous))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag, such as v1.2.3")
    parser.add_argument(
        "--previous", help="tag to list changes from (default: the previous release)"
    )
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub OWNER/NAME for links (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument("--output", type=Path, help="file to write (default: stdout)")
    args = parser.parse_args(argv)
    try:
        notes = release_notes(args.repository, args.tag, args.previous)
        if args.output is None:
            sys.stdout.write(notes)
        else:
            args.output.write_text(notes, encoding="utf-8")
    except (OSError, ReleaseNotesError) as error:
        print(f"::error::Release notes failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
