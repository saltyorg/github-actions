# Saltyorg GitHub Actions

Shared, versioned GitHub Actions used by Saltyorg repositories.

## Actions

### `retry`

Retries failed or timed-out jobs up to three actual CI executions. A fork
approval placeholder with conclusion `action_required` does not consume an
execution. Callers provide a token with `actions: write` and an optional list of
exact job names that must not be retried.

```yaml
- id: retry
  uses: saltyorg/github-actions/retry@<full-commit-sha> # v1.0.0
  with:
    github-token: ${{ github.token }}
    non-retryable-jobs: |
      ansible-lint
      saltbox-lint
```

The action returns `retried`, `terminal`, or `superseded` through its
`decision` output. Terminal and orchestration-error notification remain the
caller's responsibility. Read-only GitHub API requests retry transient failures
and honor the complete server-provided rate-limit delay; the mutating rerun
request remains single-shot and is reconciled after an ambiguous response.

### `notify`

Sends the completed workflow run from the caller's `workflow_run` event to a
Discord webhook. It uses the event snapshot as its authoritative input and
falls back to that snapshot if optional GitHub enrichment is unavailable.

```yaml
- uses: saltyorg/github-actions/notify@<full-commit-sha> # v1.0.0
  with:
    github-token: ${{ github.token }}
    discord-webhook: ${{ secrets.DISCORD_WEBHOOK }}
```

### Optional notification details

Omitting `notification-artifact` (or leaving it empty) preserves the existing
notification payload and behavior exactly. No artifact is downloaded or read.

Opt in to event details and additional fields using an artifact uploaded by the
completed workflow. Use a separate artifact name for each run attempt and place
`notification.json` at its root:

```json
{
  "schema": 1,
  "run_id": 1234,
  "run_attempt": 1,
  "event_details": "Upstream revision update; rebuilt libtorrent2.",
  "fields": [
    {
      "name": "libtorrent2",
      "value": "qBittorrent: 5.2.3\nlibtorrent: 2.0.14\nRevision: 4 → 5",
      "inline": true
    }
  ]
}
```

The producer must write numeric `run_id` and `run_attempt` from its own
`github.run_id` and `github.run_attempt`. For example, upload the file in an
artifact named `notification-${{ github.run_attempt }}`. In the notification
workflow (triggered by `workflow_run: completed`):

```yaml
permissions:
  actions: read
  contents: read

# Within the notification job's steps:
# Replace the placeholder with a released commit supporting this input.
# Existing v1.0.1 pins do not support it.
steps:
  - uses: saltyorg/github-actions/notify@<full-commit-sha>
    with:
      github-token: ${{ github.token }}
      discord-webhook: ${{ secrets.DISCORD_WEBHOOK }}
      notification-artifact: notification-${{ github.event.workflow_run.run_attempt }}
```

The action downloads only from the caller repository and the run identified by
the `workflow_run` event. The JSON must match both that run ID and its attempt.
A failed download, missing file, invalid document, or mismatched identity keeps
the ordinary workflow result and adds `Notification details unavailable.`

`event_details` and `fields` are independently optional. Event details replace
the event field's value and label it `Event - <event>`. Fields are inserted after
that field and before `Triggered by` and `Workflow`. Inline fields are padded to
complete a three-column row, keeping those metadata fields on the final row in
Discord's desktop layout. Narrow/mobile clients may stack fields. Each custom
field has a nonempty `name` and `value`; `inline` defaults to `false`. Markdown
links are supported. The producer determines which versions changed and includes
arrows only for those values. The shared action has no image-specific logic.

The document is limited to 64 KiB, field names to 256 characters, and values
(including event details) to 1024 characters. The complete embed, including
existing fields and padding, must fit Discord's 25-field and 6000-character
limits. Invalid data is rejected as a whole; values are not silently truncated.
Unknown properties and schema versions are rejected. Custom data cannot override
the workflow's result, title, repository, actor, timestamp, or mention policy.

Compatibility tests compare payload bytes with 224 SHA-256 baselines captured
from unmodified v1.0.1 (`ecc6b29bd545ef923af46f8190a0ee87eed1781e`), covering
event types, conclusions, retry metadata, and PR enrichment success/failure.
They also exercise the send path with the input omitted and explicitly empty.

### `saltbox-lint`

Checks Saltbox and Sandbox YAML using a checksum-verified, exact stable
`saltyorg/saltbox-lint` release. Pin the shared Action to a reviewed full commit
SHA and pin the linter binary separately with `version`:

```yaml
- uses: saltyorg/github-actions/saltbox-lint@<full-commit-sha>
  with:
    version: v1.2.3
    working-directory: .
    paths: |
      roles/saltbox/tasks/main.yml
      roles/sandbox/tasks/main.yml
```

The [Action metadata](https://github.com/saltyorg/saltbox-lint/blob/a75b1590d1755e5512ea6ba9fb3bec0d0aa6569a/action.yml)
and [Bash scripts](https://github.com/saltyorg/saltbox-lint/tree/a75b1590d1755e5512ea6ba9fb3bec0d0aa6569a/action)
were ported from `saltyorg/saltbox-lint` under [GPLv3](https://github.com/saltyorg/saltbox-lint/blob/a75b1590d1755e5512ea6ba9fb3bec0d0aa6569a/LICENSE);
the license text is also in this repository's [LICENSE.md](LICENSE.md).

`version` is required and accepts only an exact stable tag such as `v1.2.3`.
`working-directory` defaults to `.` relative to `GITHUB_WORKSPACE`. `paths`
defaults to `.` and contains one literal file or directory path per line,
resolved from that working directory. Empty lines are ignored. Path text is
never interpreted as a shell command or a linter option; the Action never
enables fixes implicitly.

The Action requires a Linux X64 or ARM64 runner with Bash, `curl`, `awk`,
`sha256sum`, `tar`, and standard core utilities. In normal use it downloads
only from `saltyorg/saltbox-lint` GitHub releases, verifies the archive checksum
and binary version, then runs `saltbox-lint check --format github`. It has no
caller-facing outputs;
findings appear as GitHub annotations and a step summary. Exit code `0` means
no findings, `1` means findings, and `2` means an operational or input error.

The default shared-repository tests use a local HTTP release fixture and an
argv-recording executable to test the installer and wrapper independently of
the linter repository or an unpublished release. To also exercise real linter
findings, annotations, summary, and source preservation, set
`SALTBOX_LINT_TEST_BINARY` to a local executable that reports
`saltbox-lint version 1.2.3`, then run `python3 -m unittest discover -v`.

## Release policy

Release tags are immutable semantic versions. Consumers must reference the
release's full commit SHA and keep the semantic version in a comment so
dependency automation can propose reviewed upgrades. Moving branch and major
version references are not supported consumption contracts.

Pushing a `v*` tag runs the full quality gate and publishes a GitHub Release
with generated release notes.

`retry` and `notify` form one workflow-result suite and are released together.
