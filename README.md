# Saltyorg GitHub Actions

Shared, versioned GitHub Actions used by Saltyorg repositories.

## Actions

The examples below use `v1.1.0`. The branch-based PR lookup and `saltbox-lint`
action described below are not included in that release.

### `retry`

Retries failed or timed-out jobs up to three actual CI executions. A fork
approval placeholder with conclusion `action_required` does not consume an
execution. Callers provide a token with `actions: write` and an optional list of
exact job names that must not be retried.

```yaml
- id: retry
  uses: saltyorg/github-actions/retry@v1.1.0
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

Closed or superseded pull requests return `superseded` so callers can skip retry
and notification. If a `pull_request` run has no PR references and its old commit
is no longer associated with a PR, the action looks up the original source
repository and branch. It uses the run's creation time to distinguish reused
branches and requires a single matching PR before suppressing the result.
Missing or ambiguous metadata keeps normal failure handling; API errors remain
orchestration errors. An expired approval for a current, open PR is still
reportable, including when no jobs ran.

### `notify`

Sends the completed workflow run from the caller's `workflow_run` event to a
Discord webhook. It uses the event snapshot as its authoritative input and
falls back to that snapshot if optional GitHub enrichment is unavailable.
When a PR association is absent from both the event and commit lookup, the
notifier uses the same verified source-repository, branch, and creation-time
lookup as `retry`. Ambiguous identities keep the generic event description;
they never select an arbitrary PR. Existing notification layout and optional
artifact handling are unchanged.

```yaml
- uses: saltyorg/github-actions/notify@v1.1.0
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
# The published v1.1.0 release supports notification-artifact.
steps:
  - uses: saltyorg/github-actions/notify@v1.1.0
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
`saltyorg/saltbox-lint` release. Select the linter binary with `version`.
This action is absent from shared-actions `v1.1.0`.

The following example runs the action locally from a checkout of this repository:

```yaml
- uses: ./saltbox-lint
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

### Container security actions

The container security actions are not included in published `v1.2.0`. The examples below run
from a local checkout of this repository. Consumers must use an actual published
release when adopting them; Renovate manages subsequent version updates.

`container-scan` exports one image to a temporary archive and runs pinned,
checksum-verified Trivy and Docker Scout releases against those same bytes.
Python installs and invokes the scanners, normalizes their structured reports,
and writes `report.json`, raw Trivy JSON, raw Scout/KEV SARIF, and a combined
`findings.sarif`. It also writes `scout-code-scanning.sarif` with bounded file
locations for GitHub ingestion. All scanner severities remain in the raw reports; ordinary
HIGH/CRITICAL findings and KEV findings enter the normalized report.

```yaml
- id: security
  uses: ./container-scan
  with:
    image: local/example:candidate
    name: example
    platform: linux/amd64
    output-directory: security/example-amd64
    dockerhub-user: ${{ secrets.DOCKERHUB_USERNAME }}
    dockerhub-password: ${{ secrets.DOCKERHUB_TOKEN }}
```

Ordinary findings are advisory even when a fix is available. `enforce-kev`
defaults to `true`: detected KEV findings fail with exit code 1, and an unavailable
KEV assessment fails with exit code 2. A failed advisory Trivy scan does not block
publication when the Scout KEV assessment succeeds. `report-status` independently
returns `complete` or `incomplete`; `kev-status` returns `clear`, `found`, or
`unknown`. Reports remain available after assessment errors. Invalid inputs or
unwritable output paths fail with exit code 2.

`scout-enabled` defaults to `true`. PR candidates may disable it together with
`enforce-kev`, retaining a Trivy-only advisory report with incomplete/unknown
Scout coverage. Published scans cannot disable Scout. Trusted publication must
keep KEV enforcement enabled.

The action requires Linux X64/ARM64, Python 3.11+, `gh`, Docker, and enough disk
space to export the image. The image platform can be `linux/amd64`, `linux/arm64`,
or `linux/arm/v7`; scanning exported bytes does not execute the guest image.
The optional Docker Hub credentials authenticate Scout's backend. Private-image
registry login remains the caller's responsibility. Published scans require
`kind: published` and an image reference containing a real registry digest.

Retrying happens inside individual operations. Read-only commands retry transient
network/server errors and timeouts up to four attempts, with exponential delay.
Explicit rate-limit responses use Retry-After where available, otherwise a
one-minute delay. Authentication, permission, missing-image, checksum, schema,
and scanner program errors are not retried. Scanner versions have one reference
each in the action metadata, managed by Renovate. No jobs or workflows are rerun.

`container-snapshot` accepts a JSON `targets` array of `{name, platform, image}`
objects using mutable published tags. Its Python implementation freezes each tag
once with operation-level retries, then returns a digest-pinned scan matrix and
an `expected-targets` file. Upload that file from the preparation job and download
it in the reporting job so every matrix scan uses the same snapshot.

```yaml
- id: snapshot
  uses: ./container-snapshot
  with:
    targets: '[{"name":"example","platform":"linux/amd64","image":"example/image:latest"}]'
```

`container-report` aggregates scans of published images and proposes or applies
issue operations. `expected-targets` points to a JSON file declaring the complete
image set for one stable `scope`. Each entry contains `name`, `platform`, an
immutable `image` reference, and the mutable `tracking_reference` whose current
manifest digest must match. Resolve and freeze that image set before matrix
scanning. Use the same manifest-index digest for the corresponding platforms.

```yaml
- uses: ./container-report
  with:
    reports-directory: downloaded-security-reports
    expected-targets: expected-targets.json
    scope: published-images
    dry-run: 'true'
```

Only `report.json` files below `reports-directory` are read. Preserve per-target
subdirectories when downloading artifacts; flattening files named `report.json`
would overwrite assessments. Every report must belong to this repository, the
current workflow run and attempt, and its expected image digest. Candidate,
foreign, unexpected, duplicate, malformed, and superseded reports are rejected.
Missing or failed assessments prevent issue resolution. Valid positive findings
from incomplete coverage can still be reported, and the reporting job exits 2
to show that coverage is incomplete.

The tool manages one issue per vulnerability/package/distro identity within the
scope, combining architectures and variants. It preserves scanner disagreement,
creates no duplicate on unchanged findings, and edits existing issues only when
substantive details change. Human text outside its marked body section is
preserved. Manual closures opt out of automatic reopening. Recurrence can reopen
an issue resolved by automation, with the last closure's actor checked through
issue events. Only complete current published-image scans resolve issues.

`dry-run` defaults to `true`, requires Issues read access, and performs no writes.
Activation with `dry-run: 'false'` requires the caller's repository-scoped
`GITHUB_TOKEN` with `issues: write`. Writes run only for schedule, push, or manual
events on the default branch; PR events cannot manage issues. Serialize reporting
for the scope with publication using the caller workflow's concurrency group.
The tool checks the current tracking digests before reconciliation and each
write; concurrency prevents a publication racing that check. Place reporting in
a separate job that publication does not depend on.

GitHub reads retry network errors, timeouts, HTTP 408/5xx, and rate limits. Issue
writes retry explicit rate-limit rejections. An uncertain create response is
reconciled by listing owned issues and is never blindly repeated. An idempotent
PATCH can retry only after a read proves that the same owned issue still has its
pre-write body and state. Concurrent edits stop reconciliation. Previously
completed operations remain in the result if a later operation fails.

The aggregate JSON, `report-path` and `report-status` outputs, and job summary
show proposed/applied operations and assessment errors. Assessment and issue
reconciliation errors also appear in the action log with credentials redacted.
Unreconciled writes retain the underlying HTTP or transport failure in the error
message without repeating issue creation. Upload reports with
`if: always()` so failures retain evidence. Use `scout-code-scanning.sarif` for
Code Scanning uploads. It retains every finding, package and fixed-version
property, and the primary file location. GitHub displays only the primary location,
and Scout's full package file lists can exceed ingestion limits. The original
`scout.sarif` remains unchanged as an artifact. Automated upgrades continue to own remediation; this tool does not
alter locks, dispatch upgrades, or verify repository availability of fixes.

## Release policy

Release tags are immutable semantic versions.

Pushing a `v*` tag runs the full quality gate and publishes a GitHub Release
with generated release notes. An explicitly authorized release is complete
only after the agreed commit passes required validation, the agreed tag is
pushed, and its remote target and successful release publication are verified.
A local tag, a commit on `main`, or a planned version is not a published release.

`retry` and `notify` form one workflow-result suite and are released together.
