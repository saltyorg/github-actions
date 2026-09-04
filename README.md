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

## Release policy

Release tags are immutable semantic versions. Consumers must reference the
release's full commit SHA and keep the semantic version in a comment so
dependency automation can propose reviewed upgrades. Moving branch and major
version references are not supported consumption contracts.

Pushing a `v*` tag runs the full quality gate and publishes a GitHub Release
with generated release notes.

`retry` and `notify` form one workflow-result suite and are released together.
