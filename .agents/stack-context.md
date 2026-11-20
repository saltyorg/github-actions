# Stack Context

Generated: 2026-09-20

## Stack
- **Language**: Python 3.11–3.15 (stdlib-only; the actions use the runner's system `python3`)
- **Framework**: GitHub composite actions with Python module entry points and Bash Saltbox Lint entrypoints
- **Build**: No package/build tool; CI byte-compiles `src` with `compileall`
- **Test**: `python3 -m unittest discover -v` using stdlib `unittest`; optional real Saltbox Lint binary via `SALTBOX_LINT_TEST_BINARY`
- **Lint**: jactionlint (release pinned in `jactionlint/action.yml`, `default` profile) for workflow YAML through the local `./jactionlint` action (CI gate: yes)
- **Format**: No formatter configured; `git diff --check` enforces whitespace (CI gate: yes)

## Secondary Languages
- YAML (composite action metadata, CI workflow, and workflow-lint contract fixtures)
- Bash (Saltbox Lint and jactionlint release installers and check wrappers)
- JSON (Renovate configuration)

## Conventions
- Error handling: validate inputs early; map transport failures to explicit exceptions; reconcile ambiguous mutations
- Module structure: `src/salty_actions` contains shared GitHub API code plus one module per action
- Naming: snake_case functions/modules, PascalCase classes, uppercase constants
- Tests: `tests/test_*.py` mirrors modules and uses injected fakes with `unittest.TestCase`
- Saltbox Lint action tests execute packaged Bash commands against a loopback release fixture; the real-binary mode is local and CI-independent

## CI Gates
- Python unit tests with `-W error -X dev` on 3.11, 3.15 (setup-python) and the runner's `python3`
- Python byte-compilation of `src` and `tests` with warnings as errors
- Weekly `runner-images.yml`: the same Python checks on every GitHub-hosted Ubuntu image
- Bash syntax validation for Saltbox Lint and jactionlint entrypoints
- jactionlint validation of CI, local action contracts, and the organization policy fixtures
- Git whitespace-error check
