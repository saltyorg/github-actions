# Stack Context

Generated: 2026-09-04

## Stack
- **Language**: Python 3 (stdlib-only; version not pinned, CI uses Ubuntu 24.04 system Python)
- **Framework**: GitHub composite actions with Python module entry points
- **Build**: No package/build tool; CI byte-compiles `src` with `compileall`
- **Test**: `python3 -m unittest discover -v` using stdlib `unittest`
- **Lint**: actionlint 1.7.12 for action/workflow YAML (CI gate: yes)
- **Format**: No formatter configured; `git diff --check` enforces whitespace (CI gate: yes)

## Secondary Languages
- YAML (composite action metadata, CI workflow, and actionlint contract fixture)
- JSON (Renovate configuration)

## Conventions
- Error handling: validate inputs early; map transport failures to explicit exceptions; reconcile ambiguous mutations
- Module structure: `src/salty_actions` contains shared GitHub API code plus one module per action
- Naming: snake_case functions/modules, PascalCase classes, uppercase constants
- Tests: `tests/test_*.py` mirrors modules and uses injected fakes with `unittest.TestCase`

## CI Gates
- Python unit tests
- Python module byte-compilation
- actionlint validation of CI and local action contracts
- Git whitespace-error check
