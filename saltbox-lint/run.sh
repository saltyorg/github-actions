#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "saltbox-lint: unable to start check\n" >&2; exit 2' ERR
cd -- "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
cd -- "${INPUT_WORKING_DIRECTORY:-.}"
paths=()
while IFS= read -r path; do
  path=${path%$'\r'}
  if [[ -n $path ]]; then paths+=("$path"); fi
done <<< "${INPUT_PATHS:-.}"
if (( ${#paths[@]} == 0 )); then paths=(.); fi
# The terminator prevents even paths named --fix or --format=json becoming flags.
status=0
"${SALTBOX_LINT_BINARY:?installed binary is required}" check --format github -- "${paths[@]}" || status=$?
# The CLI contract is 0/1/2; shell launch failures (126/127) are operational.
case "$status" in
  0|1|2) exit "$status" ;;
  *) printf "saltbox-lint: unable to start check\n" >&2; exit 2 ;;
esac
