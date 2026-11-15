#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "jactionlint: unable to start check\n" >&2; exit 3' ERR
cd -- "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
cd -- "${INPUT_WORKING_DIRECTORY:-.}"
files=()
while IFS= read -r file; do
  file=${file%$'\r'}
  if [[ -n $file ]]; then files+=("$file"); fi
done <<< "${INPUT_FILES:-}"
# Organization defaults ship with the action as the user-level config, which
# jactionlint applies only to a repository without a config file of its own.
export XDG_CONFIG_HOME="${ACTION_PATH:?ACTION_PATH is required}/config"
arguments=(--format github)
# The terminator prevents even files named --fix or --online becoming flags.
# Without files the linter checks the whole repository.
if (( ${#files[@]} > 0 )); then arguments+=(-- "${files[@]}"); fi
status=0
"${JACTIONLINT_BINARY:?installed binary is required}" "${arguments[@]}" || status=$?
# The CLI contract is 0/1/2/3; shell launch failures (126/127) are operational.
case "$status" in
  0|1|2|3) exit "$status" ;;
  *) printf "jactionlint: unable to start check\n" >&2; exit 3 ;;
esac
