#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "saltbox-lint: installation failed\n" >&2; exit 2' ERR
fail() { printf 'saltbox-lint: %s\n' "$1" >&2; exit 2; }

version=${INPUT_VERSION:-}
[[ $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'version must be an exact stable tag, such as v1.2.3'
[[ ${RUNNER_OS:-} == Linux ]] || fail 'only Linux runners are supported'
case ${RUNNER_ARCH:-} in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) fail 'only X64 and ARM64 runners are supported' ;;
esac
[[ -d ${RUNNER_TEMP:-} && -n ${GITHUB_OUTPUT:-} ]] || fail 'RUNNER_TEMP and GITHUB_OUTPUT are required'

base=https://github.com/saltyorg/saltbox-lint/releases/download
# The only transport override is a loopback HTTP fixture server. Never execute
# supplied downloader commands or allow an alternative release repository.
if [[ -n ${SALTBOX_LINT_DOWNLOAD_BASE_URL:-} ]]; then
  [[ $SALTBOX_LINT_DOWNLOAD_BASE_URL =~ ^http://127\.0\.0\.1:[0-9]+$ ]] || fail 'download override must be a loopback fixture server'
  base=$SALTBOX_LINT_DOWNLOAD_BASE_URL
fi
archive="saltbox-lint_${version#v}_linux_${arch}.tar.gz"
install_dir=$(mktemp -d "${RUNNER_TEMP}/saltbox-lint.XXXXXXXX")
installed=false
cleanup() {
  if [[ $installed == false ]]; then rm -rf -- "$install_dir"; fi
}
trap cleanup EXIT
cd -- "$install_dir"
curl --fail --silent --show-error --location --proto '=https,http' --proto-redir '=https' --output "$archive" "$base/$version/$archive"
curl --fail --silent --show-error --location --proto '=https,http' --proto-redir '=https' --output checksums.txt "$base/$version/checksums.txt"
# Match the complete filename, require one entry, and let sha256sum validate
# its digest syntax and content. Other release architectures are not required.
awk -v name="$archive" 'NF == 2 && ($2 == name || $2 == "*" name) { print; count++ } END { if (count != 1) exit 1 }' checksums.txt > selected.sha256
sha256sum --check --strict selected.sha256
# Extract only the binary as bytes; archive paths never become filesystem paths.
tar -xOzf "$archive" -- saltbox-lint > "$install_dir/saltbox-lint"
chmod 0755 saltbox-lint
[[ $(./saltbox-lint --version) == "saltbox-lint version ${version#v}" ]] || fail 'downloaded binary version does not match the requested tag'
rm -- "$archive" checksums.txt selected.sha256
printf 'binary=%s/saltbox-lint\n' "$install_dir" >> "$GITHUB_OUTPUT"
installed=true
