#!/usr/bin/env bash
# Offline v2.20.3 extractor for tag qualification; never executes the engine.
# Archive pins were checked against checksums.txt authenticated with Sigstore
# identity https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/v2.20.3
# and issuer https://token.actions.githubusercontent.com.
# The caller supplies owned, nonconcurrently modified paths. This does not
# download, execute the engine, or establish an adversarial race boundary.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$1" >&2; exit 1; }
test "$#" -eq 3 || fail 'usage: install-release-engine TARGET ABSOLUTE_ARCHIVE FRESH_ABSOLUTE_DIRECTORY'
target=$1
archive=$2
destination=$3
case "$target" in
  linux-amd64)
    archive_sha=a36d5d7d07a5e538e052cef2a9f93f1cd4af493cf5a3712b9177c1ebe360f0e7
    binary_sha=d124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d
    ;;
  darwin-arm64)
    archive_sha=e2c896685fcdb3ec255ce30e86ab073d56f3c02eb539061e749e98d9be1fc2b6
    binary_sha=d582cd4ff47eac803718c957ff6781d33367cdf865db2948d529b39d60b9767e
    ;;
  *) fail 'unsupported release engine target' ;;
esac
case "$archive" in /*) ;; *) fail 'archive must be absolute' ;; esac
case "$destination" in /*) ;; *) fail 'destination must be absolute' ;; esac
test -f "$archive" && test ! -L "$archive" || fail 'archive must be a regular non-symlink file'
test ! -e "$destination" && test ! -L "$destination" || fail 'destination must not exist'

# No archive parsing or destination creation happens before authentication.
actual=$(shasum -a 256 "$archive")
test "${actual%% *}" = "$archive_sha" || fail 'release engine archive digest mismatch'
mkdir "$destination"
# Retain this exclusively owned directory on failure. Never remove a
# caller-supplied path, and never grant execute permission to failed output.
set -C
tar -xzOf "$archive" goreleaser > "$destination/goreleaser"
actual=$(shasum -a 256 "$destination/goreleaser")
test "${actual%% *}" = "$binary_sha" || fail 'release engine binary digest mismatch'
chmod 500 "$destination/goreleaser"
