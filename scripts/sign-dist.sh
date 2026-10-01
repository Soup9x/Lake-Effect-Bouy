#!/bin/sh
# Signs every file in dist/downloads/ with the offline minisign release key,
# producing FILE.minisig next to each file, then verifies every signature
# against the public key the bundle was built with.
#
# Run this on the OFFLINE release workstation that holds the secret key:
#   MINISIGN_SECRET_KEY=/media/usb/minisign.key scripts/sign-dist.sh
#
# Environment:
#   MINISIGN_SECRET_KEY  path to the password-protected minisign secret key (required)
#   MINISIGN_PASSWORD    key password (otherwise prompted on the terminal)
#   RELEASE_PUBKEY_FILE  TESTING ONLY: must match what build-dist.sh used
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT=dist/downloads

die() { echo "sign-dist: ERROR: $*" >&2; exit 1; }

[ -n "${MINISIGN_SECRET_KEY:-}" ] || die "set MINISIGN_SECRET_KEY to the secret key path"
[ -f "$MINISIGN_SECRET_KEY" ] || die "secret key $MINISIGN_SECRET_KEY not found"
[ -d "$OUT" ] || die "$OUT not found; run scripts/build-dist.sh first"

KEYFILE=${RELEASE_PUBKEY_FILE:-internal/release/minisign.pub}
if grep -q PLACEHOLDER "$KEYFILE"; then
    die "$KEYFILE is the placeholder; refusing to sign (docs/release-signing.md)"
fi
if [ -n "${RELEASE_PUBKEY_FILE:-}" ]; then
    echo "sign-dist: WARNING: signing with a TEST key setup; do not publish." >&2
fi

TOOL=$(mktemp -d)/release-sign
trap 'rm -rf "$(dirname "$TOOL")"' EXIT
go build -o "$TOOL" ./cmd/release-sign

rm -f "$OUT"/*.minisig
set --
files=$(cd "$OUT" && ls | grep -v '\.minisig$')
[ -n "$files" ] || die "nothing to sign in $OUT"
for f in $files; do
    set -- "$@" "$OUT/$f"
done
# -p: release-sign checks the secret key matches the public key and verifies
# each signature right after writing it.
"$TOOL" sign -s "$MINISIGN_SECRET_KEY" -p "$KEYFILE" "$@"
"$TOOL" verify -p "$KEYFILE" "$@"
echo "sign-dist: signed $# files in $OUT. Copy $OUT to the console server's downloads directory."
