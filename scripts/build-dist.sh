#!/bin/sh
# Builds the agent release bundle into dist/downloads/ (served by the console
# at /downloads/<file>):
#   clamav-agent_linux_amd64, clamav-agent_linux_arm64,
#   clamav-agent_windows_amd64.exe, install.sh, uninstall.sh,
#   clamav-agent.service, install.ps1, uninstall.ps1, SHA256SUMS
# Then run scripts/sign-dist.sh on the offline release workstation.
#
# Environment:
#   VERSION              version string (default: git describe, else "dev")
#   RELEASE_PUBKEY_FILE  TESTING ONLY: use this minisign public key instead of
#                        the committed internal/release/minisign.pub. It is
#                        injected into the agent via -ldflags and rendered into
#                        the install scripts. Never use it for a real release.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT=dist/downloads
PKG=github.com/Soup9x/Lake-Effect-Bouy

die() { echo "build-dist: ERROR: $*" >&2; exit 1; }

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
printf '%s' "$VERSION" | grep -Eq '^[A-Za-z0-9._+-]{1,64}$' || die "VERSION '$VERSION' has invalid characters"

KEYFILE=internal/release/minisign.pub
OVERRIDE=''
if [ -n "${RELEASE_PUBKEY_FILE:-}" ]; then
    KEYFILE=$RELEASE_PUBKEY_FILE
    OVERRIDE=1
    echo "build-dist: WARNING: using TEST public key $KEYFILE instead of internal/release/minisign.pub." >&2
    echo "build-dist: WARNING: this bundle must NOT be published as a release." >&2
fi
[ -f "$KEYFILE" ] || die "public key file $KEYFILE not found"
if grep -q PLACEHOLDER "$KEYFILE"; then
    die "$KEYFILE is still the placeholder. Generate the release key offline and commit its public key (docs/release-signing.md)."
fi
# The base64 key line: the first line that is not a comment.
PUBKEY=$(grep -v '^untrusted comment:' "$KEYFILE" | tr -d '\r' | sed -n '1p')
printf '%s' "$PUBKEY" | grep -Eq '^RW[A-Za-z0-9+/]{54}$' || die "cannot parse a minisign public key from $KEYFILE"

LDFLAGS="-s -w -X main.version=$VERSION"
if [ -n "$OVERRIDE" ]; then
    LDFLAGS="$LDFLAGS -X $PKG/internal/release.pubKeyOverride=$PUBKEY"
fi

rm -rf "$OUT"
mkdir -p "$OUT"

for target in linux/amd64 linux/arm64 windows/amd64; do
    os=${target%/*}; arch=${target#*/}
    name="clamav-agent_${os}_${arch}"
    [ "$os" = windows ] && name="$name.exe"
    echo "build-dist: building $name ($VERSION)"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/$name" ./cmd/agent
done

render() { # SRC DST
    sed "s|__MINISIGN_PUBKEY__|$PUBKEY|g" "$1" > "$2"
    if grep -q '__MINISIGN_PUBKEY__' "$2"; then die "placeholder left in $2"; fi
    grep -q "$PUBKEY" "$2" || die "public key not rendered into $2"
}
render packaging/linux/install.sh "$OUT/install.sh"
render packaging/windows/install.ps1 "$OUT/install.ps1"
cp packaging/linux/uninstall.sh packaging/linux/clamav-agent.service packaging/windows/uninstall.ps1 "$OUT/"
chmod 0755 "$OUT/install.sh" "$OUT/uninstall.sh" "$OUT"/clamav-agent_linux_*

(cd "$OUT" && sha256sum -- * > SHA256SUMS)
echo "build-dist: wrote $OUT (key id from $KEYFILE). Next: scripts/sign-dist.sh on the release workstation."
