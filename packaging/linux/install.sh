#!/bin/sh
# Installs the ClamAV console agent as the systemd service clamav-agent.
#
# Usage (as root):
#   CAV_SERVER_URL=https://console.example.com CAV_ENROLL_TOKEN=cav_enr_... sh install.sh
#   sh install.sh --reinstall          # enroll again, replacing this machine's agent
#   sh install.sh --verify-only FILE SIGFILE   # only check a minisign signature
#
# Inputs (environment):
#   CAV_SERVER_URL    required, https:// console URL
#   CAV_ENROLL_TOKEN  required when enrolling (first install or --reinstall)
#   CAV_CLAMD_ADDR    optional clamd address (unix:///path or tcp://127.0.0.1:3310);
#                     default: auto-detect the clamd socket
#
# The agent binary and the systemd unit are downloaded from
# $CAV_SERVER_URL/downloads/ and their minisign signatures are VERIFIED against
# the public key embedded below before anything is installed. The key is
# never fetched from the server.
set -eu

# Substituted by scripts/build-dist.sh. Release signing public key (minisign).
MINISIGN_PUBKEY='__MINISIGN_PUBKEY__'

BIN_DST=/usr/local/bin/clamav-agent
UNIT_DST=/etc/systemd/system/clamav-agent.service
CONF_DIR=/etc/clamav-agent
CONF_FILE=$CONF_DIR/agent.yaml
STATE_DIR=/var/lib/clamav-agent
CRED_FILE=$STATE_DIR/credential
AGENT_USER=clamav-agent
SOCKET_CANDIDATES="/run/clamav/clamd.ctl /run/clamd.scan/clamd.sock /var/run/clamav/clamd.ctl"

WORK=''
cleanup() { if [ -n "$WORK" ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT INT TERM

die() { echo "install.sh: ERROR: $*" >&2; exit 1; }
say() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# minisign verification
# ---------------------------------------------------------------------------

check_pubkey() {
    # Must be a rendered key ("RW" + 54 base64 chars), not the template token.
    case "$MINISIGN_PUBKEY" in
        RW*) ;;
        *) die "this install script has no release public key embedded; use the install.sh produced by scripts/build-dist.sh" ;;
    esac
    [ "${#MINISIGN_PUBKEY}" -eq 56 ] || die "embedded public key has the wrong length"
    printf '%s' "$MINISIGN_PUBKEY" | grep -Eq '^RW[A-Za-z0-9+/]{54}$' || die "embedded public key is malformed"
}

# hex_to_bin HEX: write the bytes encoded by HEX to stdout (POSIX sh + awk).
hex_to_bin() {
    # shellcheck disable=SC2059 # the format is a generated \ooo escape list
    printf "$(printf '%s' "$1" | awk '{
        h = "0123456789abcdef"; s = tolower($0); out = ""
        for (i = 1; i < length(s); i += 2) {
            v = (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1
            out = out sprintf("\\%03o", v)
        }
        printf "%s", out
    }')"
}

b64dec() { printf '%s' "$1" | openssl base64 -d -A; }
hexof() { od -An -tx1 -v | tr -d ' \n'; }

# ed25519_verify PUBKEY_PEM MESSAGE_FILE SIG_FILE (raw 64-byte signature)
ed25519_verify() {
    openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$2" -sigfile "$3" >/dev/null 2>&1
}

# verify_with_openssl FILE SIGFILE: full minisign verification (both
# signatures and the key id) with openssl 3 + b2sum.
verify_with_openssl() {
    _t=$(mktemp -d) || return 1
    if _verify_openssl_inner "$1" "$2"; then _rc=0; else _rc=1; fi
    rm -rf "$_t"
    return $_rc
}

_verify_openssl_inner() {
    _file=$1; _sig=$2

    _l1=$(sed -n '1p' "$_sig" | tr -d '\r')
    _l2=$(sed -n '2p' "$_sig" | tr -d '\r')
    _l3=$(sed -n '3p' "$_sig" | tr -d '\r')
    _l4=$(sed -n '4p' "$_sig" | tr -d '\r')
    case "$_l1" in "untrusted comment: "*) ;; *) echo "bad untrusted comment line" >&2; return 1 ;; esac
    case "$_l3" in "trusted comment: "*) ;; *) echo "bad trusted comment line" >&2; return 1 ;; esac
    printf '%s' "$_l2" | grep -Eq '^[A-Za-z0-9+/]{99}=$' || { echo "malformed signature line" >&2; return 1; }
    printf '%s' "$_l4" | grep -Eq '^[A-Za-z0-9+/]{86}==$' || { echo "malformed global signature line" >&2; return 1; }

    b64dec "$MINISIGN_PUBKEY" > "$_t/pk" || return 1
    b64dec "$_l2" > "$_t/sigblob" || return 1
    b64dec "$_l4" > "$_t/gsig" || return 1
    [ "$(wc -c < "$_t/pk" | tr -d ' ')" -eq 42 ] || { echo "bad public key length" >&2; return 1; }
    [ "$(wc -c < "$_t/sigblob" | tr -d ' ')" -eq 74 ] || { echo "bad signature length" >&2; return 1; }
    [ "$(wc -c < "$_t/gsig" | tr -d ' ')" -eq 64 ] || { echo "bad global signature length" >&2; return 1; }

    [ "$(dd if="$_t/pk" bs=1 count=2 2>/dev/null | hexof)" = "4564" ] || { echo "unsupported public key algorithm" >&2; return 1; }
    _keyid_pk=$(dd if="$_t/pk" bs=1 skip=2 count=8 2>/dev/null | hexof)
    _keyid_sig=$(dd if="$_t/sigblob" bs=1 skip=2 count=8 2>/dev/null | hexof)
    [ "$_keyid_pk" = "$_keyid_sig" ] || { echo "signature was made with a different key (key id mismatch)" >&2; return 1; }

    # SubjectPublicKeyInfo DER prefix for an Ed25519 key, then the 32 raw bytes.
    { hex_to_bin 302a300506032b6570032100; dd if="$_t/pk" bs=1 skip=10 count=32 2>/dev/null; } > "$_t/pk.der"
    openssl pkey -pubin -inform DER -in "$_t/pk.der" -out "$_t/pk.pem" 2>/dev/null || { echo "cannot load public key" >&2; return 1; }
    dd if="$_t/sigblob" bs=1 skip=10 count=64 2>/dev/null > "$_t/sig"

    case "$(dd if="$_t/sigblob" bs=1 count=2 2>/dev/null | hexof)" in
        4544) # "ED": signature over BLAKE2b-512(file)
            command -v b2sum >/dev/null 2>&1 || { echo "b2sum is required for prehashed signatures" >&2; return 1; }
            _h=$(b2sum -l 512 < "$_file" | cut -d' ' -f1)
            printf '%s' "$_h" | grep -Eq '^[0-9a-f]{128}$' || { echo "b2sum failed" >&2; return 1; }
            hex_to_bin "$_h" > "$_t/msg"
            ed25519_verify "$_t/pk.pem" "$_t/msg" "$_t/sig" || { echo "signature verification FAILED" >&2; return 1; }
            ;;
        4564) # "Ed": legacy signature over the file itself
            ed25519_verify "$_t/pk.pem" "$_file" "$_t/sig" || { echo "signature verification FAILED" >&2; return 1; }
            ;;
        *) echo "unsupported signature algorithm" >&2; return 1 ;;
    esac

    # Global signature: Ed25519 over (signature || trusted comment text).
    { cat "$_t/sig"; printf '%s' "${_l3#trusted comment: }"; } > "$_t/global"
    ed25519_verify "$_t/pk.pem" "$_t/global" "$_t/gsig" || { echo "trusted comment signature verification FAILED" >&2; return 1; }

    echo "trusted comment: ${_l3#trusted comment: }"
    return 0
}

openssl_usable() {
    command -v openssl >/dev/null 2>&1 || return 1
    _v=$(openssl version 2>/dev/null | awk '{print $2}')
    case "$_v" in [3-9].*) ;; *) return 1 ;; esac
    command -v b2sum >/dev/null 2>&1
}

# minisign_verify FILE SIGFILE: verify with the minisign CLI when installed,
# else openssl 3 + b2sum. CAV_VERIFIER=openssl|minisign forces one (testing).
minisign_verify() {
    check_pubkey
    _mode=${CAV_VERIFIER:-auto}
    if [ "$_mode" = minisign ] || { [ "$_mode" = auto ] && command -v minisign >/dev/null 2>&1; }; then
        command -v minisign >/dev/null 2>&1 || die "minisign CLI not found"
        # -V verifies both the file signature and the trusted comment signature.
        minisign -V -q -P "$MINISIGN_PUBKEY" -m "$1" -x "$2"
        return $?
    fi
    if [ "$_mode" = openssl ] || [ "$_mode" = auto ]; then
        openssl_usable || die "cannot verify signatures: install minisign, or openssl >= 3 and b2sum (coreutils)"
        verify_with_openssl "$1" "$2"
        return $?
    fi
    die "unknown CAV_VERIFIER '$_mode'"
}

# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

download() { # URL DEST
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
}

# Prints the clamd socket path, or nothing.
detect_socket() {
    for s in $SOCKET_CANDIDATES; do
        if [ -S "$s" ]; then echo "$s"; return 0; fi
    done
    return 0
}

ensure_user() {
    if id "$AGENT_USER" >/dev/null 2>&1; then return 0; fi
    _nologin=/usr/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/bin/false
    command -v useradd >/dev/null 2>&1 || die "useradd not found"
    useradd --system --no-create-home --home-dir "$STATE_DIR" --shell "$_nologin" "$AGENT_USER"
    say "created system user $AGENT_USER"
}

join_socket_group() { # SOCKET_PATH
    _grp=$(stat -c %G "$1" 2>/dev/null || true)
    case "$_grp" in
        ''|UNKNOWN) echo "WARNING: cannot determine the group of $1" >&2 ;;
        root) echo "WARNING: $1 is owned by group root; not adding $AGENT_USER to root. Adjust clamd's LocalSocketGroup." >&2 ;;
        *)
            if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$_grp"; then
                say "$AGENT_USER is already in group $_grp"
            else
                usermod -a -G "$_grp" "$AGENT_USER"
                say "added $AGENT_USER to group $_grp (owner of $1)"
            fi
            ;;
    esac
}

install_agent() {
    reinstall=$1
    [ "$(id -u)" -eq 0 ] || die "must be run as root"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    check_pubkey

    : "${CAV_SERVER_URL:?CAV_SERVER_URL is required}"
    case "$CAV_SERVER_URL" in
        https://*) ;;
        *) die "CAV_SERVER_URL must start with https://" ;;
    esac
    printf '%s' "$CAV_SERVER_URL" | grep -Eq '^https://[][A-Za-z0-9.:-]+(/[A-Za-z0-9._~/-]*)?$' || die "CAV_SERVER_URL looks malformed"
    base=${CAV_SERVER_URL%/}

    need_enroll=0
    if [ "$reinstall" = 1 ] || [ ! -f "$CRED_FILE" ]; then need_enroll=1; fi
    if [ "$need_enroll" = 1 ] && [ -z "${CAV_ENROLL_TOKEN:-}" ]; then
        die "CAV_ENROLL_TOKEN is required to enroll"
    fi

    arch=$(detect_arch)
    WORK=$(mktemp -d)
    bin="clamav-agent_linux_${arch}"
    say "downloading $bin from $base/downloads/"
    download "$base/downloads/$bin" "$WORK/$bin"
    download "$base/downloads/$bin.minisig" "$WORK/$bin.minisig"
    download "$base/downloads/clamav-agent.service" "$WORK/clamav-agent.service"
    download "$base/downloads/clamav-agent.service.minisig" "$WORK/clamav-agent.service.minisig"

    say "verifying minisign signatures"
    minisign_verify "$WORK/$bin" "$WORK/$bin.minisig" || die "signature verification failed for $bin; NOT installing"
    minisign_verify "$WORK/clamav-agent.service" "$WORK/clamav-agent.service.minisig" || die "signature verification failed for clamav-agent.service; NOT installing"

    ensure_user

    if [ -n "${CAV_CLAMD_ADDR:-}" ]; then
        clamd_addr=$CAV_CLAMD_ADDR
        case "$clamd_addr" in unix://*) sock=${clamd_addr#unix://} ;; *) sock='' ;; esac
    else
        sock=$(detect_socket)
        if [ -n "$sock" ]; then
            clamd_addr="unix://$sock"
        else
            clamd_addr="unix:///run/clamav/clamd.ctl"
            echo "WARNING: no clamd socket found ($SOCKET_CANDIDATES); using $clamd_addr. Set CAV_CLAMD_ADDR if clamd lives elsewhere." >&2
        fi
    fi
    if [ -n "$sock" ] && [ -S "$sock" ]; then join_socket_group "$sock"; fi

    say "installing $BIN_DST"
    install -d -m 0755 -o root -g root /usr/local/bin
    install -m 0755 -o root -g root "$WORK/$bin" "$BIN_DST.new"
    mv -f "$BIN_DST.new" "$BIN_DST"

    install -d -m 0755 -o root -g root "$CONF_DIR"
    install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE_DIR"

    if [ "$need_enroll" = 1 ]; then
        say "enrolling with $base (clamd $clamd_addr)"
        replace=''
        if [ -f "$CRED_FILE" ]; then replace='--replace'; fi
        # The token is passed in the environment, never on the command line.
        # shellcheck disable=SC2086
        CAV_ENROLL_TOKEN="$CAV_ENROLL_TOKEN" "$BIN_DST" enroll --server "$base" --clamd "$clamd_addr" \
            --config "$CONF_FILE" --credential "$CRED_FILE" $replace || die "enrollment failed"
    else
        say "already enrolled; keeping the existing credential (use --reinstall to re-enroll)"
    fi
    unset CAV_ENROLL_TOKEN

    chown root:root "$CONF_FILE"; chmod 0644 "$CONF_FILE"
    chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR" "$CRED_FILE"
    chmod 0700 "$STATE_DIR"; chmod 0600 "$CRED_FILE"

    say "installing systemd unit"
    install -m 0644 -o root -g root "$WORK/clamav-agent.service" "$UNIT_DST"
    systemctl daemon-reload
    systemctl enable clamav-agent.service >/dev/null
    systemctl restart clamav-agent.service
    sleep 2
    if systemctl is-active --quiet clamav-agent.service; then
        say "clamav-agent is running"
    else
        echo "WARNING: clamav-agent is not running; see: journalctl -u clamav-agent" >&2
    fi
    "$BIN_DST" status --config "$CONF_FILE" --credential "$CRED_FILE" || true
}

main() {
    case "${1:-}" in
        --verify-only)
            [ $# -eq 3 ] || die "usage: install.sh --verify-only FILE SIGFILE"
            if minisign_verify "$2" "$3"; then echo "Signature OK"; exit 0; fi
            echo "Signature verification FAILED" >&2
            exit 1
            ;;
        --reinstall) install_agent 1 ;;
        '') install_agent 0 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
}

main "$@"
