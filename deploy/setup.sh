#!/bin/sh
# Sets up (or upgrades) the console on this host with Docker Compose.
#
# Usage, from anywhere (as a user that can run docker):
#   deploy/setup.sh
#   deploy/setup.sh --hostname 192.168.1.50 --admin-cidr 192.168.1.0/24 --yes
#
# Options:
#   --hostname HOST     console hostname or IP (default: this host's IP)
#   --admin-cidr CIDRS  space-separated networks allowed to use the web UI
#                       (default: this host's local network)
#   --email EMAIL       Let's Encrypt contact, only for a public DNS name
#   --admin-email EMAIL first admin to create if there is none
#   --yes               accept the defaults without asking
#
# What it does:
#   1. Creates deploy/.env with fresh random secrets (an existing .env is kept
#      as is; edit it to change settings, then run this again).
#   2. Builds and starts the stack (docker compose up -d --build).
#   3. If Caddy serves the console with its internal CA (an IP address or a
#      local name such as buoy.internal), publishes that CA as
#      downloads/console-ca.pem so the agent install commands can pin it.
#   4. Creates the first admin if there is none (the password is asked for
#      by the server, never passed as an argument).
#
# Running it again upgrades the stack and keeps the data, secrets and admins.
set -eu

die() { echo "setup.sh: ERROR: $*" >&2; exit 1; }
say() { echo "==> $*"; }

cd "$(dirname "$0")"

HOST=''
CIDRS=''
EMAIL=''
ADMIN_EMAIL=''
YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --hostname|--admin-cidr|--email|--admin-email)
            [ $# -ge 2 ] || die "$1 needs a value"
            case "$1" in
                --hostname) HOST=$2 ;;
                --admin-cidr) CIDRS=$2 ;;
                --email) EMAIL=$2 ;;
                --admin-email) ADMIN_EMAIL=$2 ;;
            esac
            shift
            ;;
        --yes|-y) YES=1 ;;
        -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
        *) die "unknown argument $1 (see --help)" ;;
    esac
    shift
done

INTERACTIVE=0
if [ "$YES" = 0 ] && [ -t 0 ]; then INTERACTIVE=1; fi

# ask VAR PROMPT DEFAULT: set VAR from the terminal, or to DEFAULT.
ask() {
    _v=$3
    if [ "$INTERACTIVE" = 1 ]; then
        printf '%s [%s]: ' "$2" "$3"
        read -r _in || true
        if [ -n "$_in" ]; then _v=$_in; fi
    fi
    eval "$1=\$_v"
}

for c in docker openssl curl awk; do
    command -v "$c" >/dev/null 2>&1 || die "$c is required (Ubuntu: sudo apt install docker.io docker-compose-v2 openssl curl)"
done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (Ubuntu: sudo apt install docker-compose-v2)"
docker info >/dev/null 2>&1 || die "cannot talk to Docker; run with sudo or add yourself to the docker group (then log in again)"

# The first IPv4 address, with its prefix length (e.g. 192.168.1.50/24), of
# the interface that has the default route. Without iproute2, guesses /24.
default_ip_cidr() {
    if command -v ip >/dev/null 2>&1; then
        _dev=$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
        if [ -n "$_dev" ]; then
            ip -o -4 addr show dev "$_dev" 2>/dev/null | awk '{ print $4; exit }'
        else
            ip -o -4 addr show scope global 2>/dev/null | awk '{ print $4; exit }'
        fi
    elif command -v hostname >/dev/null 2>&1; then
        hostname -I 2>/dev/null | awk '{ if ($1 != "") print $1 "/24"; exit }'
    fi
}

network_of() { # 192.168.1.50/24 -> 192.168.1.0/24
    printf '%s' "$1" | awk -F/ '{
        split($1, o, "."); bits = $2; out = ""
        for (i = 1; i <= 4; i++) {
            n = bits >= 8 ? 8 : (bits > 0 ? bits : 0); bits -= n
            m = 256 - 2 ^ (8 - n)
            v = 0
            for (b = 128; b >= 1; b /= 2) { if (int(o[i] / b) % 2 && int(m / b) % 2) v += b }
            out = out (i > 1 ? "." : "") v
        }
        print out "/" $2
    }'
}

is_local_name() { # true for names Caddy serves from its internal CA
    case "$1" in
        *[!0-9.]*) ;;
        *) return 0 ;; # IPv4 address
    esac
    case "$1" in
        *:*|localhost|*.localhost|*.local|*.internal|*.home.arpa) return 0 ;;
        *.*) return 1 ;;
        *) return 0 ;;
    esac
}

if [ -f .env ]; then
    say "keeping the existing deploy/.env (edit it to change settings)"
else
    ipcidr=$(default_ip_cidr || true)
    ip=${ipcidr%/*}
    [ -n "$HOST" ] || ask HOST "Console hostname or IP that agents will connect to" "$ip"
    [ -n "$HOST" ] || die "cannot detect this host's IP address; pass --hostname"
    if [ -z "$CIDRS" ]; then
        net=''
        if [ -n "$ipcidr" ]; then net=$(network_of "$ipcidr"); fi
        ask CIDRS "Networks allowed to open the web UI (space-separated CIDRs)" "${net:-100.64.0.0/10}"
    fi
    for c in $CIDRS; do
        case "$c" in
            */*) ;;
            *) die "admin network '$c' is not a CIDR (e.g. 192.168.1.0/24)" ;;
        esac
        case "$c" in
            172.1[6-9].*|172.2[0-9].*|172.3[01].*)
                echo "WARNING: $c overlaps Docker's internal networks; some requests could then reach the UI from inside Docker. Prefer your LAN or VPN range." >&2 ;;
        esac
    done
    if is_local_name "$HOST"; then
        # Caddy uses its internal CA for these names, so ACME is not used.
        EMAIL=${EMAIL:-unused@example.invalid}
    else
        [ -n "$EMAIL" ] || ask EMAIL "Email for Let's Encrypt notices" ""
        [ -n "$EMAIL" ] || die "--email is required for a public hostname (Let's Encrypt)"
    fi
    say "writing deploy/.env with new random secrets"
    old_umask=$(umask)
    umask 077
    cat > .env <<EOF
# Written by deploy/setup.sh. Holds secrets: keep a copy in your password
# manager (losing TOKEN_HASH_KEY forces every agent to re-enroll) and never
# commit it. See .env.example and docs/operations.md.
CAV_HOSTNAME=$HOST
ACME_EMAIL=$EMAIL
ADMIN_ALLOWED_CIDRS=$CIDRS
POSTGRES_PASSWORD=$(openssl rand -hex 24)
CAV_APP_DB_PASSWORD=$(openssl rand -hex 24)
TOKEN_HASH_KEY=$(openssl rand -base64 32)
TOKEN_HASH_KEY_PREVIOUS=
AGENT_OFFLINE_AFTER_SECONDS=180
CAV_DOWNLOADS_PATH=./downloads
EOF
    umask "$old_umask"
fi

env_value() { sed -n "s/^$1=//p" .env | tail -n 1; }
HOST=$(env_value CAV_HOSTNAME)
[ -n "$HOST" ] || die "CAV_HOSTNAME is not set in deploy/.env"
DOWNLOADS=$(env_value CAV_DOWNLOADS_PATH)
DOWNLOADS=${DOWNLOADS:-./downloads}
mkdir -p "$DOWNLOADS"
chmod 0755 "$DOWNLOADS"

say "building and starting the console (docker compose up -d --build)"
docker compose up -d --build

say "waiting for https://$HOST to answer"
i=0
until curl -fsSk --max-time 5 https://127.0.0.1/healthz >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || die "the console did not come up; check: docker compose ps && docker compose logs caddy server"
    sleep 2
done

# Is the certificate from Caddy's internal CA?
issuer=$(echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || true)
CA_PUB="$DOWNLOADS/console-ca.pem"
fingerprint=''
case "$issuer" in
    *"Caddy Local Authority"*)
        tmp=$(mktemp)
        docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$tmp" >/dev/null
        openssl x509 -in "$tmp" -out "$CA_PUB"
        rm -f "$tmp"
        chmod 0644 "$CA_PUB"
        fingerprint=$(openssl x509 -in "$CA_PUB" -noout -fingerprint -sha256 | sed 's/^.*=//')
        say "published Caddy's internal CA as $CA_PUB"
        ;;
    *)
        if [ -f "$CA_PUB" ]; then
            rm -f "$CA_PUB"
            say "the console has a publicly trusted certificate; removed the old $CA_PUB"
        fi
        ;;
esac

users=$(docker compose exec -T postgres psql -U cav_owner -d cav -Atc 'SELECT count(*) FROM users' 2>/dev/null || echo '?')
if [ "$users" = 0 ]; then
    if [ -t 0 ] && [ -t 1 ]; then
        [ -n "$ADMIN_EMAIL" ] || ask ADMIN_EMAIL "Email of the first admin" "admin@example.com"
        say "creating the first admin $ADMIN_EMAIL (choose a password of at least 12 characters)"
        docker compose run --rm -it server admin create-user --email "$ADMIN_EMAIL"
    else
        echo "No admin exists yet. Create one with:" >&2
        echo "  cd $(pwd) && docker compose run --rm -it server admin create-user --email you@example.com" >&2
    fi
fi

echo
say "the console is running"
echo "    Web UI:          https://$HOST  (only from $(env_value ADMIN_ALLOWED_CIDRS))"
if [ -n "$fingerprint" ]; then
    echo "    Private CA:      SHA-256 $fingerprint"
    echo "                     Browsers will warn until you trust it: import $(pwd)/${CA_PUB#./}"
    echo "                     (also at https://$HOST/downloads/console-ca.pem) and compare the fingerprint."
fi
if [ ! -f "$DOWNLOADS/install.sh" ]; then
    echo "    Agent release:   none published yet. Build and sign one (docs/release-signing.md),"
    echo "                     then copy dist/downloads/* into $(pwd)/${DOWNLOADS#./}/"
fi
echo "    Next:            sign in, create a tenant and an enrollment token, and paste the"
echo "                     install command it shows on each endpoint."
echo "    Back up:         deploy/.env (secrets) and the database (docs/operations.md)."
