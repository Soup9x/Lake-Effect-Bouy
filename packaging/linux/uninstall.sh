#!/bin/sh
# Removes the ClamAV console agent. Run as root.
#
#   sh uninstall.sh            # remove service, binary, config, credential, user
#   sh uninstall.sh --keep-data  # keep /etc/clamav-agent and /var/lib/clamav-agent
#
# This does not revoke the agent in the console; revoke it there too.
set -eu

die() { echo "uninstall.sh: ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "must be run as root"

keep=0
case "${1:-}" in
    --keep-data) keep=1 ;;
    '') ;;
    *) die "unknown argument $1" ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now clamav-agent.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/clamav-agent.service
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
rm -f /usr/local/bin/clamav-agent /usr/local/bin/clamav-agent.new

if [ "$keep" = 0 ]; then
    rm -rf /etc/clamav-agent /var/lib/clamav-agent
    if id clamav-agent >/dev/null 2>&1; then
        userdel clamav-agent 2>/dev/null || echo "WARNING: could not delete user clamav-agent" >&2
    fi
fi
echo "clamav-agent removed. Remember to revoke this endpoint in the console."
