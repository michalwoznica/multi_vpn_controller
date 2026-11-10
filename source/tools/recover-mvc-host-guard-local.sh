#!/usr/bin/env bash
# Manual emergency rollback for the B4 maintenance quarantine ONLY.
# This intentionally bypasses the B2/B3 journal if it is damaged.
# It does NOT remove other VPN/firewall tables, and it does NOT repair NM.
# Use from a physical/local terminal, after deciding to disable v2.4 protection.
set -euo pipefail
umask 077

usage() {
    printf '%s\n' 'Usage: recover-mvc-host-guard-local.sh --inspect|--rollback' >&2
    exit 2
}
(( $# == 1 )) || usage
case $1 in --inspect|--rollback) mode=$1 ;; *) usage ;; esac
(( EUID == 0 )) || { echo 'ERROR: root required' >&2; exit 1; }
command -v nft >/dev/null && command -v jq >/dev/null || {
    echo 'ERROR: nft and jq required; see direct nft fallback in handoff' >&2
    exit 1
}

# Read-only snapshot of table names; reject invalid nft JSON.  Match ONLY the
# three hard-coded tables owned by B4.  Never interpolate discovered names
# into arbitrary nft commands.
owned_tables() {
    local json
    json=$(nft -j list tables) || return 1
    jq -r '
      if type != "object" or (.nftables | type) != "array" or
         any(.nftables[]; type != "object" or (keys | length) != 1)
      then error("malformed nft list-tables JSON")
      else
        [.nftables[] | .table? | select(type == "object") |
           select((.family == "inet" and .name == "vpn_v240_preclone_quarantine") or
                  (.family == "bridge" and .name == "vpn_v240_preclone_bridge") or
                  (.family == "netdev" and .name == "vpn_v240_preclone_underlay")) |
           "\(.family):\(.name)"] | unique | join("\n")
      end
    ' <<< "$json"
}

before=$(owned_tables) || { echo 'ERROR: cannot inventory nft tables' >&2; exit 1; }
if [[ -z $before ]]; then
    echo 'PASS: none of the three B4 quarantine tables is present'
    echo 'RESULT: no nftables changes; other connectivity issues need separate diagnosis'
    exit 0
fi
printf '%s\n' 'B4 quarantine tables currently present:' "$before"
if [[ $mode == --inspect ]]; then
    echo 'RESULT: READ-ONLY OBSERVATION; NO RULES CHANGED'
    exit 0
fi

[[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty &&
   -z ${SSH_CONNECTION:-} && -z ${SSH_TTY:-} ]] || {
    echo 'ERROR: --rollback requires a local interactive terminal' >&2
    exit 1
}
printf '%s\n' \
  'WARNING: This deliberately DISABLES the B4 v2.4 quarantine, even if its journal is damaged.' \
  'It is NOT safe to use for an active protected VPN session.' \
  'Type exactly: EMERGENCY RELEASE MVC' > /dev/tty
printf '> ' > /dev/tty
IFS= read -r confirmation < /dev/tty || exit 1
[[ $confirmation == 'EMERGENCY RELEASE MVC' ]] || {
    echo 'ERROR: confirmation refused' >&2
    exit 1
}

# State must remain stable between the original observation and commitment.
again=$(owned_tables) || exit 1
[[ $before == "$again" ]] || {
    echo 'ERROR: quarantine table set changed; no nftables write attempted' >&2
    exit 1
}

batch=$(mktemp /run/ubs-v240-emergency-delete.XXXXXXXX.nft) || exit 1
trap 'rm -f -- "$batch"' EXIT
chmod 600 -- "$batch"
while IFS= read -r table; do
    case "$table" in
        inet:vpn_v240_preclone_quarantine)
            echo 'delete table inet vpn_v240_preclone_quarantine' >> "$batch" ;;
        bridge:vpn_v240_preclone_bridge)
            echo 'delete table bridge vpn_v240_preclone_bridge' >> "$batch" ;;
        netdev:vpn_v240_preclone_underlay)
            echo 'delete table netdev vpn_v240_preclone_underlay' >> "$batch" ;;
        *) echo 'ERROR: unexpected table identifier' >&2; exit 1 ;;
    esac
done <<< "$before"

nft --check --file "$batch" || {
    echo 'ERROR: nft rejected emergency delete batch; no commit attempted' >&2
    exit 1
}
# A single atomic nft batch. No retry after a failed or ambiguous commit.
if ! nft --file "$batch"; then
    echo 'ERROR: nft commit failed or is uncertain; check tables manually' >&2
    exit 1
fi
remaining=$(owned_tables) || {
    echo 'UNVERIFIED: deletion submitted, but poststate cannot be read' >&2
    exit 1
}
[[ -z $remaining ]] || {
    printf '%s\n' 'UNVERIFIED: some B4 quarantine tables remain:' "$remaining" >&2
    exit 1
}
printf '%s\n' \
  'PASS: all three B4 quarantine tables are absent' \
  'RESULT: EMERGENCY DISARM COMPLETE — MVC kill switch OFF; other nftables tables untouched' \
  'NOTE: B2/B3 journal is intentionally retained; do not retry B4 install in this boot'
