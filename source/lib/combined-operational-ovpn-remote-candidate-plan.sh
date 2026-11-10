#!/usr/bin/env bash
# Step 2B2C3F5: pure, read-only source-list -> one explicit candidate proposal.
# Inputs MUST be stable, typed NM GetSettings already authenticated by caller.
# NO mutation, network/DNS calls, exported activation authority or profile clone.
# Requires dual-session.sh / combined-routing-guard.sh for strict endpoints.

ubs24op_candidate_reset() {
    UBS24OP_CANDIDATE_ENDPOINT=''
    UBS24OP_CANDIDATE_PROTO=''
    UBS24OP_CANDIDATE_COUNT=0
    UBS24OP_CANDIDATE_INDEX=0
}

# Args: typed GetSettings JSON, 1-based source-order index.
# Must validate the ENTIRE list, not just the chosen entry: a malformed later
# remote must never be silently discarded to construct a misleading plan.
# The strict v2.4 witness MUST still independently validate a separate
# controller-owned single-remote saved profile and its effective socket.
ubs24op_candidate_plan() {
    ubs24op_candidate_reset
    (( $# == 2 )) || return 1
    local file=$1 index=$2 remote entry
    local -a entries=()
    [[ -f $file && ! -L $file && $index =~ ^[1-9][0-9]{0,2}$ ]] || return 1
    (( 10#$index <= 128 )) || return 1
    declare -F ubs24b_canonical_endpoint >/dev/null || return 1
    command -v jq >/dev/null 2>&1 || return 1
    # Conservative version-specific subset only. Per-entry protocol, separate
    # port and remote-random-hostname are out of scope; tcp is mandatory here.
    # Remote-random may be enabled in the SOURCE, never in the future derivative.
    jq -e '
        .type == "a{sa{sv}}" and
        (.data | type == "array" and length == 1) and
        .data[0].connection.type == {type:"s",data:"vpn"} and
        .data[0].vpn["service-type"] == {type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
        .data[0].vpn.data.type == "a{ss}" and
        (.data[0].vpn.data.data | type) == "object" and
        (.data[0].vpn.data.data as $v |
            ($v | has("port") | not) and
            $v["proto-tcp"] == "yes" and
            (($v["remote-random"] // "no") == "yes" or ($v["remote-random"] // "no") == "no") and
            (($v["remote-random-hostname"] // "no") == "no") and
            ($v.remote | type) == "string" and
            ($v.remote | length) <= 8192 and
            ($v.remote | test("^[0-9.,: \t]+$")) and
            ($v.remote | test("[\\r\\n]") | not)
        )
    ' -- "$file" >/dev/null 2>&1 || return 1
    remote=$(jq -er '.data[0].vpn.data.data.remote' -- "$file") || return 1
    # Bash read consumes one line. Disallow any embedded newline/CR so that
    # the entire authenticated source list is always validated, never a prefix.
    [[ $remote != *$'\n'* && $remote != *$'\r'* ]] || return 1
    remote=${remote//,/ }
    read -r -a entries <<< "$remote"
    (( ${#entries[@]} >= 1 && ${#entries[@]} <= 128 && index <= ${#entries[@]} )) || return 1
    for entry in "${entries[@]}"; do
        # Explicit port and no per-remote protocol or implicit fallback. The
        # shared canonical parser rejects noncanonical IPv4, zero/leading-zero
        # ports, out-of-range ports, invalid octets and non-IPv4 transport.
        [[ $entry =~ ^([0-9.]+):([1-9][0-9]{0,4})$ ]] &&
            ubs24b_canonical_endpoint "$entry" || return 1
    done
    UBS24OP_CANDIDATE_ENDPOINT=${entries[index-1]}
    UBS24OP_CANDIDATE_PROTO=tcp
    UBS24OP_CANDIDATE_COUNT=${#entries[@]}
    UBS24OP_CANDIDATE_INDEX=$index
}
