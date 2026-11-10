#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 — Agent 4, Step 2B2C3F14.
# NON-ADMITTING, read-only nft JSON shape checking and reference batch export.
# No nft invocation, no firewall writes, no GetSecrets, no NM, no activation.
# Input snapshots are supplied by a TEST. They are not authenticated kernel
# witnesses, and neither a PASS nor the export grants operational authority.

ubs24op_qg_reset() {
    UBS24OP_QG_FINDING=unverified
    UBS24OP_QG_AUTHORITY=none
    UBS24OP_QG_COVERAGE=host-ip-output-forward-and-linux-bridge-forward-only
    UBS24OP_QG_NAMESPACE_STATUS=unmanaged-external-egress-unsupported
}

# Snapshot is a private nft -j -n -s list ruleset FILE, not a shell string.
# An eventual privileged caller must bind snapshots to fixed-root lock and
# authenticate the actual netns/ruleset; F14 explicitly does neither.
ubs24op_qg_preflight_snapshot() {
    ubs24op_qg_reset
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    jq -e '
        def owned($v):
            (($v.family == "inet" and
                (($v.table // $v.name // "") == "vpn_v240_preclone_quarantine")) or
             ($v.family == "bridge" and
                (($v.table // $v.name // "") == "vpn_v240_preclone_bridge")));
        type == "object" and (.nftables | type) == "array" and
        all(.nftables[]; type == "object" and ((keys | length) == 1) and
            ((keys[0]) as $k | ["metainfo","table","chain","rule","set","element",
                 "flowtable","map","counter","quota","limit","ct helper",
                 "ct timeout","ct expectation","synproxy"] | index($k) != null)) and
        ([(.nftables[] | to_entries[] | select(.key != "metainfo") | .value |
            select(type == "object" and owned(.)))] | length) == 0 and
        ([.nftables[] | .flowtable? | select(. != null)] | length) == 0
    ' -- "$1" >/dev/null 2>&1 || return 1
    UBS24OP_QG_FINDING=offline-prestate-has-no-quarantine-object
}

# A precise, conservative witness: exactly two owned tables and three empty
# policy-DROP base chains, no owned rules, sets, maps, flowtables or extras.
# No assertion about packets that bypass these netfilter hooks.
ubs24op_qg_postshape_snapshot() {
    ubs24op_qg_reset
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    jq -e '
        def owned($v):
            (($v.family == "inet" and
                (($v.table // $v.name // "") == "vpn_v240_preclone_quarantine")) or
             ($v.family == "bridge" and
                (($v.table // $v.name // "") == "vpn_v240_preclone_bridge")));
        def matches($f;$t;$n;$h):
            (.family == $f and .table == $t and .name == $n and
             .type == "filter" and .hook == $h and .prio == -310 and
             .policy == "drop");
        type == "object" and (.nftables | type) == "array" and
        all(.nftables[]; type == "object" and ((keys | length) == 1) and
            ((keys[0]) as $k | ["metainfo","table","chain","rule","set","element",
                 "flowtable","map","counter","quota","limit","ct helper",
                 "ct timeout","ct expectation","synproxy"] | index($k) != null)) and
        ([.nftables[] | .table? | select(. != null and owned(.))] | length) == 2 and
        ([.nftables[] | .table? | select(. != null and .family == "inet" and
            .name == "vpn_v240_preclone_quarantine")] | length) == 1 and
        ([.nftables[] | .table? | select(. != null and .family == "bridge" and
            .name == "vpn_v240_preclone_bridge")] | length) == 1 and
        ([.nftables[] | .chain? | select(. != null and owned(.))] | length) == 3 and
        ([.nftables[] | .chain? | select(. != null and
            matches("inet";"vpn_v240_preclone_quarantine";"output_deny";"output"))] | length) == 1 and
        ([.nftables[] | .chain? | select(. != null and
            matches("inet";"vpn_v240_preclone_quarantine";"forward_deny";"forward"))] | length) == 1 and
        ([.nftables[] | .chain? | select(. != null and
            matches("bridge";"vpn_v240_preclone_bridge";"forward_deny";"forward"))] | length) == 1 and
        ([.nftables[] | to_entries[] | select(.key != "table" and .key != "chain" and
            .key != "metainfo") | .value | select(type == "object" and owned(.))] | length) == 0 and
        ([.nftables[] | .flowtable? | select(. != null)] | length) == 0
    ' -- "$1" >/dev/null 2>&1 || return 1
    UBS24OP_QG_FINDING=offline-quarantine-policy-shape-matches
}

# Pure export of a reviewable reference file. Never executes it.
ubs24op_qg_export_reference() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    [[ -n ${UBS24OP_QG_REFERENCE:-} && -f $UBS24OP_QG_REFERENCE &&
       ! -L $UBS24OP_QG_REFERENCE ]] || return 1
    cmp -s -- "$1" "$UBS24OP_QG_REFERENCE" || return 1
    cat -- "$1"
}

# No model outcome may be used to create a clone, modify nft, modify NM, or
# authorise recovery/disarm. The missing scope/identity/routing witnesses are
# real production blockers, not optional hardening.
ubs24op_qg_authorize_install() { return 1; }
ubs24op_qg_authorize_clone() { return 1; }
ubs24op_qg_authorize_activation() { return 1; }
ubs24op_qg_authorize_disarm() { return 1; }
ubs24op_qg_authorize_recovery() { return 1; }
