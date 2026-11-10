#!/usr/bin/env bash
# Gate C3: PRIVATE, deliberately non-admitting B2 -> A3 -> C1 lifecycle,
# including independent observation of a possibly interrupted C1 transaction.
# NOT sourced by vpn or any production host driver. No VPN is activated and
# the quarantine is NEVER automatically disarmed or a temporary NM profile
# removed. Requires the B2/B4, A3, C1 and C2 libraries to be sourced first.
# Only an independently reviewed future host admission may ever replace the
# admission witness; it is an unconditional denial in this release.

mvc24gc3_reset() {
    MVC24GC3_ATTEMPTED=no
    MVC24GC3_STAGE=unverified
    MVC24GC3_AUTHORITY=none
    MVC24GC3_IFACE= MVC24GC3_SOURCE= MVC24GC3_REMOTE= MVC24GC3_PORT=
}

mvc24gc3_admission_witness() { return 1; }
mvc24gc3_authorize_activation() { return 1; }
mvc24gc3_authorize_cleanup() { return 1; }
mvc24gc3_authorize_disarm() { return 1; }
mvc24gc3_authorize_recovery() { return 1; }
mvc24gc3_authorize_secret_export() { return 1; }

# Candidate is an untrusted proposition until C2 authenticates the saved
# source, exact hardened clone and independently selected kernel route.
mvc24gc3_discover_candidate() {
    (( $# == 1 )) || return 1
    local iface=$1 endpoint=${MVC24OP_CANDIDATE_ENDPOINT:-}
    local remote port route_a route_b source
    [[ $endpoint =~ ^([0-9.]+):([0-9]+)$ ]] || return 1
    remote=${BASH_REMATCH[1]} port=${BASH_REMATCH[2]}
    mvc24gc1_ipv4 "$remote" && mvc24gc1_port "$port" || return 1
    [[ ${MVC24OP_CANDIDATE_PROTO:-} == tcp ]] || return 1
    route_a=$(ip -j -4 route get "$remote" 2>/dev/null) || return 1
    route_b=$(ip -j -4 route get "$remote" 2>/dev/null) || return 1
    [[ -n $route_a && $route_a == "$route_b" ]] || return 1
    source=$(jq -er '
       if type=="array" and length==1 then
           (.[0].prefsrc // .[0].src // empty)
       else empty end
    ' <<< "$route_a") || return 1
    mvc24gc1_parameters "$iface" "$source" "$remote" "$port" &&
        mvc24gc2_route_snapshot_matches "$route_a" "$iface" "$source" "$remote" || return 1
    MVC24GC3_IFACE=$iface MVC24GC3_SOURCE=$source
    MVC24GC3_REMOTE=$remote MVC24GC3_PORT=$port
}

# A single, root-held transaction. The DENY witness makes this safe to
# exercise only with disposable/mock substitutes, not on the real host.
# No fallback or retry. Every failure retains all available evidence and any
# existing guard, even when we cannot determine whether nft has committed.
mvc24gc3_execute_once() {
    (( $# == 2 )) || return 1
    [[ ${MVC24GC3_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC3_ATTEMPTED=yes
    MVC24GC3_STAGE=refused-preflight
    MVC24GC3_AUTHORITY=none
    local source_uuid=$1 iface=$2 policy
    policy=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1
    mvc24gc3_admission_witness && mvc24gb4_scope &&
        mvc24gb4_no_active_vpn && mvc24ga_uuid_valid "$source_uuid" &&
        mvc24gb1_valid_ifname "$iface" || return 1
    [[ ! -e /run/mvc-controller && ! -L /run/mvc-controller ]] || return 1
    MVC24GC3_STAGE=b2-install-attempted-uncertain
    mvc24gb2_install_once "$iface" "$policy" || return 1
    MVC24GC3_STAGE=quarantine-attestation-required
    mvc24gc2_guard_witness || return 1
    MVC24GC3_STAGE=a3-clone-or-hardening-attempted-uncertain
    mvc24ga3_prepare_once "$source_uuid" || return 1
    MVC24GC3_STAGE=quarantine-with-a3-prepared
    mvc24gc2_guard_witness && mvc24gc3_discover_candidate "$iface" || return 1
    mvc24gc2_endpoint_witness "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" \
        "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" || return 1
    MVC24GC3_STAGE=c1-transition-attempted-uncertain
    mvc24gc1_transition_once "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" \
        "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" || return 1
    # B2's deny-all observation intentionally no longer applies. Verify the
    # new policy against the persisted one-shot attempt and live kernel.
    mvc24gc3_post_c1_witness || return 1
    MVC24GC3_STAGE=pinned-bootstrap-verified-no-vpn-authority
    MVC24GC3_AUTHORITY=none
}

# Exact journal and batch parser. Its argument is solely for unit testing;
# it is not a root, lock or kernel witness and grants no permission.
mvc24gc3_transition_payload_valid() {
    (( $# == 1 )) || return 1
    local dir=$1 boot iface source remote port line
    local -a recorded=() batch=()
    [[ -f $dir/transition-attempt && ! -L $dir/transition-attempt &&
       -f $dir/transition.nft && ! -L $dir/transition.nft ]] || return 1
    mapfile -t recorded < "$dir/transition-attempt" || return 1
    (( ${#recorded[@]} == 6 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    [[ ${recorded[0]} == mvc-c1-transition-attempt-v1 &&
       ${recorded[1]} == state=attempted-once &&
       ${recorded[2]} == "boot=$boot" &&
       ${recorded[3]} == "prepare=$(sha256sum "$dir/prepare-intent" | cut -d' ' -f1)" &&
       ${recorded[4]} == "commit=$(sha256sum "$dir/commit-attempt" | cut -d' ' -f1)" &&
       ${recorded[5]} == "batch=$(sha256sum "$dir/transition.nft" | cut -d' ' -f1)" ]] || return 1
    mapfile -t batch < "$dir/transition.nft" || return 1
    (( ${#batch[@]} == 8 )) || return 1
    # Extract ONLY from the exact position and strictly anchored grammar;
    # independently rebuild the entire batch byte-for-byte below.
    line=${batch[3]}
    [[ $line =~ ^add\ rule\ inet\ mvc_preclone_quarantine\ output_deny\ oifname\ \"([a-zA-Z0-9_.-]+)\"\ ip\ saddr\ ([0-9.]+)\ ip\ daddr\ ([0-9.]+)\ tcp\ dport\ ([0-9]+)\ accept$ ]] || return 1
    iface=${BASH_REMATCH[1]} source=${BASH_REMATCH[2]}
    remote=${BASH_REMATCH[3]} port=${BASH_REMATCH[4]}
    [[ $iface == "$(mvc24gb2_derive_iface)" ]] &&
        mvc24gc1_parameters "$iface" "$source" "$remote" "$port" &&
        mvc24gc1_batch_valid "$iface" "$source" "$remote" "$port" "$dir/transition.nft" || return 1
    MVC24GC3_IFACE=$iface MVC24GC3_SOURCE=$source
    MVC24GC3_REMOTE=$remote MVC24GC3_PORT=$port
}

mvc24gc3_transition_records_valid() {
    (( $# == 0 )) || return 1
    local dir
    dir=$(mvc24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller ]] || return 1
    mvc24gb2_runtime_shape && mvc24gb2_records_valid &&
        mvc24gc2_lock_held "$dir/controller.lock" "$MVC24GB2_FD" || return 1
    [[ $(find "$dir" -mindepth 1 -maxdepth 1 -print | wc -l) -eq 10 ]] || return 1
    mvc24gc3_transition_payload_valid "$dir"
}

# Read-only C1 state classification. A successful result is NOT permission to
# activate, retry, disarm, clean profiles or export secrets. An interrupted
# transition may leave quarantine OR endpoint-only egress; neither may be
# assumed until independent state reconciliation succeeds.
mvc24gc3_post_c1_witness() {
    (( $# == 0 )) || return 1
    MVC24GC3_AUTHORITY=none
    mvc24gb2_root_scope && mvc24gc3_transition_records_valid || return 1
    local dir scratch first second foreign_before foreign_after
    dir=$(mvc24gb2_runtime) || return 1
    scratch=$(mktemp -d /run/mvc-c3-observe.XXXXXXXX) || return 1
    chmod 700 "$scratch" || return 1
    local good=1
    first=$scratch/nft1.json second=$scratch/nft2.json
    if ! mvc24gb1_capture_nft "$first" ||
       ! mvc24gb1_capture_nft "$second" ||
       ! cmp -s -- "$first" "$second" ||
       ! mvc24gc1_postshape_observation "$first" "$MVC24GC3_IFACE" \
            "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" ||
       ! mvc24gc1_postshape_observation "$second" "$MVC24GC3_IFACE" \
            "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT"; then
        good=0
    fi
    if (( good == 1 )); then
        foreign_before=$(mvc24gb2_foreign_projection "$dir/prestate.json") || good=0
        foreign_after=$(mvc24gb2_foreign_projection "$first") || good=0
        [[ $foreign_before == "$foreign_after" ]] || good=0
    fi
    if (( good == 1 )); then
        mvc24gb1_capture_links "$scratch/links.json" &&
        mvc24gb1_capture_routes4 "$scratch/routes4.json" &&
        mvc24gb1_capture_routes6 "$scratch/routes6.json" &&
        cmp -s "$scratch/links.json" "$dir/links.json" &&
        cmp -s "$scratch/routes4.json" "$dir/routes4.json" &&
        cmp -s "$scratch/routes6.json" "$dir/routes6.json" &&
        mvc24gc3_transition_records_valid || good=0
    fi
    rm -f -- "$scratch/nft1.json" "$scratch/nft2.json" \
        "$scratch/links.json" "$scratch/routes4.json" "$scratch/routes6.json" || good=0
    rmdir -- "$scratch" || good=0
    (( good == 1 ))
}

# Called from a NEW, root-scoped observation process. It reads an original
# eight-file B2 deny-all record OR a complete ten-file C1 transaction. It
# never guesses a partial post-crash state, changes nft/NM or opens a tunnel.
mvc24gc3_reconcile_readonly() {
    (( $# == 0 )) || return 1
    MVC24GC3_STAGE=unverified-ambiguous-manual-review
    MVC24GC3_AUTHORITY=none
    [[ -z ${MVC24GB2_FD:-} ]] && mvc24gb2_root_scope || return 1
    local dir entries fd
    dir=$(mvc24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller && -d $dir && ! -L $dir ]] || return 1
    entries=$(find "$dir" -mindepth 1 -maxdepth 1 -print | wc -l) || return 1
    case $entries in
      8)
          if mvc24gb2_reopen && mvc24gc2_guard_witness; then
              MVC24GC3_STAGE=deny-all-observed-no-vpn-authority
              mvc24gb2_close
              return 0
          fi
          mvc24gb2_close
          return 1
          ;;
      10)
          mvc24gb2_root_scope && mvc24gb2_runtime_shape || return 1
          exec {fd}< "$dir/controller.lock" || return 1
          if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
          MVC24GB2_FD=$fd
          if mvc24gc3_post_c1_witness; then
              MVC24GC3_STAGE=pinned-bootstrap-observed-no-vpn-authority
              mvc24gb2_close
              return 0
          fi
          mvc24gb2_close
          return 1
          ;;
      *) return 1 ;;
    esac
}
