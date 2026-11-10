#!/usr/bin/env bash
# C18: PRIVATE, read-only DNS evidence BEFORE the C13 tunnel-OUTPUT permit.
# Requires held C1 endpoint-only quarantine, C9/C7/C11, and C16 fixed-path
# host DNS reader. C1 blocks ordinary OUTPUT throughout this verification.
# Recheck once AFTER C13 records its immutable intent and IMMEDIATELY before
# nft --file. No DNS/NM/firewall writes and no authority granted.

mvc24gc18_reset() {
    UBS24GC18_STAGE=unverified-precommit-dns
    UBS24GC18_DETAIL_STAGE=unverified
    UBS24GC18_AUTHORITY=none
    UBS24GC18_DNS_FINGERPRINT=
    UBS24GC18_NM_FINGERPRINT=
    UBS24GC18_ROUTE_FINGERPRINT=
    UBS24GC18_NSS_MODE=
    UBS24GC18_RECHECK_FAILURE=none
    UBS24GC18_OBS_NM_FINGERPRINT=
    UBS24GC18_OBS_ROUTE_FINGERPRINT=
    UBS24GC18_OBS_DNS_FINGERPRINT=
    UBS24GC18_OBS_NSS_MODE=
    UBS24GC18_DNS_CAPTURE_DETAIL=
}
mvc24gc18_authorize_public_activation() { return 1; }
mvc24gc18_authorize_traffic() { return 1; }
mvc24gc18_authorize_dns_change() { return 1; }
mvc24gc18_authorize_cleanup() { return 1; }
mvc24gc18_authorize_retry() { return 1; }
mvc24gc18_authorize_disarm() { return 1; }
mvc24gc18_authorize_secret_export() { return 1; }

# Same active NM connection, pinned physical endpoint and two unrelated
# public IPv4 destinations must continue to select the same VPN tunnel.
mvc24gc18_snapshot() {
    (( $# == 0 )) || return 1
    local nm route expected_route
    nm=$(mvc24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || return 1
    route=$(mvc24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    expected_route="$UBS24GC3_IFACE|$UBS24GC3_SOURCE|$UBS24GC11_TUNNEL|$UBS24GC11_TUNNEL_SOURCE"
    [[ -n $nm && $nm == "${UBS24GC6_NM_SNAPSHOT:-}" &&
       $route == "$expected_route" && $route == "${UBS24GC6_ROUTE_SNAPSHOT:-}" ]] || return 1
    UBS24GC18_NM_NOW=$nm
    UBS24GC18_ROUTE_NOW=$route
}

mvc24gc18_precommit_locked() {
    mvc24gc18_reset
    (( $# == 0 )) || return 1
    UBS24GC18_DETAIL_STAGE=upstream-stage-contract
    [[ ${UBS24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard &&
       ${UBS24GC9_AUTHORITY:-} == none &&
       ${UBS24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${UBS24GC7_AUTHORITY:-} == none &&
       ${UBS24GC11_STAGE:-} == prospective-ipv4-host-tunnel-output-only-no-commit-authority &&
       ${UBS24GC11_AUTHORITY:-} == none &&
       ${UBS24GC11_TUNNEL:-} == tun-vpnks &&
       -n ${UBS24GC11_TUNNEL_SOURCE:-} ]] || return 1
    UBS24GC18_DETAIL_STAGE=controller-guard-and-intent-witness
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
      mvc24gc3_transition_records_valid && mvc24gc7_read_intent &&
      mvc24gc5_guard_witness || return 1
    local first second nm_before route_before mode
    UBS24GC18_DETAIL_STAGE=snapshot-before-dns
    mvc24gc18_snapshot || return 1
    nm_before=$UBS24GC18_NM_NOW route_before=$UBS24GC18_ROUTE_NOW
    UBS24GC18_DETAIL_STAGE=dns-capture-first
    mvc24gc16_dns_capture || return 1
    first=$UBS24AG2D_CAPTURE mode=$UBS24AG2D_NSS_MODE
    UBS24GC18_DETAIL_STAGE=dns-capture-first-contract
    [[ -n $first && ( $mode == strict-direct || $mode == arch-conditional ) ]] || return 1
    UBS24GC18_DETAIL_STAGE=guard-and-snapshot-between-captures
    mvc24gc5_guard_witness && mvc24gc18_snapshot || return 1
    UBS24GC18_DETAIL_STAGE=snapshot-stability-between-captures
    [[ $UBS24GC18_NM_NOW == "$nm_before" &&
       $UBS24GC18_ROUTE_NOW == "$route_before" ]] || return 1
    UBS24GC18_DETAIL_STAGE=dns-capture-second
    mvc24gc16_dns_capture || return 1
    second=$UBS24AG2D_CAPTURE
    UBS24GC18_DETAIL_STAGE=dns-capture-stability
    [[ -n $second && $second == "$first" && $UBS24AG2D_NSS_MODE == "$mode" ]] || return 1
    UBS24GC18_DETAIL_STAGE=final-guard-and-intent-witness
    mvc24gc5_guard_witness && mvc24gb2_lock_valid &&
      mvc24gc3_transition_records_valid && mvc24gc7_read_intent || return 1
    UBS24GC18_DETAIL_STAGE=complete
    UBS24GC18_DNS_FINGERPRINT=$first
    UBS24GC18_NM_FINGERPRINT=$nm_before
    UBS24GC18_ROUTE_FINGERPRINT=$route_before
    UBS24GC18_NSS_MODE=$mode
    UBS24GC18_STAGE=precommit-dns-and-c1-quarantine-observed-no-authority
    UBS24GC18_AUTHORITY=none
}

# Called after C13 intent is sealed; a failure leaves its uncertain-attempt
# record behind even if nft has not run. NO retries or disarm on failure.
mvc24gc18_recheck_locked() {
    (( $# == 0 )) || return 1
    UBS24GC18_RECHECK_FAILURE=none
    UBS24GC18_OBS_NM_FINGERPRINT=
    UBS24GC18_OBS_ROUTE_FINGERPRINT=
    UBS24GC18_OBS_DNS_FINGERPRINT=
    UBS24GC18_OBS_NSS_MODE=
    UBS24GC18_DNS_CAPTURE_DETAIL=

    UBS24GC18_DETAIL_STAGE=recheck-contract
    if [[ ${UBS24GC18_STAGE:-} != precommit-dns-and-c1-quarantine-observed-no-authority ||
          ${UBS24GC18_AUTHORITY:-} != none ||
          -z ${UBS24GC18_DNS_FINGERPRINT:-} ||
          -z ${UBS24GC18_NM_FINGERPRINT:-} ||
          -z ${UBS24GC18_ROUTE_FINGERPRINT:-} ]]; then
        UBS24GC18_RECHECK_FAILURE=contract
        return 1
    fi

    UBS24GC18_DETAIL_STAGE=recheck-controller-guard-intent-witness
    if ! mvc24gb2_root_scope || ! mvc24gb2_lock_valid ||
       ! mvc24gc3_transition_records_valid || ! mvc24gc7_read_intent ||
       ! mvc24gc13_intent_valid || ! mvc24gc5_guard_witness; then
        UBS24GC18_RECHECK_FAILURE=controller-guard-intent-witness
        return 1
    fi

    UBS24GC18_DETAIL_STAGE=recheck-snapshot
    if ! mvc24gc18_snapshot; then
        UBS24GC18_RECHECK_FAILURE=snapshot-capture
        return 1
    fi
    UBS24GC18_OBS_NM_FINGERPRINT=$UBS24GC18_NM_NOW
    UBS24GC18_OBS_ROUTE_FINGERPRINT=$UBS24GC18_ROUTE_NOW

    UBS24GC18_DETAIL_STAGE=recheck-snapshot-stability
    if [[ $UBS24GC18_NM_NOW != "$UBS24GC18_NM_FINGERPRINT" ||
          $UBS24GC18_ROUTE_NOW != "$UBS24GC18_ROUTE_FINGERPRINT" ]]; then
        UBS24GC18_RECHECK_FAILURE=nm-or-route-fingerprint-drift
        return 1
    fi

    UBS24GC18_DETAIL_STAGE=recheck-dns-capture
    if ! mvc24gc16_dns_capture; then
        UBS24GC18_DNS_CAPTURE_DETAIL=${UBS24AG2D_DETAIL_STAGE:-${UBS24GC16_DNS_DETAIL_STAGE:-unknown}}
        UBS24GC18_RECHECK_FAILURE=dns-capture
        return 1
    fi
    UBS24GC18_OBS_DNS_FINGERPRINT=${UBS24AG2D_CAPTURE:-}
    UBS24GC18_OBS_NSS_MODE=${UBS24AG2D_NSS_MODE:-}
    UBS24GC18_DNS_CAPTURE_DETAIL=${UBS24AG2D_DETAIL_STAGE:-${UBS24GC16_DNS_DETAIL_STAGE:-unknown}}

    UBS24GC18_DETAIL_STAGE=recheck-dns-stability
    if [[ -z ${UBS24AG2D_CAPTURE:-} ||
          $UBS24AG2D_CAPTURE != "$UBS24GC18_DNS_FINGERPRINT" ||
          $UBS24AG2D_NSS_MODE != "$UBS24GC18_NSS_MODE" ]]; then
        UBS24GC18_RECHECK_FAILURE=dns-fingerprint-or-mode-drift
        return 1
    fi

    UBS24GC18_DETAIL_STAGE=recheck-final-witness
    if ! mvc24gc5_guard_witness || ! mvc24gc13_intent_valid ||
       ! mvc24gb2_lock_valid; then
        UBS24GC18_RECHECK_FAILURE=final-witness
        return 1
    fi
    UBS24GC18_DETAIL_STAGE=recheck-complete
    UBS24GC18_STAGE=precommit-dns-rechecked-under-c1-no-authority
}
