#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export UBS24E_CODE_ROOT=$PWD
source lib/combined-operational-public-v240-composition.sh

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; ((++P)); }
fail(){ printf 'FAIL: %s\n' "$1"; ((++F)); }

# The shared reconciler is production-loaded but grants no authority itself.
declare -F mvc24pubr_reconcile_partial_d4_to_openvpn_hold >/dev/null && pass reconciler-loaded || fail reconciler-loaded
[[ $(mvc24pub_wireguard_runtime_root) == /run/mvc-wireguard ]] && pass fixed-production-d4-runtime-root || fail fixed-production-d4-runtime-root

# Exercise the real reconciliation coordinator while substituting only its
# independently-tested inventory/mutation leaves. This verifies normalization
# ordering for both early-C11 residue and post-guard/active-WG residue.
run_reconcile_case(){
    local initial_guard=$1 initial_nm=$2 initial_route=$3 initial_key=$4
    LOG=()
    cur_guard=$initial_guard cur_nm=$initial_nm cur_route=$initial_route cur_key=$initial_key
    mvc24pubr_context_witness(){ LOG+=(authority); return 0; }
    mvc24pubr_inventory_all(){ LOG+=(inventory); UBS24PUBR_GUARD_STATUS=$cur_guard; UBS24PUBR_NM_STATUS=$cur_nm; UBS24PUBR_ROUTE_STATUS=$cur_route; UBS24PUBR_KEYFILE_STATUS=$cur_key; UBS24PUBR_HOLD_STATUS=absent; return 0; }
    mvc24pubr_ensure_hold_routes(){ LOG+=(holds); UBS24PUBR_HOLD_STATUS=full; return 0; }
    mvc24pubr_disconnect_wg_if_active(){ LOG+=(wg-down); cur_nm=down; UBS24PUBR_NM_STATUS=down; return 0; }
    mvc24pubr_route_inventory(){ LOG+=(route-observe); UBS24PUBR_ROUTE_STATUS=$cur_route; return 0; }
    mvc24pubr_guard_inventory(){ LOG+=(guard-observe); UBS24PUBR_GUARD_STATUS=$cur_guard; return 0; }
    mvc24gd4_restore_openvpn_guard(){ LOG+=(restore-c11); cur_guard=c11; UBS24GD4_STAGE=pure-openvpn-guard-restored-route-profile-remain-private-hold; return 0; }
    mvc24pubr_remove_endpoint_route_if_owned(){ LOG+=(route-remove); cur_route=absent; UBS24PUBR_ROUTE_STATUS=absent; return 0; }
    mvc24pubr_remove_profile_if_owned(){ LOG+=(profile-remove); cur_nm=absent; cur_key=absent; return 0; }
    mvc24gd4_finish_teardown(){ LOG+=(finish-d4); UBS24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
    mvc24pubr_reconcile_partial_d4_to_openvpn_hold
}

run_reconcile_case c11 absent absent absent && pass intent-only-partial-reconcile-succeeds || fail intent-only-partial-reconcile-succeeds
[[ ${LOG[*]} == 'inventory holds wg-down route-observe guard-observe route-remove profile-remove finish-d4' ]] && pass intent-only-partial-reconcile-order || fail intent-only-partial-reconcile-order
[[ $UBS24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] && pass intent-only-normalizes-to-d4-handoff || fail intent-only-normalizes-to-d4-handoff

run_reconcile_case parallel active owned owned && pass active-partial-reconcile-succeeds || fail active-partial-reconcile-succeeds
[[ ${LOG[*]} == 'inventory holds wg-down route-observe guard-observe restore-c11 route-remove profile-remove finish-d4' ]] && pass active-partial-reconcile-order || fail active-partial-reconcile-order
[[ $UBS24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] && pass active-partial-normalizes-to-d4-handoff || fail active-partial-normalizes-to-d4-handoff

# Impossible active WG with C11 must fail before any cleanup mutation.
LOG=()
mvc24pubr_context_witness(){ LOG+=(authority); return 0; }
mvc24pubr_inventory_all(){ LOG+=(inventory); UBS24PUBR_GUARD_STATUS=c11; UBS24PUBR_NM_STATUS=active; UBS24PUBR_ROUTE_STATUS=owned; UBS24PUBR_KEYFILE_STATUS=owned; UBS24PUBR_HOLD_STATUS=absent; return 0; }
mvc24pubr_ensure_hold_routes(){ LOG+=(holds); return 0; }
! mvc24pubr_reconcile_partial_d4_to_openvpn_hold && pass impossible-active-c11-refused || fail impossible-active-c11-refused
[[ ${LOG[*]} == 'inventory' ]] && pass impossible-active-c11-no-mutation || fail impossible-active-c11-no-mutation

# CONNECT must route a post-intent D4 failure through partial reconciliation
# rather than strand it as an unsupported residue state.
T=$(mktemp -d /tmp/ubs-c23bd.XXXXXXXX)
trap 'rm -rf -- "$T"' EXIT
TEST_D4_RUNTIME=$T/wg
mvc24pub_wireguard_runtime_root(){ printf '%s\n' "$TEST_D4_RUNTIME"; }
mvc24pubc_reset; mvc24gco_reset; mvc24gd4_reset
LOG=()
mvc24pubc_preflight_readonly(){ LOG+=(preflight); UBS24PUBC_OVPN_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBC_WG_UUID=22222222-2222-4222-8222-222222222222; UBS24PUBC_TEMP_UUID=33333333-3333-4333-8333-333333333333; UBS24PUBC_UNDERLAY=f15ra; UBS24PUBC_NM_OWNER=':1.2|123|0'; return 0; }
mvc24pubc_transaction_write(){ LOG+=("tx-$1"); UBS24PUBC_TRANSACTION_STATE=$1; return 0; }
mvc24gco_enable_public_live(){ LOG+=(enable); UBS24GCO_MODE=public-live-explicit-command; UBS24GCO_AUTHORITY=public-explicit-connect; return 0; }
mvc24gco_start_once(){ LOG+=(ovpn-start); UBS24GCO_STAGE=protected-openvpn-observed; UBS24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority; return 0; }
# C23BF Stage 7: this test deliberately stubs the whole OpenVPN vertical, so it
# also bypasses A1's real preclone-intent hooks. Preclone retirement is covered
# by the Stage-7 real-public hermetic suite; keep this older test scoped to D4.
mvc24pubc_retire_preclone_intent_after_c7(){ return 0; }
mvc24gd4_start_once(){ LOG+=(wg-start); mkdir -p "$TEST_D4_RUNTIME"; UBS24GD4_STAGE=parallel-guard-commit-outcome-uncertain; return 1; }
mvc24pubc_cleanup_partial_d4_once(){ LOG+=(partial-cleanup); return 0; }
mvc24pubc_consume_authority(){ LOG+=(consume); UBS24PUBC_AUTHORITY=none; UBS24PUBC_APPROVAL=consumed; return 0; }
! mvc24pubc_connect_once wg ovpn && pass connect-post-intent-failure-rejected-after-cleanup || fail connect-post-intent-failure-rejected-after-cleanup
[[ ${LOG[*]} == 'preflight tx-prepared-before-mutation enable ovpn-start tx-openvpn-protected wg-start partial-cleanup consume' ]] && pass connect-post-intent-failure-cleanup-order || fail connect-post-intent-failure-cleanup-order
[[ $UBS24PUBC_STAGE == wireguard-start-failed-parallel-guard-commit-outcome-uncertain-auto-cleaned-partial-d4-baseline ]] && pass connect-post-intent-reports-auto-cleaned || fail connect-post-intent-reports-auto-cleaned
rm -rf -- "$TEST_D4_RUNTIME"

# Fresh DISCONNECT must likewise reconcile an authenticated openvpn-protected
# transaction when the D4 runtime exists, then use the normal C19/C23T path.
mkdir -p "$TEST_D4_RUNTIME"
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); UBS24PUBD_MARKER_KIND=transaction; UBS24PUBD_TRANSACTION_STATE=openvpn-protected; UBS24PUBD_OVPN_SOURCE_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBD_OVPN_CLONE_UUID=22222222-2222-4222-8222-222222222222; UBS24PUBD_WG_SOURCE_UUID=33333333-3333-4333-8333-333333333333; UBS24PUBD_WG_TEMP_UUID=44444444-4444-4444-8444-444444444444; UBS24PUBD_UNDERLAY=f15ra; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(rehydrate-ovpn); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(rehydrate-wg); return 0; }
mvc24pubr_reconcile_partial_d4_to_openvpn_hold(){ LOG+=(partial-reconcile); UBS24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_reobserve_openvpn_after_wg(){ LOG+=(observe-ovpn); return 0; }
mvc24gco_stop_once(){ LOG+=(stop-ovpn); UBS24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; UBS24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(release-holds); UBS24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); UBS24GC23T_STAGE=completed-session-archived-sameboot-ready; UBS24GCO_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_transaction(){ LOG+=(finalize); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once && pass fresh-disconnect-partial-d4-succeeds || fail fresh-disconnect-partial-d4-succeeds
[[ ${LOG[*]} == 'marker lock rehydrate-ovpn rehydrate-wg partial-reconcile observe-ovpn stop-ovpn release-holds complete finalize' ]] && pass fresh-disconnect-partial-d4-order || fail fresh-disconnect-partial-d4-order
[[ $UBS24PUBD_STAGE == public-openvpn-partial-session-complete-sameboot-ready ]] && pass fresh-disconnect-partial-d4-final-state || fail fresh-disconnect-partial-d4-final-state



# R3A-pinned core identities after the lowercase internal function rename.
[[ $(sha256sum lib/combined-operational-d4-wireguard-parallel-live.sh | awk '{print $1}') == e6ca95fad0e5e264e887b56db0f0773cca24f048148aa5854382425fea6b0f76 ]] && pass r3a-d4-source-identity || fail r3a-d4-source-identity
[[ $(sha256sum lib/combined-operational-openvpn-composition.sh | awk '{print $1}') == 22379db8691d473d5734d2c306e488494381baa28d85815c3a58e1d451dd944c ]] && pass r3a-gco-source-identity || fail r3a-gco-source-identity
[[ $(sha256sum lib/combined-operational-c19-protected-openvpn-stop.sh | awk '{print $1}') == 36b013813f36b17b285e982020d11b3159d4f1f5d38a8c515364a8f3f404904b ]] && pass r3a-c19-source-identity || fail r3a-c19-source-identity

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
