#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export MVC24E_CODE_ROOT=$PWD
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
    mvc24pubr_inventory_all(){ LOG+=(inventory); MVC24PUBR_GUARD_STATUS=$cur_guard; MVC24PUBR_NM_STATUS=$cur_nm; MVC24PUBR_ROUTE_STATUS=$cur_route; MVC24PUBR_KEYFILE_STATUS=$cur_key; MVC24PUBR_HOLD_STATUS=absent; return 0; }
    mvc24pubr_ensure_hold_routes(){ LOG+=(holds); MVC24PUBR_HOLD_STATUS=full; return 0; }
    mvc24pubr_disconnect_wg_if_active(){ LOG+=(wg-down); cur_nm=down; MVC24PUBR_NM_STATUS=down; return 0; }
    mvc24pubr_route_inventory(){ LOG+=(route-observe); MVC24PUBR_ROUTE_STATUS=$cur_route; return 0; }
    mvc24pubr_guard_inventory(){ LOG+=(guard-observe); MVC24PUBR_GUARD_STATUS=$cur_guard; return 0; }
    mvc24gd4_restore_openvpn_guard(){ LOG+=(restore-c11); cur_guard=c11; MVC24GD4_STAGE=pure-openvpn-guard-restored-route-profile-remain-private-hold; return 0; }
    mvc24pubr_remove_endpoint_route_if_owned(){ LOG+=(route-remove); cur_route=absent; MVC24PUBR_ROUTE_STATUS=absent; return 0; }
    mvc24pubr_remove_profile_if_owned(){ LOG+=(profile-remove); cur_nm=absent; cur_key=absent; return 0; }
    mvc24gd4_finish_teardown(){ LOG+=(finish-d4); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
    mvc24pubr_reconcile_partial_d4_to_openvpn_hold
}

run_reconcile_case c11 absent absent absent && pass intent-only-partial-reconcile-succeeds || fail intent-only-partial-reconcile-succeeds
[[ ${LOG[*]} == 'inventory holds wg-down route-observe guard-observe route-remove profile-remove finish-d4' ]] && pass intent-only-partial-reconcile-order || fail intent-only-partial-reconcile-order
[[ $MVC24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] && pass intent-only-normalizes-to-d4-handoff || fail intent-only-normalizes-to-d4-handoff

run_reconcile_case parallel active owned owned && pass active-partial-reconcile-succeeds || fail active-partial-reconcile-succeeds
[[ ${LOG[*]} == 'inventory holds wg-down route-observe guard-observe restore-c11 route-remove profile-remove finish-d4' ]] && pass active-partial-reconcile-order || fail active-partial-reconcile-order
[[ $MVC24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] && pass active-partial-normalizes-to-d4-handoff || fail active-partial-normalizes-to-d4-handoff

# Impossible active WG with C11 must fail before any cleanup mutation.
LOG=()
mvc24pubr_context_witness(){ LOG+=(authority); return 0; }
mvc24pubr_inventory_all(){ LOG+=(inventory); MVC24PUBR_GUARD_STATUS=c11; MVC24PUBR_NM_STATUS=active; MVC24PUBR_ROUTE_STATUS=owned; MVC24PUBR_KEYFILE_STATUS=owned; MVC24PUBR_HOLD_STATUS=absent; return 0; }
mvc24pubr_ensure_hold_routes(){ LOG+=(holds); return 0; }
! mvc24pubr_reconcile_partial_d4_to_openvpn_hold && pass impossible-active-c11-refused || fail impossible-active-c11-refused
[[ ${LOG[*]} == 'inventory' ]] && pass impossible-active-c11-no-mutation || fail impossible-active-c11-no-mutation

# CONNECT must route a post-intent D4 failure through partial reconciliation
# rather than strand it as an unsupported residue state.
T=$(mktemp -d /tmp/mvc-c23bd.XXXXXXXX)
trap 'rm -rf -- "$T"' EXIT
TEST_D4_RUNTIME=$T/wg
mvc24pub_wireguard_runtime_root(){ printf '%s\n' "$TEST_D4_RUNTIME"; }
mvc24pubc_reset; mvc24gco_reset; mvc24gd4_reset
LOG=()
mvc24pubc_preflight_readonly(){ LOG+=(preflight); MVC24PUBC_OVPN_UUID=11111111-1111-4111-8111-111111111111; MVC24PUBC_WG_UUID=22222222-2222-4222-8222-222222222222; MVC24PUBC_TEMP_UUID=33333333-3333-4333-8333-333333333333; MVC24PUBC_UNDERLAY=f15ra; MVC24PUBC_NM_OWNER=':1.2|123|0'; return 0; }
mvc24pubc_transaction_write(){ LOG+=("tx-$1"); MVC24PUBC_TRANSACTION_STATE=$1; return 0; }
mvc24gco_enable_public_live(){ LOG+=(enable); MVC24GCO_MODE=public-live-explicit-command; MVC24GCO_AUTHORITY=public-explicit-connect; return 0; }
mvc24gco_start_once(){ LOG+=(ovpn-start); MVC24GCO_STAGE=protected-openvpn-observed; MVC24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority; return 0; }
# C23BF Stage 7: this test deliberately stubs the whole OpenVPN vertical, so it
# also bypasses A1's real preclone-intent hooks. Preclone retirement is covered
# by the Stage-7 real-public hermetic suite; keep this older test scoped to D4.
mvc24pubc_retire_preclone_intent_after_c7(){ return 0; }
mvc24gd4_start_once(){ LOG+=(wg-start); mkdir -p "$TEST_D4_RUNTIME"; MVC24GD4_STAGE=parallel-guard-commit-outcome-uncertain; return 1; }
mvc24pubc_cleanup_partial_d4_once(){ LOG+=(partial-cleanup); return 0; }
mvc24pubc_consume_authority(){ LOG+=(consume); MVC24PUBC_AUTHORITY=none; MVC24PUBC_APPROVAL=consumed; return 0; }
! mvc24pubc_connect_once wg ovpn && pass connect-post-intent-failure-rejected-after-cleanup || fail connect-post-intent-failure-rejected-after-cleanup
[[ ${LOG[*]} == 'preflight tx-prepared-before-mutation enable ovpn-start tx-openvpn-protected wg-start partial-cleanup consume' ]] && pass connect-post-intent-failure-cleanup-order || fail connect-post-intent-failure-cleanup-order
[[ $MVC24PUBC_STAGE == wireguard-start-failed-parallel-guard-commit-outcome-uncertain-auto-cleaned-partial-d4-baseline ]] && pass connect-post-intent-reports-auto-cleaned || fail connect-post-intent-reports-auto-cleaned
rm -rf -- "$TEST_D4_RUNTIME"

# Fresh DISCONNECT must likewise reconcile an authenticated openvpn-protected
# transaction when the D4 runtime exists, then use the normal C19/C23T path.
mkdir -p "$TEST_D4_RUNTIME"
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=transaction; MVC24PUBD_TRANSACTION_STATE=openvpn-protected; MVC24PUBD_OVPN_SOURCE_UUID=11111111-1111-4111-8111-111111111111; MVC24PUBD_OVPN_CLONE_UUID=22222222-2222-4222-8222-222222222222; MVC24PUBD_WG_SOURCE_UUID=33333333-3333-4333-8333-333333333333; MVC24PUBD_WG_TEMP_UUID=44444444-4444-4444-8444-444444444444; MVC24PUBD_UNDERLAY=f15ra; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(rehydrate-ovpn); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(rehydrate-wg); return 0; }
mvc24pubr_reconcile_partial_d4_to_openvpn_hold(){ LOG+=(partial-reconcile); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_reobserve_openvpn_after_wg(){ LOG+=(observe-ovpn); return 0; }
mvc24gco_stop_once(){ LOG+=(stop-ovpn); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(release-holds); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; MVC24GCO_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_transaction(){ LOG+=(finalize); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once && pass fresh-disconnect-partial-d4-succeeds || fail fresh-disconnect-partial-d4-succeeds
[[ ${LOG[*]} == 'marker lock rehydrate-ovpn rehydrate-wg partial-reconcile observe-ovpn stop-ovpn release-holds complete finalize' ]] && pass fresh-disconnect-partial-d4-order || fail fresh-disconnect-partial-d4-order
[[ $MVC24PUBD_STAGE == public-openvpn-partial-session-complete-sameboot-ready ]] && pass fresh-disconnect-partial-d4-final-state || fail fresh-disconnect-partial-d4-final-state



# R4-pinned core identities after non-persistent literal cleanup.
[[ $(sha256sum lib/combined-operational-d4-wireguard-parallel-live.sh | awk '{print $1}') == fd2e61c0b0433a96040fcc95719d4a90dcadef17986586a919e16ae60fae17e9 ]] && pass r5c-d4-source-identity || fail r5c-d4-source-identity
[[ $(sha256sum lib/combined-operational-openvpn-composition.sh | awk '{print $1}') == 56ef654e061368fa16bd2ec69153ffb6710ef447fe3a1ede3231ae8b2e5d2ee4 ]] && pass r4-gco-source-identity || fail r4-gco-source-identity
[[ $(sha256sum lib/combined-operational-c19-protected-openvpn-stop.sh | awk '{print $1}') == d768cf016faf50abbcce2ade7f5b340fe2ec9d3f71f1660ea3927f464e3321c5 ]] && pass r5d-c19-source-identity || fail r5d-c19-source-identity

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
