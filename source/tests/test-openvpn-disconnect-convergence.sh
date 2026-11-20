#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export MVC24E_CODE_ROOT=$PWD
source lib/combined-operational-public-composition.sh
P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# 1. Identity-bound active OpenVPN classification does not require the old
# route/DNS/tunnel readiness snapshot. Exact clone + optional MVC tun is enough
# to admit cleanup; unrelated managed VPN state is not.
mvc24pubd_reset
MVC24PUBD_OPERATION=disconnect
MVC24PUBD_APPROVAL=approved-process-local
MVC24PUBD_AUTHORITY=public-explicit-disconnect
MVC24PUBD_STAGE=observing-openvpn-owned
MVC24PUBD_SESSION_MODE=openvpn-only
MVC24GC7_SOURCE_UUID=11111111-1111-4111-8111-111111111111
MVC24GC7_CLONE_UUID=22222222-2222-4222-8222-222222222222
MVC24GC7_NM_OWNER=':1.7|100|0'
mvc24gb2_root_scope(){ return 0; }; mvc24gb2_lock_valid(){ return 0; }
mvc24gc23t_clone_present(){ [[ $1 == "$MVC24GC7_CLONE_UUID" ]]; }
OBS=owned
nmcli(){
    if [[ $* == *'UUID,TYPE,NAME,DEVICE connection show --active'* ]]; then
        case $OBS in
          owned) printf '%s:vpn:vpnks-ovpn:\ncccccccc-cccc-4ccc-8ccc-cccccccccccc:tun:tun-vpnks:tun-vpnks\n' "$MVC24GC7_CLONE_UUID" ;;
          foreign) printf '%s:vpn:vpnks-ovpn:\naaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:vpn:foreign:\n' "$MVC24GC7_CLONE_UUID" ;;
          inactive-tun) printf 'cccccccc-cccc-4ccc-8ccc-cccccccccccc:tun:tun-vpnks:tun-vpnks\n' ;;
        esac
        return 0
    fi
    return 1
}
mvc24pubd_openvpn_owned_active_observed && pass owned-active-openvpn-admitted-without-healthy-route-dns-shape || fail owned-active-observer
OBS=foreign
! mvc24pubd_openvpn_owned_active_observed && pass foreign-managed-vpn-blocks-openvpn-convergence || fail foreign-vpn-not-blocked
OBS=inactive-tun
! mvc24pubd_openvpn_owned_active_observed && pass tun-without-owned-active-clone-is-ambiguous || fail inactive-tun-not-blocked

# 2. Combined mode may still have only the exact authenticated MVC WG survivor
# while classifying OpenVPN before WG-first convergence.
OBS=combined
MVC24PUBD_SESSION_MODE=combined
MVC24PUBD_WG_TEMP_UUID=44444444-4444-4444-8444-444444444444
nmcli(){
    if [[ $* == *'UUID,TYPE,NAME,DEVICE connection show --active'* ]]; then
        printf '%s:vpn:vpnks-ovpn:\n' "$MVC24GC7_CLONE_UUID"
        printf '%s:wireguard:vpnks-wg:vpnks-wg\n' "$MVC24PUBD_WG_TEMP_UUID"
        return 0
    fi
    return 1
}
mvc24pubd_openvpn_owned_active_observed && pass exact-combined-wg-survivor-is-allowed-before-openvpn-stop || fail combined-wg-observer

# 3. The new D4 convergence helper deliberately ignores OpenVPN route health.
# It converges exact authenticated WG residue to C11 + private holds.
STATE_NM=active; STATE_KERNEL=active; STATE_ROUTE=absent; STATE_KEY=owned; STATE_HOLD=absent; STATE_GUARD=parallel
mvc24pubr_context_witness(){ return 0; }
mvc24pubr_inventory_all(){
    MVC24PUBR_NM_STATUS=$STATE_NM; MVC24PUBR_KERNEL_STATUS=$STATE_KERNEL
    MVC24PUBR_ROUTE_STATUS=$STATE_ROUTE; MVC24PUBR_KEYFILE_STATUS=$STATE_KEY
    MVC24PUBR_HOLD_STATUS=$STATE_HOLD; MVC24PUBR_GUARD_STATUS=$STATE_GUARD
}
mvc24pubr_ensure_hold_routes(){ STATE_HOLD=full; MVC24PUBR_HOLD_STATUS=full; }
mvc24pubr_disconnect_wg_dropout_if_active(){ STATE_NM=down; STATE_KERNEL=absent; }
mvc24pubr_route_inventory(){ MVC24PUBR_ROUTE_STATUS=$STATE_ROUTE; }
mvc24pubr_guard_inventory(){ MVC24PUBR_GUARD_STATUS=$STATE_GUARD; }
mvc24gd4_restore_openvpn_guard(){ STATE_GUARD=c11; }
mvc24pubr_remove_endpoint_route_if_owned(){ STATE_ROUTE=absent; }
mvc24pubr_remove_profile_if_owned(){ STATE_NM=absent; STATE_KERNEL=absent; STATE_KEY=absent; }
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_convergence &&
  [[ $STATE_NM == absent && $STATE_KERNEL == absent && $STATE_ROUTE == absent && $STATE_KEY == absent &&
     $STATE_HOLD == full && $STATE_GUARD == c11 &&
     $MVC24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] &&
  pass degraded-openvpn-does-not-block-wireguard-first-convergence || fail wg-convergence

# 4. Public coordinator: degraded OpenVPN-only state is not revalidated through
# C15/C16. It is classified by exact ownership, stopped through the convergent
# C19 path, then finalized normally.
source lib/combined-operational-public-disconnect.sh
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gc19_reset; mvc24gd4_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=transaction; MVC24PUBD_TRANSACTION_STATE=openvpn-protected; MVC24PUBD_SESSION_MODE=openvpn-only; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ return 1; }
mvc24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
mvc24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent-probe); return 1; }
mvc24pubd_openvpn_owned_active_observed(){ LOG+=(ovpn-owned); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-nominal-probe); return 1; }
mvc24pubd_warn(){ LOG+=(warn); return 0; }
mvc24pubd_stop_openvpn_convergent(){ LOG+=(ovpn-stop-converge); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GCO_STAGE=completed-session-archived-sameboot-ready; MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_transaction(){ LOG+=(tx-finalize); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once || fail coordinator-degraded-openvpn-only
[[ ${LOG[*]} == 'marker lock ovpn-id ovpn-absent-probe ovpn-owned ovpn-nominal-probe warn ovpn-stop-converge complete tx-finalize' &&
   $MVC24PUBD_STAGE == public-openvpn-session-complete-sameboot-ready ]] &&
  pass coordinator-converges-degraded-openvpn-only || fail coordinator-openvpn-only-order

# 5. Combined degraded OpenVPN state converges WG first, then the exact OpenVPN
# clone, then private holds. No healthy OpenVPN reobservation is required.
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gc19_reset; mvc24gd4_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_TRANSACTION_STATE=none; MVC24PUBD_SESSION_MODE=combined; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ return 1; }
mvc24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
mvc24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent-probe); return 1; }
mvc24pubd_openvpn_owned_active_observed(){ LOG+=(ovpn-owned); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-nominal-probe); return 1; }
mvc24pubd_warn(){ LOG+=(warn); return 0; }
mvc24pub_wireguard_runtime_root(){ printf '%s\n' /run/mvc-wireguard; }
mvc24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_convergence(){ LOG+=(wg-converge); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_stop_openvpn_convergent(){ LOG+=(ovpn-stop-converge); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GCO_STAGE=completed-session-archived-sameboot-ready; MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
mkdir -p /run/mvc-wireguard
mvc24pubd_disconnect_once || fail coordinator-degraded-combined
rm -rf /run/mvc-wireguard
[[ ${LOG[*]} == 'marker lock ovpn-id ovpn-absent-probe ovpn-owned ovpn-nominal-probe warn wg-id wg-converge ovpn-stop-converge hold-release complete marker-finalize' &&
   $MVC24PUBD_STAGE == public-dual-session-complete-sameboot-ready ]] &&
  pass coordinator-converges-wg-before-degraded-openvpn || fail coordinator-combined-order

# 6. Existing fully absent OpenVPN path remains the truthful absent-intent path;
# it must not call the new active-clone stop.
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gc19_reset; mvc24gd4_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=transaction; MVC24PUBD_TRANSACTION_STATE=openvpn-protected; MVC24PUBD_SESSION_MODE=openvpn-only; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ return 1; }
mvc24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
mvc24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent); return 0; }
mvc24pubd_adopt_openvpn_absence_to_c1(){ LOG+=(ovpn-adopt); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24pubd_stop_openvpn_convergent(){ LOG+=(unexpected-active-stop); return 1; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GCO_STAGE=completed-session-archived-sameboot-ready; MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_transaction(){ LOG+=(tx-finalize); return 0; }
mvc24pubd_disconnect_once || fail coordinator-absent-regression
[[ ${LOG[*]} == 'marker lock ovpn-id ovpn-absent ovpn-adopt complete tx-finalize' ]] &&
  pass absent-openvpn-still-uses-truthful-absence-path || fail absent-path-regressed

printf 'Results: %d passed, 0 failed\n' "$P"
