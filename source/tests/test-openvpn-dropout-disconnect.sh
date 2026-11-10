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

# 1. The new reconciliation context grants no authority by itself and accepts
# only the explicit disconnect stage after the public coordinator has granted
# process-local disconnect authority.
mvc24pubr_reset; mvc24pubd_reset; mvc24gco_reset
mvc24gb2_root_scope(){ return 0; }; mvc24gb2_lock_valid(){ return 0; }
MVC24GCO_STAGE=protected-openvpn-absent-reconciliation
MVC24PUBD_OPERATION=disconnect
MVC24PUBD_APPROVAL=approved-process-local
MVC24PUBD_AUTHORITY=public-explicit-disconnect
MVC24PUBD_STAGE=reconciling-openvpn-dropout-wireguard
mvc24pubr_context_witness && pass openvpn-dropout-reconciler-is-exact-disconnect-authority-bound || fail context-witness
MVC24PUBD_STAGE=idle
! mvc24pubr_context_witness && pass openvpn-dropout-reconciler-rejects-out-of-stage-use || fail context-stage-bound

# 2. The OpenVPN-absent observer accepts only an owned inactive clone with no
# active VPN/tun/ppp carrier; the exact authenticated WG survivor is allowed.
MVC24PUBD_STAGE=observing-openvpn-dropout
MVC24PUBD_SESSION_MODE=combined
MVC24PUBD_WG_TEMP_UUID=44444444-4444-4444-8444-444444444444
MVC24GC7_SOURCE_UUID=11111111-1111-4111-8111-111111111111
MVC24GC7_CLONE_UUID=22222222-2222-4222-8222-222222222222
MVC24GC7_NM_OWNER=':1.7|100|0'
mvc24pub_disconnect_admission_witness(){ return 0; }
mvc24gc23t_clone_present(){ [[ $1 == "$MVC24GC7_CLONE_UUID" ]]; }
OBS_MODE=wg-only
nmcli(){
    if [[ $* == *'UUID,TYPE,NAME,DEVICE connection show --active'* ]]; then
        case $OBS_MODE in
          wg-only) printf '%s:wireguard:vpnks-wg:vpnks-wg\n' "$MVC24PUBD_WG_TEMP_UUID" ;;
          foreign-vpn) printf 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:vpn:foreign:eth0\n' ;;
          none) : ;;
        esac
        return 0
    fi
    return 1
}
ip(){ [[ $OBS_MODE == tun-present ]] && [[ $* == 'link show dev tun-vpnks' ]]; }
pgrep(){ [[ $OBS_MODE == openvpn-process ]] && [[ ${1:-} == -x && ${2:-} == openvpn ]]; }
mvc24pubd_openvpn_absent_observed && pass exact-wg-survivor-with-openvpn-absent-is-observed || fail absent-observer-positive
OBS_MODE=foreign-vpn
! mvc24pubd_openvpn_absent_observed && pass foreign-active-vpn-blocks-dropout-reconciliation || fail foreign-vpn-rejected
OBS_MODE=openvpn-process
! mvc24pubd_openvpn_absent_observed && pass surviving-openvpn-process-blocks-absence-classification || fail openvpn-process-rejected

# 3. Exact incident primitive: active authenticated WG + parallel guard +
# missing proto-186 route is normalized to C11 + full private holds without
# treating route absence as ambiguous.
STATE_NM=active; STATE_KERNEL=active; STATE_ROUTE=absent; STATE_KEY=owned; STATE_HOLD=absent; STATE_GUARD=parallel
mvc24pubr_context_witness(){ return 0; }
mvc24pubr_inventory_all(){
    MVC24PUBR_NM_STATUS=$STATE_NM; MVC24PUBR_KERNEL_STATUS=$STATE_KERNEL
    MVC24PUBR_ROUTE_STATUS=$STATE_ROUTE; MVC24PUBR_KEYFILE_STATUS=$STATE_KEY
    MVC24PUBR_HOLD_STATUS=$STATE_HOLD; MVC24PUBR_GUARD_STATUS=$STATE_GUARD
}
mvc24pubr_ensure_hold_routes(){ STATE_HOLD=full; MVC24PUBR_HOLD_STATUS=full; }
mvc24pubr_disconnect_wg_dropout_if_active(){
    [[ $STATE_NM == active && $STATE_GUARD == parallel && $STATE_ROUTE == absent ]] || return 1
    STATE_NM=down; STATE_KERNEL=absent
}
mvc24pubr_route_inventory(){ MVC24PUBR_ROUTE_STATUS=$STATE_ROUTE; }
mvc24pubr_guard_inventory(){ MVC24PUBR_GUARD_STATUS=$STATE_GUARD; }
mvc24gd4_restore_openvpn_guard(){ [[ $STATE_GUARD == parallel ]] || return 1; STATE_GUARD=c11; }
mvc24pubr_remove_endpoint_route_if_owned(){ [[ $STATE_ROUTE == absent ]]; }
mvc24pubr_remove_profile_if_owned(){ STATE_NM=absent; STATE_KERNEL=absent; STATE_KEY=absent; }
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_absent &&
  [[ $STATE_NM == absent && $STATE_KERNEL == absent && $STATE_ROUTE == absent && $STATE_KEY == absent &&
     $STATE_HOLD == full && $STATE_GUARD == c11 &&
     $MVC24GD4_STAGE == wireguard-residue-removed-openvpn-absent-c11-private-hold ]] &&
  pass route-lost-wg-survivor-reconciles-to-c11-private-hold || fail route-lost-reconciliation

# 4. Alternative C19 journal is truthful and hash-binds the still-live public
# marker. Tampering that marker invalidates the intent.
rm -rf /run/mvc-disconnect /run/mvc-public-session /run/mvc-controller /run/mvc-output-transition
mkdir -m 700 /run/mvc-public-session /run/mvc-controller /run/mvc-output-transition
printf 'marker\n' > /run/mvc-public-session/active; chmod 400 /run/mvc-public-session/active
printf 'c1\n' > /run/mvc-controller/transition-attempt; chmod 400 /run/mvc-controller/transition-attempt
printf 'c13\n' > /run/mvc-output-transition/attempt; chmod 400 /run/mvc-output-transition/attempt
B=$(mktemp /dev/shm/c24a-batch.XXXXXX); chmod 600 "$B"; printf 'batch\n' > "$B"
MVC24GC7_CLONE_UUID=22222222-2222-4222-8222-222222222222
MVC24GC7_NM_OWNER=':1.7|100|0'
mvc24gb2_root_scope(){ return 0; }; mvc24gb2_lock_valid(){ return 0; }
mvc24gc3_transition_records_valid(){ return 0; }; mvc24gc13_intent_valid(){ return 0; }
# Container /run is overlayfs; emulate only the production tmpfs host fact.
eval "$(declare -f stat | sed '1s/^stat /c24a_old_stat /')" 2>/dev/null || true
stat(){ if [[ $# -eq 4 && $1 == -f && $2 == -c && $3 == %T && $4 == /run ]]; then printf 'tmpfs\n'; else command stat "$@"; fi; }
mvc24gc19_publish_absent_intent "$B" active && mvc24gc19_intent_valid && pass truthful-openvpn-absent-c19-intent-publishes-and-validates || fail absent-intent-valid
printf 'tamper\n' >> /run/mvc-public-session/active
! mvc24gc19_intent_valid && pass c19-absent-intent-rejects-public-marker-tamper || fail absent-intent-tamper
rm -f "$B"; rm -rf /run/mvc-disconnect /run/mvc-public-session /run/mvc-controller /run/mvc-output-transition

# 5. Public coordinator ordering for exact dropout path, including normal final
# same-boot-ready state. All lifecycle stages below are substituted only to
# prove orchestration; primitive behavior is covered above.
source lib/combined-operational-public-disconnect.sh
LOG=()
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset; mvc24gc19_reset
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; MVC24PUBD_TRANSACTION_STATE=none; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-live); return 1; }
mvc24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
mvc24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_absent(){ LOG+=(wg-reconcile); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-absent-c11-private-hold; return 0; }
mvc24pubd_adopt_openvpn_absence_to_c1(){ LOG+=(ovpn-adopt); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GCO_STAGE=completed-session-archived-sameboot-ready; MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once || fail coordinator-dropout-success
[[ ${LOG[*]} == 'marker lock ovpn-live ovpn-id ovpn-absent wg-id wg-reconcile ovpn-adopt hold-release complete marker-finalize' &&
   $MVC24PUBD_STAGE == public-dual-session-complete-sameboot-ready &&
   $MVC24PUBD_AUTHORITY == none && $MVC24PUBD_APPROVAL == consumed ]] &&
  pass coordinator-completes-dropout-to-normal-sameboot-ready-state || fail coordinator-order

printf 'Results: %d passed, 0 failed\n' "$P"
