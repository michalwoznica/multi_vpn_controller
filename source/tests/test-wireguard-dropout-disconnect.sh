#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
export UBS24E_CODE_ROOT=$ROOT
source lib/combined-operational-public-v240-composition.sh

P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# 1. New context is bound to genuine explicit disconnect authority and exact
# published-WG-dropout stages; it grants no standalone authority.
ubs24pubr_reset
ubs24gb2_root_scope(){ return 0; }; ubs24gb2_lock_valid(){ return 0; }
ubs24pub_disconnect_admission_witness(){ return 0; }
UBS24GCO_STAGE=protected-openvpn-observed
UBS24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
UBS24PUBD_AUTHORITY=public-explicit-disconnect
UBS24PUBD_STAGE=observing-published-wireguard-dropout
ubs24pubr_context_witness && pass inverse-dropout-context-is-explicit-disconnect-bound || fail inverse-context
UBS24PUBD_AUTHORITY=none
! ubs24pubr_context_witness && pass inverse-dropout-context-rejects-missing-authority || fail inverse-context-authority
UBS24PUBD_AUTHORITY=public-explicit-disconnect

# 2. Classifier accepts only inactive/absent WG under exact parallel guard.
ubs24pubr_inventory_all(){
  UBS24PUBR_NM_STATUS=$STATE_NM
  UBS24PUBR_KERNEL_STATUS=$STATE_KERNEL
  UBS24PUBR_ROUTE_STATUS=$STATE_ROUTE
  UBS24PUBR_KEYFILE_STATUS=$STATE_KEY
  UBS24PUBR_HOLD_STATUS=$STATE_HOLD
  UBS24PUBR_GUARD_STATUS=$STATE_GUARD
}
STATE_NM=absent; STATE_KERNEL=absent; STATE_ROUTE=absent; STATE_KEY=absent; STATE_HOLD=absent; STATE_GUARD=parallel
ubs24pubr_published_wg_absent_observed && pass exact-published-wg-absence-is-observed || fail inverse-observer-positive
STATE_NM=active; STATE_KERNEL=active
! ubs24pubr_published_wg_absent_observed && pass active-wireguard-is-not-misclassified-as-dropout || fail inverse-observer-active
STATE_NM=absent; STATE_KERNEL=absent; STATE_GUARD=c11
! ubs24pubr_published_wg_absent_observed && pass nonparallel-guard-is-not-admitted-as-fresh-dropout || fail inverse-observer-guard

# 3. Exact already-absent WG + already-absent proto-186 route normalizes to
# C11 + private holds without needing a fake NM down.
STATE_NM=absent; STATE_KERNEL=absent; STATE_ROUTE=absent; STATE_KEY=absent; STATE_HOLD=absent; STATE_GUARD=parallel
ubs24pubr_ensure_hold_routes(){ STATE_HOLD=full; UBS24PUBR_HOLD_STATUS=full; }
ubs24pubr_route_inventory(){ UBS24PUBR_ROUTE_STATUS=$STATE_ROUTE; }
ubs24pubr_guard_inventory(){ UBS24PUBR_GUARD_STATUS=$STATE_GUARD; }
ubs24gd4_restore_openvpn_guard(){ [[ $STATE_GUARD == parallel ]] || return 1; STATE_GUARD=c11; }
ubs24pubr_remove_endpoint_route_if_owned(){ [[ $STATE_ROUTE == absent ]]; }
ubs24pubr_remove_profile_if_owned(){ [[ $STATE_NM == absent && $STATE_KERNEL == absent && $STATE_KEY == absent ]]; }
ubs24gd4_finish_teardown(){
  [[ $STATE_GUARD == c11 && $STATE_HOLD == full && $STATE_NM == absent && $STATE_KERNEL == absent && $STATE_ROUTE == absent && $STATE_KEY == absent ]] || return 1
  UBS24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold
}
ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold &&
  [[ $STATE_GUARD == c11 && $STATE_HOLD == full && $UBS24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] &&
  pass absent-wg-and-route-reconcile-to-normal-openvpn-hold || fail inverse-reconcile-absent

# 4. A down exact profile + owned endpoint route is also safely retired.
STATE_NM=down; STATE_KERNEL=absent; STATE_ROUTE=owned; STATE_KEY=owned; STATE_HOLD=absent; STATE_GUARD=parallel
ubs24pubr_remove_endpoint_route_if_owned(){ [[ $STATE_ROUTE == owned ]] || return 1; STATE_ROUTE=absent; }
ubs24pubr_remove_profile_if_owned(){ [[ $STATE_NM == down && $STATE_KEY == owned ]] || return 1; STATE_NM=absent; STATE_KEY=absent; }
ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold &&
  [[ $STATE_NM == absent && $STATE_ROUTE == absent && $STATE_KEY == absent && $STATE_GUARD == c11 && $STATE_HOLD == full ]] &&
  pass down-wg-profile-and-owned-route-are-retired || fail inverse-reconcile-owned

# 5. Public coordinator falls back only after exact dual-active reobservation
# fails, then completes through the existing OpenVPN stop/finalization path.
source lib/combined-operational-public-v240-disconnect.sh
LOG=()
ubs24pubd_reset; ubs24gco_reset; ubs24gd4_reset
ubs24pubd_parse_session_marker(){ LOG+=(marker); UBS24PUBD_MARKER_KIND=active; UBS24PUBD_SESSION_MODE=combined; UBS24PUBD_TRANSACTION_STATE=none; return 0; }
ubs24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
ubs24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-live); return 0; }
ubs24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
ubs24gd4_dual_active_observed(){ LOG+=(dual-observe); return 1; }
ubs24gd4_private_hold_routes_state(){ [[ $1 == absent ]]; }
ubs24pubr_published_wg_absent_observed(){ LOG+=(wg-absent); return 0; }
ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold(){ LOG+=(wg-reconcile); UBS24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
ubs24pubd_reobserve_openvpn_after_wg(){ LOG+=(ovpn-reobserve); return 0; }
ubs24gco_stop_once(){ LOG+=(ovpn-stop); UBS24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; return 0; }
ubs24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); UBS24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
ubs24gco_complete_once(){ LOG+=(complete); UBS24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
ubs24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
ubs24gb2_close(){ LOG+=(close); return 0; }
ubs24pubd_disconnect_once || fail inverse-coordinator-success
[[ ${LOG[*]} == 'marker lock ovpn-live wg-id dual-observe wg-absent wg-reconcile ovpn-reobserve ovpn-stop hold-release complete marker-finalize' &&
   $UBS24PUBD_STAGE == public-dual-session-complete-sameboot-ready &&
   $UBS24PUBD_AUTHORITY == none && $UBS24PUBD_APPROVAL == consumed ]] &&
  pass coordinator-completes-wg-dropout-to-normal-sameboot-ready-state || fail inverse-coordinator-order

printf 'Results: %d passed, 0 failed\n' "$P"
