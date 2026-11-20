#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
export MVC24E_CODE_ROOT=$ROOT
source lib/combined-operational-public-composition.sh

P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# 1. Teardown identity is reconstructed from the immutable same-boot D4 intent.
# The mutable saved source profile must no longer be a cleanup prerequisite.
body=$(awk '
  /^mvc24pubd_load_d4_intent\(\)/ {inside=1}
  inside {print}
  inside && /^}/ {exit}
' lib/combined-operational-public-disconnect.sh)
[[ $body == *'Teardown authority is the immutable same-boot D4 intent'* ]] &&
  [[ $body != *'mvc24gd2_find_saved_keyfile'* ]] &&
  [[ $body != *'mvc24gd2_validate_keyfile'* ]] &&
  [[ $body != *'connection.type connection show uuid'* ]] &&
  pass teardown-authority-no-longer-depends-on-current-saved-wg-profile || fail d4-source-profile-dependency

# 2. The public authority witness explicitly admits the convergence stage.
mvc24gb2_root_scope(){ return 0; }
mvc24gb2_lock_valid(){ return 0; }
mvc24pub_disconnect_admission_witness(){ return 0; }
MVC24GCO_STAGE=protected-openvpn-observed
MVC24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
MVC24PUBD_AUTHORITY=public-explicit-disconnect
MVC24PUBD_STAGE=reconciling-dual-wireguard
mvc24pubr_context_witness && pass dual-convergence-stage-is-authorized-after-session-authentication || fail convergence-authority

# 3. A proto-186 endpoint route already absent after underlay churn is a safe
# post-state, not a reason to abort authenticated convergence.
LOG=()
cur_guard=parallel
cur_nm=active
cur_route=absent
cur_key=owned
mvc24pubr_context_witness(){ LOG+=(authority); return 0; }
mvc24pubr_inventory_all(){
  LOG+=(inventory)
  MVC24PUBR_GUARD_STATUS=$cur_guard
  MVC24PUBR_NM_STATUS=$cur_nm
  MVC24PUBR_KERNEL_STATUS=$([[ $cur_nm == active ]] && printf active || printf absent)
  MVC24PUBR_ROUTE_STATUS=$cur_route
  MVC24PUBR_KEYFILE_STATUS=$cur_key
  MVC24PUBR_HOLD_STATUS=absent
  return 0
}
mvc24pubr_ensure_hold_routes(){ LOG+=(holds); MVC24PUBR_HOLD_STATUS=full; return 0; }
mvc24pubr_disconnect_wg_if_active(){ LOG+=(wg-down); cur_nm=down; MVC24PUBR_NM_STATUS=down; MVC24PUBR_KERNEL_STATUS=absent; return 0; }
mvc24pubr_route_inventory(){ LOG+=(route-observe); MVC24PUBR_ROUTE_STATUS=$cur_route; return 0; }
mvc24pubr_guard_inventory(){ LOG+=(guard-observe); MVC24PUBR_GUARD_STATUS=$cur_guard; return 0; }
mvc24gd4_restore_openvpn_guard(){ LOG+=(restore-c11); cur_guard=c11; MVC24GD4_STAGE=pure-openvpn-guard-restored-route-profile-remain-private-hold; return 0; }
mvc24pubr_remove_endpoint_route_if_owned(){ LOG+=(route-remove); [[ $cur_route == absent ]]; return 0; }
mvc24pubr_remove_profile_if_owned(){ LOG+=(profile-remove); cur_nm=absent; cur_key=absent; return 0; }
mvc24gd4_finish_teardown(){ LOG+=(finish-d4); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubr_reconcile_partial_d4_to_openvpn_hold &&
  [[ ${LOG[*]} == 'inventory holds wg-down route-observe guard-observe restore-c11 route-remove profile-remove finish-d4' ]] &&
  [[ $MVC24GD4_STAGE == wireguard-residue-removed-openvpn-protected-private-hold ]] &&
  pass active-wg-with-already-absent-endpoint-route-converges || fail absent-endpoint-route-convergence

# 4. Foreign/unsupported guard state still blocks mutation before cleanup.
LOG=()
mvc24pubr_inventory_all(){
  LOG+=(inventory)
  MVC24PUBR_GUARD_STATUS=unknown
  MVC24PUBR_NM_STATUS=active
  MVC24PUBR_KERNEL_STATUS=active
  MVC24PUBR_ROUTE_STATUS=absent
  MVC24PUBR_KEYFILE_STATUS=owned
  MVC24PUBR_HOLD_STATUS=absent
  return 0
}
mvc24pubr_ensure_hold_routes(){ LOG+=(unexpected-mutation); return 0; }
! mvc24pubr_reconcile_partial_d4_to_openvpn_hold &&
  [[ ${LOG[*]} == 'inventory' ]] &&
  pass ambiguous-guard-remains-fatal-before-mutation || fail ambiguous-guard-refusal

# 5. Published dual teardown now uses the general authenticated reconciler when
# nominal running-shape reobservation fails. It must not require the old exact
# "published WG absent" classifier.
source lib/combined-operational-public-disconnect.sh
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; MVC24PUBD_TRANSACTION_STATE=none; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ return 1; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-live); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
mvc24gd4_dual_active_observed(){ LOG+=(dual-observe); return 1; }
mvc24gd4_private_hold_routes_state(){ [[ $1 == absent ]]; }
mvc24pubd_warn(){ LOG+=(warning); return 0; }
mvc24pubr_published_wg_absent_observed(){ LOG+=(legacy-classifier); return 1; }
mvc24pubr_reconcile_partial_d4_to_openvpn_hold(){ LOG+=(wg-converge); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_reobserve_openvpn_after_wg(){ LOG+=(ovpn-reobserve); return 0; }
mvc24gco_stop_once(){ LOG+=(ovpn-stop); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once || fail coordinator-general-convergence-success
[[ ${LOG[*]} == 'marker lock ovpn-live wg-id dual-observe warning wg-converge ovpn-reobserve ovpn-stop hold-release complete marker-finalize' ]] &&
  [[ $MVC24PUBD_STAGE == public-dual-session-complete-sameboot-ready ]] &&
  pass coordinator-converges-authenticated-dual-drift-without-shape-classifier || fail coordinator-general-convergence-order

# 6. A nominal healthy dual session also uses the same convergence engine,
# keeping one cleanup model instead of two historical-shape paths.
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; MVC24PUBD_TRANSACTION_STATE=none; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ return 1; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-live); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
mvc24gd4_dual_active_observed(){ LOG+=(dual-observe); return 0; }
mvc24gd4_private_hold_routes_state(){ [[ $1 == absent ]]; }
mvc24pubd_warn(){ LOG+=(unexpected-warning); return 0; }
mvc24pubr_reconcile_partial_d4_to_openvpn_hold(){ LOG+=(wg-converge); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_reobserve_openvpn_after_wg(){ LOG+=(ovpn-reobserve); return 0; }
mvc24gco_stop_once(){ LOG+=(ovpn-stop); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
mvc24pubd_disconnect_once || fail coordinator-nominal-convergence-success
[[ ${LOG[*]} == 'marker lock ovpn-live wg-id dual-observe wg-converge ovpn-reobserve ovpn-stop hold-release complete marker-finalize' ]] &&
  pass nominal-and-drifted-dual-state-share-one-cleanup-path || fail nominal-convergence-order

printf 'Results: %d passed, 0 failed\n' "$P"
