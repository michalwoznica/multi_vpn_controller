#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
export MVC24E_CODE_ROOT=$ROOT
source lib/combined-operational-public-composition.sh

P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# 1. Protected stop accepts an authenticated raw-B2 partial-start guard and
# converges the owned WG side instead of demanding the fully protected shape.
LOG=()
mvc24gwg_authority_witness(){ LOG+=(authority); return 0; }
mvc24gwg_guard_exact_now(){ LOG+=(protected-no); return 1; }
mvc24gwg_b2_guard_exact_now(){ LOG+=(b2); return 0; }
mvc24gwg_owned_tables_absent_now(){ return 1; }
mvc24gwg_converge_owned_network_once(){ LOG+=(converge); return 0; }
mvc24gwg_release_guard_once(){ LOG+=(release); return 0; }
mvc24gwg_retire_runtime_once(){ LOG+=(retire); return 0; }
mvc24gwg_stop_once || fail protected-raw-b2-stop
[[ ${LOG[*]} == 'authority protected-no b2 converge release retire' ]] &&
  pass protected-partial-start-raw-b2-converges || fail protected-raw-b2-order

# 2. An ambiguous protected guard still blocks before owned network mutation.
LOG=()
mvc24gwg_authority_witness(){ LOG+=(authority); return 0; }
mvc24gwg_guard_exact_now(){ LOG+=(protected-no); return 1; }
mvc24gwg_b2_guard_exact_now(){ LOG+=(b2-no); return 1; }
mvc24gwg_owned_tables_absent_now(){ LOG+=(absent-no); return 1; }
mvc24gwg_converge_owned_network_once(){ LOG+=(unexpected-mutation); return 0; }
! mvc24gwg_stop_once && [[ ${LOG[*]} == 'authority protected-no b2-no absent-no' ]] &&
  pass protected-partial-start-ambiguous-guard-remains-fatal || fail protected-ambiguous-guard

# 3. Protected prepared+D4 partial start dispatches normal convergence teardown.
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/d4"
LOG=()
mvc24pubd_parse_session_marker(){
    MVC24PUBD_MARKER_KIND=transaction
    MVC24PUBD_TRANSACTION_STATE=prepared-before-mutation
    MVC24PUBD_SESSION_MODE=wireguard-protected
    MVC24PUBD_WG_TEMP_UUID=11111111-2222-4333-8444-555555555555
    MVC24PUBD_UNDERLAY=test-wlan0
    return 0
}
mvc24pubd_finalize_prepared_transaction_if_clean(){ return 1; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_emergency_disarm_boundary_observed(){ return 1; }
mvc24pub_wireguard_runtime_root(){ printf '%s\n' "$TMP/d4"; }
mvc24pubd_load_d4_intent(){ LOG+=(load-d4); return 0; }
mvc24gwg_stop_once(){ LOG+=(stop); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
MVC24PUBD_ATTEMPTED=no
mvc24pubd_disconnect_once || fail protected-d4-partial-dispatch
[[ ${LOG[*]} == 'lock load-d4 stop' && ${MVC24PUBD_STAGE:-} == public-wireguard-protected-partial-start-clean-baseline-restored ]] &&
  pass protected-prepared-d4-partial-start-uses-disconnect || fail protected-d4-partial-stage

# 4. Protected pre-D4 partial start uses the dedicated authenticated B2 release path.
rm -rf -- "$TMP/d4"
LOG=()
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_emergency_disarm_boundary_observed(){ return 1; }
mvc24gwg_reconcile_pre_d4_partial_start_once(){ LOG+=(pre-d4-reconcile); return 0; }
MVC24PUBD_ATTEMPTED=no
mvc24pubd_disconnect_once || fail protected-pre-d4-dispatch
[[ ${LOG[*]} == 'lock pre-d4-reconcile' && ${MVC24PUBD_STAGE:-} == public-wireguard-protected-pre-d4-partial-start-clean-baseline-restored ]] &&
  pass protected-pre-d4-partial-start-uses-journalled-disconnect || fail protected-pre-d4-stage

# 5. Post-emergency boundary is preserved: B4 absence without a normal disconnect release
# intent remains outside normal disconnect authority and does not enter the pre-D4 reconciler.
LOG=()
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_emergency_disarm_boundary_observed(){ LOG+=(emergency-boundary); return 0; }
mvc24gwg_reconcile_pre_d4_partial_start_once(){ LOG+=(unexpected-reconcile); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
MVC24PUBD_ATTEMPTED=no
! mvc24pubd_disconnect_once &&
  [[ ${LOG[*]} == 'lock emergency-boundary close' && ${MVC24PUBD_STAGE:-} == emergency-disarm-recovery-required ]] &&
  pass protected-partial-start-preserves-emergency-boundary || fail protected-emergency-boundary

# 6. Split prepared+D4 partial start likewise dispatches the existing
# convergence-aware split stop path.
mkdir -p "$TMP/d4"
LOG=()
mvc24pubd_parse_session_marker(){
    MVC24PUBD_MARKER_KIND=transaction
    MVC24PUBD_TRANSACTION_STATE=wireguard-split-prepared
    MVC24PUBD_SESSION_MODE=wireguard-split
    MVC24PUBD_WG_TEMP_UUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
    MVC24PUBD_UNDERLAY=test-wlan0
    return 0
}
mvc24gws_lock_reopen(){ LOG+=(lock); return 0; }
mvc24gws_prepared_clean_observed(){ return 1; }
mvc24pub_wireguard_runtime_root(){ printf '%s\n' "$TMP/d4"; }
mvc24pubd_load_d4_intent(){ LOG+=(load-d4); return 0; }
mvc24gws_network_clean_retirement_pending_observed(){ return 1; }
mvc24gws_stop_once(){ LOG+=(stop); return 0; }
mvc24gws_lock_close(){ LOG+=(close); return 0; }
MVC24PUBD_ATTEMPTED=no
mvc24pubd_disconnect_once || fail split-d4-partial-dispatch
[[ ${LOG[*]} == 'lock load-d4 stop' && ${MVC24PUBD_STAGE:-} == public-wireguard-split-partial-start-clean-baseline-restored ]] &&
  pass split-prepared-d4-partial-start-uses-disconnect || fail split-d4-partial-stage

# 7. Disconnect authority witnesses explicitly admit only the new partial-start
# stages; the cleanup engines still require authenticated same-boot authority.
protected_body=$(awk '/mvc24gwg_authority_witness\(\)/,/^}/' lib/combined-operational-wireguard-protected.sh)
split_body=$(awk '/mvc24gws_authority_witness\(\)/,/^}/' lib/combined-operational-wireguard-split.sh)
[[ $protected_body == *'stopping-wireguard-protected-partial-start'* &&
   $protected_body == *'reconciling-wireguard-protected-pre-d4-partial-start'* &&
   $split_body == *'stopping-wireguard-split-partial-start'* ]] &&
  pass partial-start-stages-are-explicitly-authorized || fail partial-stage-authority

# 8. The prepared transaction parser recognises only the two new protected-WG
# release journal filenames in addition to the pre-existing allowlist.
parser_body=$(awk '/elif \[\[ \$state == prepared-before-mutation/,/\[\[ -f \$file \]\]/' lib/combined-operational-public-disconnect.sh)
[[ $parser_body == *'wg-pre-d4-release.nft'* && $parser_body == *'wg-pre-d4-release-intent'* ]] &&
  pass protected-pre-d4-release-journals-are-parser-bound || fail pre-d4-parser-bindings

# 9. A pre-D4 release cannot be invented from B4 absence. Without an existing
# intent it first requires the exact authenticated B2 guard.
LOG=()
mvc24gwg_pre_d4_release_intent_path(){ printf '%s\n' "$TMP/no-intent"; }
mvc24gwg_pre_d4_release_batch_path(){ printf '%s\n' "$TMP/no-batch"; }
mvc24gwg_b2_guard_exact_now(){ LOG+=(b2-refused); return 1; }
mvc24gwg_pre_d4_publish_release_intent(){ LOG+=(unexpected-publish); return 0; }
! mvc24gwg_pre_d4_release_guard_once && [[ ${LOG[*]} == 'b2-refused' ]] &&
  pass pre-d4-release-requires-exact-b2-before-intent || fail pre-d4-release-authority

# 10. Failed standalone-WG starts now direct the operator to normal disconnect,
# not immediately to the recovery tools.
connect_body=$(awk '/mvc24pubc_connect_wireguard_protected_once\(\)/,/^}/' lib/combined-operational-public-connect.sh)
split_connect_body=$(awk '/mvc24pubc_connect_wireguard_split_once\(\)/,/^}/' lib/combined-operational-wireguard-split.sh)
[[ $connect_body == *'wireguard-protected-start-failed-'*'-use-disconnect'* &&
   $split_connect_body == *'wireguard-split-start-failed-'*'-use-disconnect'* ]] &&
  pass standalone-wg-start-failures-direct-to-normal-disconnect || fail start-failure-guidance

printf 'Results: %d passed, 0 failed\n' "$P"
