#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export UBS24E_CODE_ROOT=$PWD
source lib/combined-operational-public-v240-composition.sh

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; ((++P)); }
fail(){ printf 'FAIL: %s\n' "$1"; ((++F)); }

# Production loading / fixed-path boundary.
declare -F mvc24pube_reconcile_incomplete_start_locked >/dev/null && pass early-reconciler-loaded || fail early-reconciler-loaded
[[ $(mvc24pub_session_runtime_root) == /run/mvc-public-session ]] && pass fixed-public-runtime-root || fail fixed-public-runtime-root

# The prepared transaction parser must accept only the known early-cleanup
# evidence files. This is a real parser/file-format test, not a coordinator mock.
T=$(mktemp -d /tmp/ubs-c23be.XXXXXXXX)
trap 'rm -rf -- "$T"' EXIT
TEST_RUNTIME=$T/public
mkdir -m 700 "$TEST_RUNTIME"
mvc24pub_session_runtime_root(){ printf '%s\n' "$TEST_RUNTIME"; }
boot=$(cat /proc/sys/kernel/random/boot_id)
userns=$(readlink /proc/self/ns/user); netns=$(readlink /proc/self/ns/net); mntns=$(readlink /proc/self/ns/mnt)
cat > "$TEST_RUNTIME/transaction" <<EOF2
ubs-v240-public-transaction-v1
state=prepared-before-mutation
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=11111111-1111-4111-8111-111111111111
ovpn_clone_uuid=-
wg_source_uuid=22222222-2222-4222-8222-222222222222
wg_temp_uuid=33333333-3333-4333-8333-333333333333
underlay=f15ra
controller_prepare_sha=-
controller_transition_sha=-
activation_sha=-
output_sha=-
d4_intent_sha=-
EOF2
chmod 400 "$TEST_RUNTIME/transaction"
: > "$TEST_RUNTIME/early-plan"; chmod 400 "$TEST_RUNTIME/early-plan"
mvc24pubd_reset
mvc24pubd_parse_transaction_marker && pass prepared-parser-allows-known-early-evidence || fail prepared-parser-allows-known-early-evidence
[[ $UBS24PUBD_TRANSACTION_STATE == prepared-before-mutation ]] && pass prepared-parser-preserves-state || fail prepared-parser-preserves-state
: > "$TEST_RUNTIME/early-retire-intent"; chmod 400 "$TEST_RUNTIME/early-retire-intent"
mvc24pubd_parse_transaction_marker && pass prepared-parser-allows-retirement-evidence || fail prepared-parser-allows-retirement-evidence
rm -f "$TEST_RUNTIME/early-retire-intent"
: > "$TEST_RUNTIME/unknown"; chmod 400 "$TEST_RUNTIME/unknown"
! mvc24pubd_parse_transaction_marker && pass prepared-parser-rejects-unknown-evidence || fail prepared-parser-rejects-unknown-evidence
rm -f "$TEST_RUNTIME/unknown"

# Direct durable simple-intent serialization/validation.
UBS24PUBE_SOURCE_UUID=11111111-1111-4111-8111-111111111111
UBS24PUBE_CLONE_UUID=44444444-4444-4444-8444-444444444444
UBS24PUBE_NM_OWNER=':1.2|123|0'
echo plan > "$TEST_RUNTIME/early-plan"; chmod 400 "$TEST_RUNTIME/early-plan"
stop_intent=$TEST_RUNTIME/early-stop-intent
mvc24pube_publish_simple_intent stop "$stop_intent" && pass durable-stop-intent-publishes || fail durable-stop-intent-publishes
mvc24pube_simple_intent_valid stop "$stop_intent" && pass durable-stop-intent-validates || fail durable-stop-intent-validates
sed -i 's/state=observation-driven-cleanup/state=tampered/' "$stop_intent"; chmod 400 "$stop_intent"
! mvc24pube_simple_intent_valid stop "$stop_intent" && pass durable-stop-intent-tamper-rejected || fail durable-stop-intent-tamper-rejected
rm -f "$stop_intent"

# High-level reconciler ordering: real coordinator, independently tested leaves
# substituted so no host mutation occurs in this test.
LOG=()
release_path=$T/no-release-yet
mvc24pube_prepare_plan_locked(){ LOG+=(plan); return 0; }
mvc24pube_release_intent_path(){ printf '%s\n' "$release_path"; }
mvc24pube_ensure_c1_guard(){ LOG+=(c1); return 0; }
mvc24pube_stop_clone_if_needed(){ LOG+=(stop); return 0; }
mvc24pube_delete_clone_if_needed(){ LOG+=(delete); return 0; }
mvc24pube_release_guard(){ LOG+=(release); return 0; }
mvc24pube_retire_runtime_roots(){ LOG+=(retire); return 0; }
mvc24pube_reconcile_incomplete_start_locked && pass normal-early-reconcile-succeeds || fail normal-early-reconcile-succeeds
[[ ${LOG[*]} == 'plan c1 stop delete release retire' ]] && pass normal-early-reconcile-order || fail normal-early-reconcile-order
[[ $UBS24PUBE_STAGE == clean-baseline-restored ]] && pass normal-early-reconcile-final-stage || fail normal-early-reconcile-final-stage

# A process that died after final nft release must not demand C1 again.
: > "$T/release-intent"; release_path=$T/release-intent
LOG=()
mvc24pube_release_intent_valid(){ LOG+=(release-intent); return 0; }
mvc24pube_owned_tables_absent_now(){ LOG+=(tables-absent); return 0; }
mvc24pube_reconcile_incomplete_start_locked && pass post-release-resume-succeeds || fail post-release-resume-succeeds
[[ ${LOG[*]} == 'plan release-intent tables-absent release retire' ]] && pass post-release-resume-skips-pre-release-mutations || fail post-release-resume-skips-pre-release-mutations

# Restore the production early-reconciler definitions after the coordinator
# substitutions above, then verify intent-before-mutation ordering at each leaf.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh

# C11 -> C1 handback publishes/validates its intent before nft commit.
LOG=(); handback_done=$T/handback-done
hb_intent=$T/hb-intent; hb_batch=$T/hb.nft
mvc24pube_guard_state_now(){ [[ -e $handback_done ]] && printf '%s\n' c1 || printf '%s\n' c11; }
mvc24pube_handback_intent_path(){ printf '%s\n' "$hb_intent"; }
mvc24pube_handback_batch_path(){ printf '%s\n' "$hb_batch"; }
mvc24pube_publish_handback_intent(){ LOG+=(publish-handback); : > "$hb_intent"; : > "$hb_batch"; return 0; }
mvc24pube_handback_intent_valid(){ LOG+=(validate-handback); return 0; }
nft(){ LOG+=(nft-handback); : > "$handback_done"; return 0; }
UBS24PUBE_C13_PRESENT=yes
mvc24pube_ensure_c1_guard && pass handback-intent-before-nft-succeeds || fail handback-intent-before-nft-succeeds
[[ ${LOG[*]} == 'publish-handback validate-handback nft-handback' ]] && pass handback-intent-before-nft-order || fail handback-intent-before-nft-order

# NM stop intent precedes the single down request; host state, not nmcli exit,
# decides completion.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh
LOG=(); stop_intent2=$T/stop2
mvc24pube_stop_intent_path(){ printf '%s\n' "$stop_intent2"; }
mvc24pube_publish_simple_intent(){ LOG+=(publish-stop); : > "$2"; return 0; }
mvc24pube_simple_intent_valid(){ LOG+=(validate-stop); return 0; }
mvc24pube_active_clone_state(){ printf '%s\n' active; }
nmcli(){ LOG+=(nm-down); return 1; }
mvc24pube_converged_no_vpn_topology(){ LOG+=(converged); return 0; }
UBS24PUBE_CLONE_UUID=44444444-4444-4444-8444-444444444444
mvc24pube_stop_clone_if_needed && pass stop-intent-before-nm-down-succeeds || fail stop-intent-before-nm-down-succeeds
[[ ${LOG[*]} == 'publish-stop validate-stop nm-down converged' ]] && pass stop-intent-before-nm-down-order || fail stop-intent-before-nm-down-order

# Clone-delete intent precedes exact UUID deletion and post-state absence is
# authoritative even if the delete command's reply is lost.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh
LOG=(); del_intent=$T/delete-intent; clone_absent_calls=0
mvc24pube_converged_no_vpn_topology(){ LOG+=(converged); return 0; }
mvc24gc23t_clone_absent(){ ((++clone_absent_calls)); (( clone_absent_calls >= 2 )); }
mvc24gc23t_clone_present(){ return 0; }
mvc24pube_clone_exact_or_absent(){ LOG+=(clone-exact); return 0; }
mvc24pube_clone_delete_intent_path(){ printf '%s\n' "$del_intent"; }
mvc24pube_publish_simple_intent(){ LOG+=(publish-delete); : > "$2"; return 0; }
mvc24pube_simple_intent_valid(){ LOG+=(validate-delete); return 0; }
mvc24gc23t_nm_delete(){ LOG+=(nm-delete); return 1; }
UBS24PUBE_SOURCE_UUID=11111111-1111-4111-8111-111111111111
UBS24PUBE_CLONE_UUID=44444444-4444-4444-8444-444444444444
mvc24pube_delete_clone_if_needed && pass clone-delete-intent-before-delete-succeeds || fail clone-delete-intent-before-delete-succeeds
[[ ${LOG[*]} == 'converged clone-exact publish-delete validate-delete clone-exact nm-delete' ]] && pass clone-delete-intent-before-delete-order || fail clone-delete-intent-before-delete-order

# Guard release: intent is published before nft deletion and the post-witness
# decides success.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh
LOG=(); rel_intent=$T/release2-intent; rel_batch=$T/release2.nft
mvc24pube_release_intent_path(){ printf '%s\n' "$rel_intent"; }
mvc24pube_release_batch_path(){ printf '%s\n' "$rel_batch"; }
mvc24pube_publish_release_intent(){ LOG+=(publish-release); : > "$rel_intent"; : > "$rel_batch"; return 0; }
mvc24pube_release_intent_valid(){ LOG+=(validate-release); return 0; }
mvc24pube_owned_tables_absent_now(){ return 1; }
mvc24pube_guard_state_now(){ printf '%s\n' c1; }
mvc24pube_converged_no_vpn_topology(){ return 0; }
mvc24gc23t_clone_absent(){ return 0; }
nft(){ LOG+=(nft-release); return 0; }
mvc24gc23t_release_post_witness(){ LOG+=(release-post); return 0; }
mvc24gc23t_b2_topology_witness(){ LOG+=(topology-post); return 0; }
mvc24pube_release_guard && pass release-intent-before-nft-delete-succeeds || fail release-intent-before-nft-delete-succeeds
[[ ${LOG[*]} == 'publish-release validate-release nft-release release-post topology-post' ]] && pass release-intent-before-nft-delete-order || fail release-intent-before-nft-delete-order

# Runtime retirement publishes durable intent before closing the B2 descriptor
# and before any owned journal directory is moved.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh
LOG=(); retire_intent=$T/retire-intent
mvc24pube_release_intent_valid(){ LOG+=(release-valid); return 0; }
mvc24gc23t_release_post_witness(){ LOG+=(release-post); return 0; }
mvc24gc23t_b2_topology_witness(){ LOG+=(topology); return 0; }
mvc24gc23t_clone_absent(){ LOG+=(clone-absent); return 0; }
mvc24pube_owned_tables_absent_now(){ LOG+=(tables-absent); return 0; }
mvc24pube_retire_intent_path(){ printf '%s\n' "$retire_intent"; }
mvc24pube_publish_retire_intent(){ LOG+=(publish-retire); : > "$retire_intent"; return 0; }
mvc24pube_retire_intent_valid(){ LOG+=(retire-valid); return 0; }
mvc24gb2_close(){ LOG+=(close-b2); return 0; }
mvc24pube_retire_archive_continue(){ LOG+=(archive); return 0; }
UBS24PUBE_CLONE_UUID=44444444-4444-4444-8444-444444444444
mvc24pube_retire_runtime_roots && pass retire-intent-before-runtime-move-succeeds || fail retire-intent-before-runtime-move-succeeds
[[ ${LOG[*]} == 'release-valid release-post topology clone-absent tables-absent publish-retire retire-valid close-b2 archive' ]] && pass retire-intent-before-runtime-move-order || fail retire-intent-before-runtime-move-order

# The archive continuation itself is observation-driven and moves the public
# transaction runtime last. Simulate an interruption after the other fixed
# roots were already moved: continuation must still finish without B2/C7.
source lib/combined-operational-public-v240-openvpn-early-reconcile.sh
AR=$T/archive-resume; mkdir -p "$AR/runtime" "$AR/archive/44444444-4444-4444-8444-444444444444" "$AR/archive/44444444-4444-4444-8444-444444444444/controller" "$AR/archive/44444444-4444-4444-8444-444444444444/activation"
chmod 700 "$AR/runtime" "$AR/archive" "$AR/archive/44444444-4444-4444-8444-444444444444" "$AR/archive/44444444-4444-4444-8444-444444444444/controller" "$AR/archive/44444444-4444-4444-8444-444444444444/activation"
: > "$AR/runtime/transaction"; chmod 400 "$AR/runtime/transaction"
mvc24pube_runtime(){ printf '%s\n' "$AR/runtime"; }
mvc24pube_archive_root(){ printf '%s\n' "$AR/archive"; }
mvc24pube_controller_runtime(){ printf '%s\n' "$AR/missing-controller"; }
mvc24pube_activation_runtime(){ printf '%s\n' "$AR/missing-activation"; }
mvc24pube_output_runtime(){ printf '%s\n' "$AR/missing-output"; }
mvc24pube_retire_intent_valid(){ UBS24PUBE_SOURCE_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBE_CLONE_UUID=44444444-4444-4444-8444-444444444444; UBS24PUBE_UNDERLAY=f15ra; UBS24PUBE_C13_PRESENT=no; return 0; }
mvc24pube_retire_plan_hashes(){ UBS24PUBE_RETIRE_C1_SHA=$(printf '1%.0s' {1..64}); UBS24PUBE_RETIRE_C7_SHA=$(printf '2%.0s' {1..64}); UBS24PUBE_RETIRE_C13_SHA=-; return 0; }
mvc24gb4_no_active_vpn(){ return 0; }
mvc24gc23t_clone_absent(){ return 0; }
mvc24pube_owned_tables_absent_now(){ return 0; }
mvc24pube_controller_dir_valid_for_retire(){ return 0; }
mvc24pube_single_attempt_dir_valid(){ return 0; }
mvc24pube_retire_archive_continue && pass retire-resume-after-controller-move-succeeds || fail retire-resume-after-controller-move-succeeds
[[ ! -e $AR/runtime && -d $AR/archive/44444444-4444-4444-8444-444444444444/public-session ]] && pass retire-public-runtime-moved-last || fail retire-public-runtime-moved-last

# Restore complete production composition after leaf overrides.
source lib/combined-operational-public-v240-composition.sh

# CONNECT: a C7-authenticated start failure must self-clean; pre-C7 must not
# invent ownership.
mvc24pub_session_runtime_root(){ printf '%s\n' /run/mvc-public-session; }
mvc24pubc_reset; mvc24gco_reset
LOG=()
mvc24pubc_preflight_readonly(){ LOG+=(preflight); UBS24PUBC_OVPN_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBC_WG_UUID=22222222-2222-4222-8222-222222222222; UBS24PUBC_TEMP_UUID=33333333-3333-4333-8333-333333333333; UBS24PUBC_UNDERLAY=f15ra; return 0; }
mvc24pubc_transaction_write(){ LOG+=("tx-$1"); UBS24PUBC_TRANSACTION_STATE=$1; return 0; }
mvc24gco_enable_public_live(){ LOG+=(enable); UBS24GCO_MODE=public-live-explicit-command; UBS24GCO_AUTHORITY=public-explicit-connect; return 0; }
mvc24gco_start_once(){ LOG+=(ovpn-start); UBS24GC17_STAGE=bootstrap-or-activation-outcome-uncertain; return 1; }
mvc24pube_c7_intent_present(){ LOG+=(c7); return 0; }
mvc24pube_reconcile_incomplete_start_locked(){ LOG+=(early-clean); UBS24PUBE_STAGE=clean-baseline-restored; return 0; }
mvc24pubc_consume_authority(){ LOG+=(consume); UBS24PUBC_AUTHORITY=none; return 0; }
! mvc24pubc_connect_once wg ovpn && pass connect-c7-partial-start-returns-failure-after-cleanup || fail connect-c7-partial-start-returns-failure-after-cleanup
[[ ${LOG[*]} == 'preflight tx-prepared-before-mutation enable ovpn-start c7 early-clean consume' ]] && pass connect-c7-partial-start-cleanup-order || fail connect-c7-partial-start-cleanup-order
[[ $UBS24PUBC_STAGE == openvpn-start-failed-bootstrap-or-activation-outcome-uncertain-auto-cleaned-baseline ]] && pass connect-c7-partial-start-reports-clean-baseline || fail connect-c7-partial-start-reports-clean-baseline

mvc24pubc_reset; mvc24gco_reset; LOG=()
mvc24pube_c7_intent_present(){ LOG+=(c7); return 1; }
! mvc24pubc_connect_once wg ovpn && pass connect-pre-c7-failure-remains-refused || fail connect-pre-c7-failure-remains-refused
[[ ${LOG[*]} == 'preflight tx-prepared-before-mutation enable ovpn-start c7 consume' ]] && pass connect-pre-c7-does-not-run-early-cleanup || fail connect-pre-c7-does-not-run-early-cleanup
[[ $UBS24PUBC_STAGE == openvpn-start-failed-bootstrap-or-activation-outcome-uncertain-cleanup-refused-use-disconnect-or-recovery ]] && pass connect-pre-c7-stage-explicit || fail connect-pre-c7-stage-explicit

# Fresh DISCONNECT after network cleanup but interrupted journal retirement does
# not need the already-archived B2/C7 roots; the durable retirement intent is
# enough to resume non-network journal movement.
mvc24pubd_reset; LOG=(); retire_resume=$T/retire-resume-marker; : > "$retire_resume"
mvc24pubd_parse_session_marker(){ LOG+=(marker); UBS24PUBD_MARKER_KIND=transaction; UBS24PUBD_TRANSACTION_STATE=prepared-before-mutation; UBS24PUBD_OVPN_SOURCE_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBD_WG_SOURCE_UUID=22222222-2222-4222-8222-222222222222; UBS24PUBD_WG_TEMP_UUID=33333333-3333-4333-8333-333333333333; UBS24PUBD_UNDERLAY=f15ra; return 0; }
mvc24pube_retire_intent_path(){ printf '%s\n' "$retire_resume"; }
mvc24pube_retire_archive_continue(){ LOG+=(retire-resume); return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(unexpected-lock); return 1; }
mvc24pubd_disconnect_once && pass disconnect-retirement-resumes-without-b2 || fail disconnect-retirement-resumes-without-b2
[[ ${LOG[*]} == 'marker retire-resume' ]] && pass disconnect-retirement-bypasses-missing-b2-lock || fail disconnect-retirement-bypasses-missing-b2-lock
[[ $UBS24PUBD_STAGE == public-incomplete-openvpn-start-clean-baseline-restored ]] && pass disconnect-retirement-final-state || fail disconnect-retirement-final-state
rm -f -- "$retire_resume"

# Fresh DISCONNECT: prepared transaction + live state goes through lock + early
# reconciler instead of being rejected as unsupported.
mvc24pubd_reset; LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); UBS24PUBD_MARKER_KIND=transaction; UBS24PUBD_TRANSACTION_STATE=prepared-before-mutation; UBS24PUBD_OVPN_SOURCE_UUID=11111111-1111-4111-8111-111111111111; UBS24PUBD_WG_SOURCE_UUID=22222222-2222-4222-8222-222222222222; UBS24PUBD_WG_TEMP_UUID=33333333-3333-4333-8333-333333333333; UBS24PUBD_UNDERLAY=f15ra; return 0; }
mvc24pubd_finalize_prepared_transaction_if_clean(){ LOG+=(clean-check); return 1; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pube_reconcile_incomplete_start_locked(){ LOG+=(early-clean); UBS24PUBE_STAGE=clean-baseline-restored; return 0; }
mvc24pubd_disconnect_once && pass disconnect-prepared-live-c7-reconciles || fail disconnect-prepared-live-c7-reconciles
[[ ${LOG[*]} == 'marker clean-check lock early-clean' ]] && pass disconnect-prepared-live-c7-order || fail disconnect-prepared-live-c7-order
[[ $UBS24PUBD_STAGE == public-incomplete-openvpn-start-clean-baseline-restored ]] && pass disconnect-prepared-live-c7-final-state || fail disconnect-prepared-live-c7-final-state

# Frozen physical core remains unchanged.
[[ $(sha256sum lib/combined-operational-d4-wireguard-parallel-live.sh | awk '{print $1}') == e6ca95fad0e5e264e887b56db0f0773cca24f048148aa5854382425fea6b0f76 ]] && pass r3a-d4-source-identity || fail r3a-d4-source-identity
[[ $(sha256sum lib/combined-operational-openvpn-composition.sh | awk '{print $1}') == 22379db8691d473d5734d2c306e488494381baa28d85815c3a58e1d451dd944c ]] && pass r3a-gco-source-identity || fail r3a-gco-source-identity
[[ $(sha256sum lib/combined-operational-c19-protected-openvpn-stop.sh | awk '{print $1}') == 36b013813f36b17b285e982020d11b3159d4f1f5d38a8c515364a8f3f404904b ]] && pass r3a-c19-source-identity || fail r3a-c19-source-identity

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
