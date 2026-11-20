#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export MVC24E_CODE_ROOT=$PWD
source lib/combined-operational-public-composition.sh

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

# 1. Break-glass observation is a strict conjunction: B4 absence alone is not
# authority.  The same-boot C19/B2 session, clean managed network state,
# topology safety and unchanged foreign policy must all prove true.
LOG=()
mvc24pubd_reset
MVC24PUBD_SESSION_MODE=combined
MVC24PUBD_OVPN_SOURCE_UUID=11111111-1111-4111-8111-111111111111
MVC24PUBD_OVPN_CLONE_UUID=22222222-2222-4222-8222-222222222222
mvc24pubd_b4_all_absent(){ LOG+=(b4); return 0; }
mvc24gb4_no_active_vpn(){ LOG+=(vpn); return 0; }
mvc24pubd_managed_routes_absent(){ LOG+=(routes); return 0; }
mvc24pubd_breakglass_wg_absent(){ LOG+=(wg); return 0; }
mvc24gc23t_recover_locked_session(){ LOG+=(session); MVC24GC23T_SOURCE_UUID=$MVC24PUBD_OVPN_SOURCE_UUID; MVC24GC23T_CLONE_UUID=$MVC24PUBD_OVPN_CLONE_UUID; MVC24GC23T_NM_OWNER=':1.7|100|0'; return 0; }
mvc24gc23t_b2_topology_witness(){ LOG+=(topology); return 0; }
mvc24gc23t_release_post_witness(){ LOG+=(foreign); return 0; }
mvc24gc23t_clone_present(){ LOG+=(clone); return 0; }
# Keep this test hermetic instead of touching /run/mvc-completion.
[[ ! -e /run/mvc-completion && ! -L /run/mvc-completion ]] || rm -rf /run/mvc-completion
mvc24pubd_breakglass_recovered_observed &&
  [[ ${LOG[*]} == 'b4 vpn routes wg session topology foreign clone' ]] &&
  pass 'break-glass retirement requires full authenticated clean-state witness' || fail 'break-glass witness conjunction'

# 2. Any failed safety predicate refuses the state before clone retirement.
LOG=()
mvc24pubd_managed_routes_absent(){ LOG+=(routes); return 1; }
! mvc24pubd_breakglass_recovered_observed && [[ ${LOG[*]} == 'b4 vpn routes' ]] &&
  pass 'managed-route residue blocks break-glass retirement before mutation' || fail 'route-residue refusal'

# 3. Coordinator ordering: when normal active parsing cannot authenticate the
# removed D4 intent, the recovery parser may reattach, but B4-absent state is
# routed exclusively through recovery finalization and never normal teardown.
source lib/combined-operational-public-disconnect.sh
mvc24pubd_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(normal-marker); return 1; }
mvc24pubd_parse_breakglass_marker(){ LOG+=(recovery-marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; return 0; }
mvc24pubd_parse_completed_session_marker(){ LOG+=(completed-marker); return 1; }
mvc24pubd_parse_recovered_completed_marker(){ LOG+=(recovered-completed-marker); return 1; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ LOG+=(b4); return 0; }
mvc24pubd_breakglass_recovered_observed(){ LOG+=(observe); return 0; }
mvc24pubd_breakglass_finalize_once(){ LOG+=(finalize); return 0; }
mvc24pubd_finalize_completed_marker(){ LOG+=(marker-retire); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(NORMAL-TEARDOWN-MUST-NOT-RUN); return 1; }
mvc24gb2_close(){ LOG+=(close); return 0; }
mvc24pubd_disconnect_once &&
  [[ ${LOG[*]} == 'normal-marker recovery-marker lock b4 observe finalize marker-retire' &&
     $MVC24PUBD_STAGE == public-breakglass-recovered-session-retired-sameboot-ready ]] &&
  pass 'disconnect retires authenticated break-glass state without re-entering normal guarded teardown' || fail 'break-glass coordinator order'

# 4. B4 already absent but recovery proof failing is fail-closed and does not
# fall through into OpenVPN/WireGuard mutation paths.
mvc24pubd_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=transaction; MVC24PUBD_TRANSACTION_STATE=openvpn-protected; MVC24PUBD_SESSION_MODE=openvpn-only; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_b4_all_absent(){ LOG+=(b4); return 0; }
mvc24pubd_breakglass_recovered_observed(){ LOG+=(observe); return 1; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(NORMAL-TEARDOWN-MUST-NOT-RUN); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
! mvc24pubd_disconnect_once &&
  [[ ${LOG[*]} == 'marker lock b4 observe close' && $MVC24PUBD_STAGE == breakglass-recovered-state-refused ]] &&
  pass 'ambiguous B4-absent state remains blocked and cannot enter normal teardown' || fail 'ambiguous break-glass refusal'

# 5. If recovery archival completed but public marker deletion was interrupted,
# the dedicated completed-recovery parser is attempted before baseline fallback.
mvc24pubd_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(normal); return 1; }
mvc24pubd_parse_breakglass_marker(){ LOG+=(recovery-live); return 1; }
mvc24pubd_parse_completed_session_marker(){ LOG+=(normal-completed); return 1; }
mvc24pubd_parse_recovered_completed_marker(){ LOG+=(recovered-completed); MVC24PUBD_COMPLETED_MARKER_FILE=/run/mvc-public-session/active; return 0; }
mvc24pubd_finalize_completed_marker(){ LOG+=(retire); return 0; }
mvc24pub_baseline_clean_readonly(){ LOG+=(BASELINE-MUST-NOT-RUN); return 0; }
mvc24pubd_disconnect_once &&
  [[ ${LOG[*]} == 'normal recovery-live normal-completed recovered-completed retire' &&
     $MVC24PUBD_STAGE == public-breakglass-recovered-session-retired-sameboot-ready ]] &&
  pass 'interrupted recovered-marker retirement resumes filesystem-only' || fail 'recovered marker resume'

# 6. Recovery records are an explicit intent-before-delete/archive chain rather
# than pretending the normal C23T release intent existed after emergency disarm.
DISC=lib/combined-operational-public-disconnect.sh
for sig in mvc-c24b-breakglass-finalize-v1 mvc-c24b-breakglass-clone-delete-v1 mvc-c24b-breakglass-archive-plan-v1; do
    if [[ $(grep -Fc "$sig" "$DISC") -ge 2 ]]; then pass "$sig producer/validator pair present"; else fail "$sig producer/validator pair present"; fi
done

# 7. Emergency tool remains a B4-only break-glass tool, but now tells the
# operator to use authenticated disconnect for finalization instead of exposing
# the internal B4 retry prohibition as the user-facing contract.
REC=tools/recover-mvc-host-guard-local.sh
if grep -Fq 'run sudo mvc disconnect once to authenticate and finalize recovery' "$REC" &&
   ! grep -Fq 'do not retry B4 install in this boot' "$REC"; then
    pass 'emergency disarm guidance delegates recovered-session retirement to mvc disconnect'
else
    fail 'emergency disarm recovery-finalization guidance'
fi

# 8. Installer explicitly authorizes both current development predecessors and
# the exact old emergency recovery bytes when using the update action.
INST=tools/install-mvc.sh
if grep -Fq "'70fcc4f01e85f5d07db130a0dfe5a8b2b039d5fb7f4e7c98ef6707335924f2b8'" "$INST" &&
   grep -Fq "'41a1e75248a5cc2cfee7854b82ba4ca0f14df538997d10c4a3db3d46ce7766fc'" "$INST" &&
   grep -Fq "'b521110ab5dabcd43c4d0c903283f50f2e76dc520d20074e0ef49a81c104a02c'" "$INST"; then
    pass 'installer update allowlists exact R1/R2 controller and prior emergency recovery identities'
else
    fail 'installer predecessor authorization'
fi

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
