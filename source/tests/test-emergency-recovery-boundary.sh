#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
export MVC24E_CODE_ROOT=$PWD
source lib/combined-operational-public-composition.sh
source lib/combined-operational-public-disconnect.sh

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

DISC=lib/combined-operational-public-disconnect.sh
ENTRY=lib/combined-controller-entry.sh
REC=tools/recover-mvc-host-guard-local.sh
INST=tools/install-mvc.sh

# 1. The provisional R3 lifecycle-retirement protocol must be gone from the
# public disconnect implementation. Emergency recovery is no longer a second
# normal lifecycle path in this release.
if ! grep -Eq 'mvc-c24b-breakglass-(finalize|clone-delete|archive-plan)-v1|mvc24pubd_parse_breakglass_marker|mvc24pubd_breakglass_finalize_once' "$DISC"; then
    pass 'R3 break-glass lifecycle-finalization protocol is absent from public disconnect'
else
    fail 'R3 break-glass lifecycle-finalization protocol removal'
fi

# 2. The public CLI must not advertise a recovered-session same-boot success
# state that the current release no longer provides.
if ! grep -Fq 'EMERGENCY RECOVERY FINALIZED — SAME-BOOT FRESH SESSION ELIGIBLE' "$ENTRY" &&
   ! grep -Fq 'public-breakglass-recovered-session-retired-sameboot-ready' "$ENTRY"; then
    pass 'controller exposes no post-emergency same-boot finalization success'
else
    fail 'controller post-emergency success removal'
fi

# 3. Recovery finalization now belongs only to the independent emergency tool.
# B4 disarm remains phase 1, while --finalize can resume authenticated lifecycle
# retirement after the kill switch is already off. Normal mvc disconnect remains
# outside this catastrophic recovery path.
if grep -Fq -- '--finalization-inspect|--finalize' "$REC" &&
   grep -Fq 'RESULT: EMERGENCY RECOVERY COMPLETE — MVC OWNED STATE RETIRED' "$REC" &&
   grep -Fq 'mvc_er_finalize_recovery' "$REC" &&
   ! grep -Fq 'run sudo mvc disconnect once to authenticate and finalize recovery' "$REC"; then
    pass 'independent emergency tool owns authenticated post-disarm finalization'
else
    fail 'independent emergency finalization boundary'
fi

# 4. B4 absence without a normal release intent is the emergency-disarm
# boundary. This is a classification only; B4 absence grants no cleanup authority.
mvc24pubd_reset
MVC24PUBD_SESSION_MODE=combined
mvc24pubd_b4_all_absent(){ return 0; }
mvc24pubd_normal_guard_release_intent_present(){ return 1; }
if mvc24pubd_emergency_disarm_boundary_observed; then
    pass 'B4 absence without normal release intent is classified as emergency boundary'
else
    fail 'emergency boundary classification'
fi

# 5. A normal teardown that already published its authenticated guard-release
# intent must remain resumable even if B4 is already absent after the commit.
mvc24pubd_normal_guard_release_intent_present(){ return 0; }
if ! mvc24pubd_emergency_disarm_boundary_observed; then
    pass 'normal release-intent resume is not misclassified as emergency recovery'
else
    fail 'normal release resume classification'
fi

# 6. Coordinator ordering: an authenticated protected session with B4 absent
# and no normal release intent refuses before any tunnel/profile mutation.
mvc24pubd_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; MVC24PUBD_TRANSACTION_STATE=none; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_emergency_disarm_boundary_observed(){ LOG+=(emergency-boundary); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(MUTATION-PATH-MUST-NOT-RUN); return 0; }
mvc24gb2_close(){ LOG+=(close); return 0; }
if ! mvc24pubd_disconnect_once &&
   [[ ${LOG[*]} == 'marker lock emergency-boundary close' &&
      $MVC24PUBD_STAGE == emergency-disarm-recovery-required ]]; then
    pass 'disconnect refuses post-emergency lifecycle mutation and requires recovery'
else
    fail 'disconnect emergency-boundary coordinator order'
fi

# 7. Normal guarded teardown still proceeds when the emergency boundary is not
# present. This protects R2-R6 convergence behavior from the R7 cleanup.
mvc24pubd_reset; mvc24gco_reset; mvc24gd4_reset
LOG=()
mvc24pubd_parse_session_marker(){ LOG+=(marker); MVC24PUBD_MARKER_KIND=active; MVC24PUBD_SESSION_MODE=combined; MVC24PUBD_TRANSACTION_STATE=none; return 0; }
mvc24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
mvc24pubd_emergency_disarm_boundary_observed(){ LOG+=(boundary-check); return 1; }
mvc24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
mvc24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent-probe); return 1; }
mvc24pubd_openvpn_owned_active_observed(){ LOG+=(ovpn-owned); return 0; }
mvc24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-nominal); return 0; }
mvc24pubd_load_d4_intent(){ LOG+=(wg); return 0; }
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_convergence(){ LOG+=(wg-clean); MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold; return 0; }
mvc24pubd_stop_openvpn_convergent(){ LOG+=(ovpn-stop); MVC24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; MVC24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
mvc24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
mvc24gco_complete_once(){ LOG+=(complete); MVC24GCO_STAGE=completed-session-archived-sameboot-ready; MVC24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
mvc24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
if mvc24pubd_disconnect_once && [[ $MVC24PUBD_STAGE == public-dual-session-complete-sameboot-ready ]]; then
    pass 'ordinary authenticated disconnect convergence remains active'
else
    fail 'ordinary disconnect preserved after recovery-boundary cleanup'
fi

# 8. The current package must authenticate the exact released 2.4.4 controller
# plus both the released 2.4.4 and R1 emergency-recovery bytes as update predecessors.
if grep -Fq "'c659143883ddf900ddba4aa4c6cd74edd761b820be5b1d51bb335cdcbf9c31db'" "$INST" &&
   grep -Fq "'cceded2c13eccb7cec970f213a12631f635cec28ad218ab2105c7a120f771897'" "$INST" &&
   grep -Fq "'9eca9dc61bb76dee7f4c06579a5609d46e85e514121628f03eab604518462717'" "$INST"; then
    pass 'installer authenticates released 2.4.4 and R1 emergency recovery predecessors'
else
    fail 'installer recovery predecessor authorization'
fi

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
