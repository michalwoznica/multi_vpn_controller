#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
A=$ROOT/dist/mvc
PASS=0; FAIL=0
ok(){ printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'rm -rf -- "$TMP"' EXIT
sed '$d' "$A" > "$TMP/body"

[[ $($A version) == 'Multi VPN Controller 2.4.1' ]] && ok 'generated candidate reports v2.4.1' || bad 'generated candidate reports v2.4.1'

BODY=$TMP/body bash -s <<'CHECK' && ok 'generated candidate contains both authenticated dropout reconciler families' || bad 'generated candidate contains both authenticated dropout reconciler families'
set -euo pipefail
source "$BODY"
for fn in ubs24pubd_openvpn_absent_observed ubs24pubr_reconcile_d4_to_c11_hold_openvpn_absent ubs24gc19_publish_absent_intent ubs24pubr_published_wg_absent_observed ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold; do
  declare -F "$fn" >/dev/null
 done
CHECK

# OpenVPN disappears / WG survives: exercise the generated coordinator ordering.
BODY=$TMP/body bash -s <<'OPENVPN_DROP' && ok 'generated disconnect completes authenticated OpenVPN-dropout path same-boot-ready' || bad 'generated disconnect completes authenticated OpenVPN-dropout path same-boot-ready'
set -euo pipefail
source "$BODY"
LOG=()
ubs24pubd_reset; ubs24gco_reset; ubs24gd4_reset; ubs24gc19_reset
ubs24pubd_parse_session_marker(){ LOG+=(marker); UBS24PUBD_MARKER_KIND=active; UBS24PUBD_SESSION_MODE=combined; UBS24PUBD_TRANSACTION_STATE=none; return 0; }
ubs24pubd_acquire_existing_lock(){ LOG+=(lock); return 0; }
ubs24pubd_rehydrate_openvpn_locked(){ LOG+=(ovpn-live); return 1; }
ubs24pubd_rehydrate_openvpn_identity_locked(){ LOG+=(ovpn-id); return 0; }
ubs24pubd_openvpn_absent_observed(){ LOG+=(ovpn-absent); return 0; }
ubs24pubd_load_d4_intent(){ LOG+=(wg-id); return 0; }
ubs24pubr_reconcile_d4_to_c11_hold_openvpn_absent(){ LOG+=(wg-reconcile); UBS24GD4_STAGE=wireguard-residue-removed-openvpn-absent-c11-private-hold; return 0; }
ubs24pubd_adopt_openvpn_absence_to_c1(){ LOG+=(ovpn-adopt); UBS24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority; UBS24GCO_STAGE=protected-stopped-c1-held-finalize-pending; return 0; }
ubs24gd4_release_private_hold_after_openvpn_stop(){ LOG+=(hold-release); UBS24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold; return 0; }
ubs24gco_complete_once(){ LOG+=(complete); UBS24GC23T_STAGE=completed-session-archived-sameboot-ready; return 0; }
ubs24pubd_finalize_marker(){ LOG+=(marker-finalize); return 0; }
ubs24gb2_close(){ LOG+=(close); return 0; }
ubs24pubd_disconnect_once
[[ ${LOG[*]} == 'marker lock ovpn-live ovpn-id ovpn-absent wg-id wg-reconcile ovpn-adopt hold-release complete marker-finalize' ]]
[[ $UBS24PUBD_STAGE == public-dual-session-complete-sameboot-ready && $UBS24PUBD_AUTHORITY == none ]]
OPENVPN_DROP

# WG disappears / OpenVPN survives: exercise the generated inverse coordinator path.
BODY=$TMP/body bash -s <<'WG_DROP' && ok 'generated disconnect completes authenticated WG-dropout path same-boot-ready' || bad 'generated disconnect completes authenticated WG-dropout path same-boot-ready'
set -euo pipefail
source "$BODY"
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
ubs24pubd_disconnect_once
[[ ${LOG[*]} == 'marker lock ovpn-live wg-id dual-observe wg-absent wg-reconcile ovpn-reobserve ovpn-stop hold-release complete marker-finalize' ]]
[[ $UBS24PUBD_STAGE == public-dual-session-complete-sameboot-ready && $UBS24PUBD_AUTHORITY == none ]]
WG_DROP

# The wrapper remains the same audited dispatcher promotion; disconnect is not a side channel.
if grep -Fq 'preflight|list|status|connect|disconnect)' "$A" && grep -Fq 'ubs24e_dispatch "$@"' "$A"; then
  ok 'generated public wrapper still delegates lifecycle only to audited dispatcher'
else
  bad 'generated public wrapper still delegates lifecycle only to audited dispatcher'
fi

printf 'RESULT: C24A Stage-3 generated dropout reconciliation %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
