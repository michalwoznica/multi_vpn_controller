#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
REC=$ROOT/source/tools/recover-mvc-host-guard-local.sh
# shellcheck source=../tools/recover-mvc-host-guard-local.sh
source "$REC"

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
PUB=$TMP/public
CTRL=$TMP/controller
ACT=$TMP/activation
OUT=$TMP/output
WGRT=$TMP/wireguard
KEY=$TMP/vpnks-wg.nmconnection

# Parser fixtures use ordinary test-user files; production ownership/mode checks
# remain in the tool and are covered structurally. Override only those checks and
# fixed path helpers inside this test process.
mvc_er_public_root(){ printf '%s\n' "$PUB"; }
mvc_er_controller_root(){ printf '%s\n' "$CTRL"; }
mvc_er_activation_root(){ printf '%s\n' "$ACT"; }
mvc_er_output_root(){ printf '%s\n' "$OUT"; }
mvc_er_disconnect_root(){ printf '%s\n' "$TMP/disconnect"; }
mvc_er_completion_root(){ printf '%s\n' "$TMP/completion"; }
mvc_er_wireguard_root(){ printf '%s\n' "$WGRT"; }
mvc_er_controller_prepare_path(){ printf '%s\n' "$CTRL/prepare-intent"; }
mvc_er_controller_transition_path(){ printf '%s\n' "$CTRL/transition-attempt"; }
mvc_er_activation_path(){ printf '%s\n' "$ACT/attempt"; }
mvc_er_output_path(){ printf '%s\n' "$OUT/attempt"; }
mvc_er_d4_intent_path(){ printf '%s\n' "$WGRT/intent"; }
mvc_er_wg_keyfile_path(){ printf '%s\n' "$KEY"; }
mvc_er_secure_dir(){ [[ -d $1 && ! -L $1 ]]; }
mvc_er_secure_file(){ [[ -f $1 && ! -L $1 ]]; }

uuid_os=11111111-1111-4111-8111-111111111111
uuid_oc=22222222-2222-4222-8222-222222222222
uuid_ws=33333333-3333-4333-8333-333333333333
uuid_wt=44444444-4444-4444-8444-444444444444
underlay=test-wlan0
boot=$(cat /proc/sys/kernel/random/boot_id)
userns=$(readlink /proc/self/ns/user)
netns=$(readlink /proc/self/ns/net)
mntns=$(readlink /proc/self/ns/mnt)

reset_fixture(){
    rm -rf -- "$PUB" "$CTRL" "$ACT" "$OUT" "$WGRT" "$TMP/disconnect" "$TMP/completion" "$KEY"
    mkdir -p "$PUB" "$CTRL" "$ACT" "$OUT"
    printf 'prepare\n' > "$CTRL/prepare-intent"
    printf 'transition\n' > "$CTRL/transition-attempt"
    printf 'activation\n' > "$ACT/attempt"
    printf 'output\n' > "$OUT/attempt"
}
sha(){ sha256sum "$1" | awk '{print $1}'; }

write_active_combined(){
    local d4_hash=$1
    cat > "$PUB/active" <<MARKER
mvc-public-active-v1
state=dual-active-published
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=$uuid_os
ovpn_clone_uuid=$uuid_oc
wg_source_uuid=$uuid_ws
wg_temp_uuid=$uuid_wt
underlay=$underlay
controller_prepare_sha=$(sha "$CTRL/prepare-intent")
controller_transition_sha=$(sha "$CTRL/transition-attempt")
activation_sha=$(sha "$ACT/attempt")
output_sha=$(sha "$OUT/attempt")
d4_intent_sha=$d4_hash
MARKER
}

write_transaction(){
    local state=$1 os=$2 oc=$3 ws=$4 wt=$5 prepare=$6 transition=$7 activation=$8 output=$9 d4=${10}
    cat > "$PUB/transaction" <<MARKER
mvc-public-transaction-v1
state=$state
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=$os
ovpn_clone_uuid=$oc
wg_source_uuid=$ws
wg_temp_uuid=$wt
underlay=$underlay
controller_prepare_sha=$prepare
controller_transition_sha=$transition
activation_sha=$activation
output_sha=$output
d4_intent_sha=$d4
MARKER
}

# 1. Combined recovery may authenticate a public marker after normal teardown
# already retired D4; its marker hash is historical evidence while the retained
# OpenVPN/B2 journals remain live and hash-bound.
reset_fixture
hist_d4=$(printf 'd4-history' | sha256sum | awk '{print $1}')
write_active_combined "$hist_d4"
if mvc_er_parse_active_marker && [[ $MVC_ER_SESSION_MODE == combined && $MVC_ER_D4_STATUS == historical-only ]]; then
    pass 'combined active marker authenticates with historical D4 after WG journal retirement'
else
    fail 'combined historical-D4 marker authentication'
fi

# 2. OpenVPN-only protected transaction authenticates against its four retained
# OpenVPN/B2 journals and requires no D4 evidence.
reset_fixture
write_transaction openvpn-protected "$uuid_os" "$uuid_oc" - - \
  "$(sha "$CTRL/prepare-intent")" "$(sha "$CTRL/transition-attempt")" \
  "$(sha "$ACT/attempt")" "$(sha "$OUT/attempt")" -
if mvc_er_parse_transaction_marker && [[ $MVC_ER_SESSION_MODE == openvpn-only && $MVC_ER_D4_STATUS == not-applicable ]]; then
    pass 'OpenVPN-only retained transaction authenticates read-only'
else
    fail 'OpenVPN-only retained transaction authentication'
fi

# 3. Protected WG recovery requires the live immutable D4 evidence plus the B2
# prepare journal.
reset_fixture
mkdir -p "$WGRT"; printf 'd4-intent\n' > "$WGRT/intent"
write_transaction wireguard-protected - - "$uuid_ws" "$uuid_wt" \
  "$(sha "$CTRL/prepare-intent")" - - - "$(sha "$WGRT/intent")"
if mvc_er_parse_transaction_marker && [[ $MVC_ER_SESSION_MODE == wireguard-protected && $MVC_ER_D4_STATUS == live-authenticated-evidence ]]; then
    pass 'protected WireGuard retained transaction requires authenticated D4 evidence'
else
    fail 'protected WireGuard retained transaction authentication'
fi

# 4. Split WG recovery similarly requires D4 and the exact split lock surface.
reset_fixture
mkdir -p "$WGRT"; printf 'd4-intent\n' > "$WGRT/intent"; : > "$PUB/split.lock"
write_transaction wireguard-split - - "$uuid_ws" "$uuid_wt" - - - - "$(sha "$WGRT/intent")"
if mvc_er_parse_transaction_marker && [[ $MVC_ER_SESSION_MODE == wireguard-split && $MVC_ER_D4_STATUS == live-authenticated-evidence ]]; then
    pass 'split WireGuard retained transaction requires D4 and split-lock evidence'
else
    fail 'split WireGuard retained transaction authentication'
fi

# 5. Journal hash drift is an authentication failure.
reset_fixture
write_transaction openvpn-protected "$uuid_os" "$uuid_oc" - - \
  "$(sha "$CTRL/prepare-intent")" "$(sha "$CTRL/transition-attempt")" \
  "$(sha "$ACT/attempt")" "$(sha "$OUT/attempt")" -
printf 'changed\n' >> "$ACT/attempt"
if ! mvc_er_parse_transaction_marker; then
    pass 'retained journal hash mismatch blocks authentication'
else
    fail 'journal mismatch refusal'
fi

# 6. Same-boot binding is mandatory.
reset_fixture
write_transaction openvpn-protected "$uuid_os" "$uuid_oc" - - \
  "$(sha "$CTRL/prepare-intent")" "$(sha "$CTRL/transition-attempt")" \
  "$(sha "$ACT/attempt")" "$(sha "$OUT/attempt")" -
sed -i 's/^boot=.*/boot=00000000-0000-4000-8000-000000000000/' "$PUB/transaction"
if ! mvc_er_parse_transaction_marker; then
    pass 'wrong-boot retained marker is rejected'
else
    fail 'wrong-boot marker refusal'
fi

# 7. R1 intentionally classifies pre-mutation/partial-start markers as not yet
# finalizable rather than inventing cleanup authority in the first checkpoint.
reset_fixture
write_transaction prepared-before-mutation "$uuid_os" - - - - - - - -
set +e
mvc_er_parse_transaction_marker
rc=$?
set -e
if (( rc == 2 )) && [[ $MVC_ER_PARSE_DETAIL == partial-start-not-supported-r1 ]]; then
    pass 'R1 explicitly defers partial-start recovery finalization'
else
    fail 'partial-start R1 classification'
fi

install_common_classifier_stubs(){
    mvc_er_root_scope(){ return 0; }
    mvc_er_b4_all_absent(){ return 0; }
    mvc_er_fixed_roots_safe(){ return 0; }
    mvc_er_session_not_busy(){ return 0; }
    mvc_er_no_active_vpn_or_tunnel(){ return 0; }
    mvc_er_managed_routes_absent(){ return 0; }
    mvc_er_ipv6_no_default(){ return 0; }
    mvc_er_parse_session_marker(){
        MVC_ER_SESSION_MODE=combined
        MVC_ER_MARKER_KIND=active
        MVC_ER_TRANSACTION_STATE=dual-active-observed
        MVC_ER_OVPN_CLONE_UUID=$uuid_oc
        MVC_ER_WG_TEMP_UUID=$uuid_wt
        MVC_ER_D4_STATUS=historical-only
        return 0
    }
    mvc_er_openvpn_clone_inventory(){ MVC_ER_OVPN_CLONE_STATUS=inactive-authenticated-residue; return 0; }
    mvc_er_wireguard_residue_absent(){ return 0; }
    mkdir -p "$PUB"
}

# 8. An exact inactive authenticated OpenVPN clone is cleanup work for the
# future finalizer, not a reason to reject eligibility.
install_common_classifier_stubs
if mvc_er_finalization_classify && [[ $MVC_ER_REASON == eligible-authenticated-retained-session && $MVC_ER_OVPN_CLONE_STATUS == inactive-authenticated-residue ]]; then
    pass 'inactive authenticated OpenVPN clone remains finalization-eligible'
else
    fail 'inactive OpenVPN clone eligibility'
fi

# 9. B4 must already be absent; the classifier never grants authority to skip
# the emergency disarm phase.
install_common_classifier_stubs
mvc_er_b4_all_absent(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == b4-still-present-or-unreadable ]]; then
    pass 'B4 presence blocks finalization eligibility'
else
    fail 'B4 presence refusal'
fi

# 10. Any active MVC or foreign VPN/tunnel blocks retirement.
install_common_classifier_stubs
mvc_er_no_active_vpn_or_tunnel(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == active-or-foreign-vpn-tunnel-remains ]]; then
    pass 'active or foreign tunnel blocks finalization eligibility'
else
    fail 'active VPN refusal'
fi

# 11. Reserved MVC routing residue blocks retirement.
install_common_classifier_stubs
mvc_er_managed_routes_absent(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == mvc-proto-186-or-187-route-remains ]]; then
    pass 'proto-186/187 residue blocks finalization eligibility'
else
    fail 'managed-route refusal'
fi

# 12. IPv6 default routing remains the same safety boundary adopted in 2.4.4.
install_common_classifier_stubs
mvc_er_ipv6_no_default(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == ipv6-default-route-present-or-unreadable ]]; then
    pass 'IPv6 default route blocks finalization eligibility'
else
    fail 'IPv6-default refusal'
fi

# 13. Retained session authentication failure never falls through to profile
# cleanup eligibility.
install_common_classifier_stubs
mvc_er_parse_session_marker(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == retained-session-marker-authentication-failed ]]; then
    pass 'damaged retained session marker blocks finalization eligibility'
else
    fail 'retained-marker authentication refusal'
fi

# 14. OpenVPN temporary profile identity must be exact when residue remains.
install_common_classifier_stubs
mvc_er_openvpn_clone_inventory(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == openvpn-temporary-profile-identity-ambiguous ]]; then
    pass 'ambiguous OpenVPN clone identity blocks finalization eligibility'
else
    fail 'OpenVPN profile ambiguity refusal'
fi

# 15. WG profile/keyfile residue is still the dual-recovery tool's job and
# blocks finalization until it is gone.
install_common_classifier_stubs
mvc_er_wireguard_residue_absent(){ return 1; }
if ! mvc_er_finalization_classify && [[ $MVC_ER_REASON == wireguard-temporary-residue-remains ]]; then
    pass 'WireGuard residue blocks emergency finalization eligibility'
else
    fail 'WireGuard residue refusal'
fi

# 16. If no live MVC authority exists at all, a clean host is already eligible;
# the classifier does not require an invented recovery marker.
install_common_classifier_stubs
rm -rf -- "$PUB"
mvc_er_fixed_roots_all_absent(){ return 0; }
mvc_er_openvpn_clone_inventory(){ MVC_ER_OVPN_CLONE_STATUS=not-applicable; return 0; }
mvc_er_wireguard_residue_absent(){ return 0; }
if mvc_er_finalization_classify && [[ $MVC_ER_REASON == eligible-already-clean-baseline && $MVC_ER_SESSION_MODE == baseline ]]; then
    pass 'already-clean baseline is eligible without retained session authority'
else
    fail 'already-clean baseline classification'
fi

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
