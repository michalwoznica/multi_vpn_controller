#!/usr/bin/env bash
# C23AT — public v2.4 definition loader for the physically proven composition.
# Sourcing this file defines functions only. It grants no mutation authority.

[[ -n ${UBS24E_CODE_ROOT:-} && -d $UBS24E_CODE_ROOT/lib ]] || return 1

# C23AY: C4's mature read-only OpenVPN admission deliberately binds its
# recovery-script identity and saved-profile preview to an explicit source
# root. Private local-console drivers set this themselves; the public loader
# must do the same rather than trusting an inherited environment value.
UBS24GC4_SOURCE_ROOT=$UBS24E_CODE_ROOT

ubs24pub_openvpn_manifest_before_final() {
    cat <<'MANIFEST'
dual-session
wireguard-peers
combined-routing-guard
combined-dbus-gdbus-portable
combined-dbus-gdbus-settings
combined-protected-dns
combined-activation-v2-openvpn-host-dns-evidence
combined-operational-nm-owner-identity
combined-operational-ovpn-remote-candidate-plan
combined-operational-ovpn-derivative-preview
combined-operational-preclone-quarantine-offline
combined-operational-host-guard-plan
combined-operational-host-guard-transaction
combined-operational-host-guard-acceptance
combined-operational-ovpn-native-clone-adapter
combined-operational-ovpn-temporary-harden
combined-operational-ovpn-guarded-prepare
combined-operational-c1-bootstrap-transition
combined-operational-c2-identity-binding
combined-operational-c3-held-lifecycle
combined-operational-c5-openvpn-activation
combined-operational-c6-active-tunnel-observation
combined-operational-c7-sameboot-activation-reconciliation
combined-operational-c8-credential-custody-preflight
combined-operational-c14-nm-native-custody
combined-operational-c9-held-activation-sequence
combined-operational-c11-tunnel-egress-candidate
combined-operational-c16-protected-dns-acceptance
combined-operational-c18-precommit-dns-gate
combined-operational-c13-journalled-output-commit
combined-operational-c15-output-reattachment
combined-operational-c17-held-openvpn-vertical
combined-operational-c19-protected-openvpn-stop
combined-operational-c23t-session-finalize
MANIFEST
}


# Fixed production runtime root for the public same-boot lifecycle. Production
# code never reads an inherited environment variable for this path. Tests may
# override this function in their own process after sourcing the composition.
ubs24pub_session_runtime_root() { printf '%s\n' /run/mvc-public-session; }
ubs24pub_wireguard_runtime_root() { printf '%s\n' /run/mvc-wireguard; }

ubs24pub_source_module() {
    (( $# == 1 )) || return 1
    local module=$1
    [[ $module =~ ^[a-z0-9-]+$ && -f $UBS24E_CODE_ROOT/lib/$module.sh &&
       ! -L $UBS24E_CODE_ROOT/lib/$module.sh ]] || return 1
    # shellcheck disable=SC1090
    source "$UBS24E_CODE_ROOT/lib/$module.sh"
}

# Reproduce accept-v240-dual-session-c23ar-local.sh's proven source ordering.
# The private wrapper sources C4/preflight/NM backend immediately before the
# final composition file, so the final composition's admission witnesses win.
while IFS= read -r ubs24pub_module; do
    [[ -n $ubs24pub_module ]] || continue
    ubs24pub_source_module "$ubs24pub_module" || return 1
done < <(ubs24pub_openvpn_manifest_before_final)
unset ubs24pub_module

for ubs24pub_module in \
    combined-operational-c4-local-admission \
    combined-preflight \
    combined-networkmanager-backend \
    combined-operational-openvpn-composition \
    combined-operational-d2-wireguard-semantic-readonly \
    combined-operational-d3-wireguard-parallel-plan \
    combined-operational-d4-wireguard-parallel-live \
    combined-operational-wireguard-protected-v240 \
    combined-operational-wireguard-split-v240 \
    combined-operational-public-v240-reconcile \
    combined-operational-public-v240-openvpn-early-reconcile \
    combined-operational-public-v240-readonly \
    combined-operational-public-v240-connect \
    combined-operational-public-v240-disconnect; do
    ubs24pub_source_module "$ubs24pub_module" || return 1
done
unset ubs24pub_module

for ubs24pub_required in \
    ubs24gco_start_once ubs24gco_stop_once ubs24gco_complete_once \
    ubs24gd2_assess_saved_profile ubs24gd4_start_once ubs24gd4_stop_once \
    ubs24gwg_preflight_readonly ubs24gwg_start_once ubs24gwg_stop_once \
    ubs24gws_preflight_readonly ubs24pubc_connect_wireguard_split_once ubs24gws_stop_once \
    ubs24pubr_reconcile_partial_d4_to_openvpn_hold ubs24pubr_reconcile_d4_to_c11_hold_openvpn_absent \
    ubs24pubr_published_wg_absent_observed ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold \
    ubs24pube_reconcile_incomplete_start_locked \
    ubs24pub_saved_profile_kind ubs24pub_bind_openvpn_name ubs24pub_bind_combined_names ubs24pub_list_readonly ubs24pub_status_readonly \
    ubs24pubc_connect_openvpn_once ubs24pubc_connect_once ubs24pubc_publish_active_session \
    ubs24pubd_disconnect_once ubs24pubd_parse_active_marker; do
    declare -F "$ubs24pub_required" >/dev/null || return 1
done
unset ubs24pub_required

# Explicit fresh-process initialization boundary for the public controller.
# C23AR physically proved the core only when its wrapper reset every loaded
# stage before admission. The public CLI must provide the same guarantee rather
# than relying on source-time defaults or a previous caller's incidental state.
ubs24pub_process_initialize() {
    (( $# == 0 )) || return 1
    local reset
    for reset in \
        ubs24gb1_reset ubs24gb2_reset ubs24gb4_reset \
        ubs24ga_reset ubs24ga2_reset ubs24ga3_reset \
        ubs24gc1_reset ubs24gc3_reset ubs24gc4_reset ubs24gc5_reset ubs24gc6_reset \
        ubs24gc7_reset ubs24gc8_reset ubs24gc14_reset ubs24gc9_reset ubs24gc11_reset \
        ubs24gc13_reset ubs24gc15_reset ubs24gc16_reset ubs24gc17_reset ubs24gc18_reset \
        ubs24gc19_reset ubs24gc23t_reset ubs24gco_reset \
        ubs24gd2_reset ubs24gd3_reset ubs24gd4_reset ubs24gwg_reset ubs24gws_reset ubs24pubr_reset ubs24pube_reset \
        ubs24op_candidate_reset ubs24op_preview_reset ubs24op_qg_reset \
        ubs24pub_reset ubs24pubc_reset ubs24pubd_reset; do
        declare -F "$reset" >/dev/null || return 1
        "$reset" || return 1
    done

    # Reset functions deliberately clear mutable stage state, not trusted code
    # provenance. Rebind C4 to this exact packaged source tree every time.
    UBS24GC4_SOURCE_ROOT=$UBS24E_CODE_ROOT

    [[ ${UBS24GD4_TEMP_NAME:-} == vpnks-wg &&
       ${UBS24GD4_RUNTIME:-} == /run/mvc-wireguard &&
       ${UBS24PUBC_STAGE:-} == idle && ${UBS24PUBD_STAGE:-} == idle ]]
}
