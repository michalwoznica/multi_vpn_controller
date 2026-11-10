#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 — minimal public production loader.
# Source this file from tools/vpn-v240 only. Sourcing defines functions; it
# does not call live backends or mutate networking.
#
# The physically grounded lifecycle composition is loaded first. The public
# dispatcher is loaded second. Historical/offline controller stacks are not
# production dependencies and intentionally are not sourced here.

[[ -n "${UBS24E_CODE_ROOT:-}" && -d "$UBS24E_CODE_ROOT/lib" ]] || return 1

for ubs24e_module in \
    combined-operational-public-v240-composition \
    combined-controller-entry; do
    [[ -f "$UBS24E_CODE_ROOT/lib/$ubs24e_module.sh" &&
       ! -L "$UBS24E_CODE_ROOT/lib/$ubs24e_module.sh" ]] || return 1
    # shellcheck disable=SC1090
    source "$UBS24E_CODE_ROOT/lib/$ubs24e_module.sh" || return 1
done
unset ubs24e_module

# Production wiring check only. These are the public CLI entrypoints and the
# modern lifecycle coordinators they dispatch to; legacy development entrypoints
# are intentionally not part of the production dependency contract.
for ubs24e_required in \
    ubs24_parse_command \
    ubs24e_dispatch \
    ubs24e_operational_ready \
    ubs24e_c23aw_live_ready \
    ubs24pub_list_readonly \
    ubs24pub_status_readonly \
    ubs24pubc_preflight_readonly \
    ubs24pubc_preflight_openvpn_readonly \
    ubs24gwg_preflight_readonly \
    ubs24pubc_connect_once \
    ubs24pubc_connect_openvpn_once \
    ubs24pubc_connect_wireguard_protected_once \
    ubs24pubd_disconnect_once \
    ubs24gco_start_once \
    ubs24gco_stop_once \
    ubs24gco_complete_once \
    ubs24gd4_start_once \
    ubs24gd4_stop_once \
    ubs24gwg_start_once \
    ubs24gwg_stop_once; do
    declare -F -- "$ubs24e_required" >/dev/null || return 1
done
unset ubs24e_required
