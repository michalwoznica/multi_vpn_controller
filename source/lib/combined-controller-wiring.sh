#!/usr/bin/env bash
# Multi VPN Controller 2.4.x — minimal public production loader.
# Source this file from tools/mvc only. Sourcing defines functions; it
# does not call live backends or mutate networking.
#
# The physically grounded lifecycle composition is loaded first. The public
# dispatcher is loaded second. Historical/offline controller stacks are not
# production dependencies and intentionally are not sourced here.

[[ -n "${MVC24E_CODE_ROOT:-}" && -d "$MVC24E_CODE_ROOT/lib" ]] || return 1

for mvc24e_module in \
    combined-operational-public-composition \
    combined-controller-entry; do
    [[ -f "$MVC24E_CODE_ROOT/lib/$mvc24e_module.sh" &&
       ! -L "$MVC24E_CODE_ROOT/lib/$mvc24e_module.sh" ]] || return 1
    # shellcheck disable=SC1090
    source "$MVC24E_CODE_ROOT/lib/$mvc24e_module.sh" || return 1
done
unset mvc24e_module

# Production wiring check only. These are the public CLI entrypoints and the
# modern lifecycle coordinators they dispatch to; legacy development entrypoints
# are intentionally not part of the production dependency contract.
for mvc24e_required in \
    mvc24_parse_command \
    mvc24e_dispatch \
    mvc24e_operational_ready \
    mvc24e_c23aw_live_ready \
    mvc24pub_list_readonly \
    mvc24pub_status_readonly \
    mvc24pubc_preflight_readonly \
    mvc24pubc_preflight_openvpn_readonly \
    mvc24gwg_preflight_readonly \
    mvc24pubc_connect_once \
    mvc24pubc_connect_openvpn_once \
    mvc24pubc_connect_wireguard_protected_once \
    mvc24pubd_disconnect_once \
    mvc24gco_start_once \
    mvc24gco_stop_once \
    mvc24gco_complete_once \
    mvc24gd4_start_once \
    mvc24gd4_stop_once \
    mvc24gwg_start_once \
    mvc24gwg_stop_once; do
    declare -F -- "$mvc24e_required" >/dev/null || return 1
done
unset mvc24e_required
