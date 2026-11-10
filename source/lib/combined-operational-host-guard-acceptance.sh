#!/usr/bin/env bash
# Gate B4: local-operator-only maintenance acceptance of B2/B3 host quarantine.
# Must be sourced AFTER the B2 and B3 libraries; not imported by public vpn.
# This is NOT an active VPN firewall transition and grants NO A3 authority.

ubs24gb4_reset() {
    UBS24GB4_OPERATION=none
    UBS24GB4_APPROVAL=none
    UBS24GB4_ATTEMPTED=no
}

ubs24gb4_scope() {
    (( $# == 0 )) || return 1
    # TTY is not a proof of physical-host ownership. Block common remote shells.
    [[ -t 0 && -t 1 && -z ${SSH_CONNECTION:-} && -z ${SSH_TTY:-} ]] || return 1
    ubs24gb2_root_scope
}

ubs24gb4_no_active_vpn() {
    (( $# == 0 )) || return 1
    # Acceptance operates only with all VPNs stopped, including unmanaged ones.
    local active wg_interfaces links nm_type pgrep_status
    command -v nmcli >/dev/null && command -v wg >/dev/null &&
      command -v pgrep >/dev/null && command -v jq >/dev/null &&
      command -v ip >/dev/null || return 1
    active=$(nmcli -t -f TYPE connection show --active) || return 1
    [[ -n $active ]] || return 1
    while IFS= read -r nm_type; do
        case ${nm_type,,} in
            vpn|wireguard|tun|tap|ppp) return 1 ;;
            ethernet|wifi|802-3-ethernet|802-11-wireless|loopback|bridge|vlan|bond|dummy) ;;
            *) return 1 ;;
        esac
    done <<< "$active"
    wg_interfaces=$(wg show interfaces) || return 1
    [[ -z $wg_interfaces ]] || return 1
    links=$(ip -j -d link show) || return 1
    jq -e 'type=="array" and all(.[];
      (.ifname|type)=="string" and
      ((.ifname | test("^(tun|tap|wg)([0-9_.-]|$)"))|not) and
      ((.linkinfo.info_kind // "") | IN("wireguard","tun","tap","vti","vti6","ipip","sit","gre","gretap","ip6tnl")|not))' \
      <<< "$links" >/dev/null 2>&1 || return 1
    if pgrep -x openvpn >/dev/null 2>&1; then return 1; else
        pgrep_status=$?
        (( pgrep_status == 1 )) || return 1
    fi
    if pgrep -x wireguard-go >/dev/null 2>&1; then return 1; else
        pgrep_status=$?
        (( pgrep_status == 1 )) || return 1
    fi
}

ubs24gb4_underlay() {
    (( $# == 0 )) || return 1
    local iface
    iface=$(ip -j -4 route show table all | jq -er '
        [.[] | select(.dst == "default")] as $d |
        if ($d|length)==1 and ($d[0].dev|type)=="string" then $d[0].dev else empty end') || return 1
    ubs24gb1_valid_ifname "$iface" || return 1
    printf '%s\n' "$iface"
}

ubs24gb4_confirm() {
    (( $# == 1 )) || return 1
    local expected=$1 entered=''
    [[ -r /dev/tty && -w /dev/tty ]] || return 1
    printf '\nThis will change your REAL HOST nftables firewall.\n' > /dev/tty
    printf 'It can immediately disconnect network access, including SSH.\n' > /dev/tty
    printf 'A local recovery terminal is essential. No automatic fail-open recovery.\n' > /dev/tty
    printf 'Type exactly: %s\n> ' "$expected" > /dev/tty
    IFS= read -r entered < /dev/tty || return 1
    [[ $entered == "$expected" ]]
}

# B3 calls this exactly once before disarm, with an already-held B2 lock.
ubs24gb4_disarm_witness() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GB4_OPERATION:-} == release &&
       ${UBS24GB4_APPROVAL:-} == release-once ]] || return 1
    UBS24GB4_APPROVAL=consumed
    ubs24gb4_scope && ubs24gb4_no_active_vpn && ubs24gb2_lock_valid
}

ubs24gb4_install() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GB4_ATTEMPTED:-no} == no ]] || return 1
    UBS24GB4_ATTEMPTED=yes
    UBS24GB4_OPERATION=install
    UBS24GB4_APPROVAL=none
    local iface confirmed_iface
    ubs24gb4_scope && ubs24gb4_no_active_vpn || return 1
    [[ ! -e /run/ubs-v240-controller && ! -L /run/ubs-v240-controller ]] || return 1
    iface=$(ubs24gb4_underlay) || return 1
    ubs24gb4_confirm 'INSTALL UBS V240 DENY ALL' || return 1
    # Recheck immediately before calling the one-shot B2 transaction.
    ubs24gb4_scope && ubs24gb4_no_active_vpn || return 1
    confirmed_iface=$(ubs24gb4_underlay) || return 1
    [[ $iface == "$confirmed_iface" ]] || return 1
    ubs24gb2_install_once "$iface" "$UBS24GB4_POLICY" || return 1
    [[ ${UBS24GB2_STAGE:-} == host-deny-all-attested-observation-only &&
       ${UBS24GB2_AUTHORITY:-} == none ]] || return 1
}

ubs24gb4_release() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GB4_ATTEMPTED:-no} == no ]] || return 1
    UBS24GB4_ATTEMPTED=yes
    UBS24GB4_OPERATION=release
    UBS24GB4_APPROVAL=none
    ubs24gb4_scope && ubs24gb4_no_active_vpn || return 1
    ubs24gb2_reopen || return 1
    [[ ${UBS24GB2_STAGE:-} == host-deny-all-attested-observation-only ]] || return 1
    ubs24gb4_confirm 'RELEASE UBS V240 DENY ALL' || return 1
    ubs24gb4_scope && ubs24gb4_no_active_vpn || return 1
    UBS24GB4_APPROVAL=release-once
    ubs24gb3_release_once || return 1
    [[ ${UBS24GB3_STAGE:-} == explicit-disarm-verified-owned-runtime-retired &&
       ${UBS24GB3_AUTHORITY:-} == none ]] || return 1
}

ubs24gb4_status() {
    (( $# == 0 )) || return 1
    ubs24gb2_root_scope || return 1
    ubs24gb2_reopen || return 1
    [[ ${UBS24GB2_STAGE:-} == host-deny-all-attested-observation-only ]] || return 1
}

# B4 does not authorise any tunnel activity or guard policy transition.
ubs24gb4_authorize_clone() { return 1; }
ubs24gb4_authorize_activation() { return 1; }
ubs24gb4_authorize_recovery() { return 1; }
ubs24gb4_authorize_policy_transition() { return 1; }
