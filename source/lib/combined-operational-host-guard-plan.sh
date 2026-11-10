#!/usr/bin/env bash
# Release Gate B1 — production-targeted, READ-ONLY quarantine batch preparation.
# Never commits nftables, touches NetworkManager, or grants A3 guard authority.
# F14 source policy + exactly one operator-designated route-referenced lowerdev.
# The result is an untrusted plan, NOT proof of complete namespace/physical coverage.

mvc24gb1_reset() {
    MVC24GB1_STAGE=blocked
    MVC24GB1_AUTHORITY=none
}

mvc24gb1_valid_ifname() {
    (( $# == 1 )) && [[ $1 =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$ &&
        $1 != lo && $1 != tun* && $1 != wg* ]]
}

mvc24gb1_scope() {
    (( $# == 0 )) || return 1
    [[ $EUID == 0 && $(stat -f -c %T /run) == tmpfs &&
       ! -e /run/mvc-controller && ! -L /run/mvc-controller ]] || return 1
    # Scope is PID1-relative, NOT cryptographic physical-host ownership.
    [[ $(readlink /proc/self/ns/net) == "$(readlink /proc/1/ns/net)" &&
       $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || return 1
    # Reject mapped root in a user namespace, including the disposable F30 lab.
    [[ $(awk '{print $1 ":" $2 ":" $3}' /proc/self/uid_map) == '0:0:4294967295' ]]
}

mvc24gb1_routes_valid() {
    (( $# == 3 )) || return 1
    local iface=$1 routes4=$2 routes6=$3
    mvc24gb1_valid_ifname "$iface" || return 1
    [[ -f $routes4 && ! -L $routes4 && -f $routes6 && ! -L $routes6 ]] || return 1
    # All routing tables, rather than only `main`. Narrow supported topology:
    # exactly one IPv4 default and no IPv6 default at preparation time.
    jq -e --arg i "$iface" '
      type == "array" and
      ([.[] | select(.dst == "default")] | length) == 1 and
      ([.[] | select(.dst == "default")] | .[0] |
        .dev == $i and ((.type // "unicast") == "unicast") and
        (has("nexthops") | not) and (has("nhid") | not))
    ' "$routes4" >/dev/null 2>&1 || return 1
    jq -e 'type == "array" and all(.[]; .dst != "default")' \
        "$routes6" >/dev/null 2>&1
}

mvc24gb1_links_valid() {
    (( $# == 2 )) || return 1
    local iface=$1 links=$2
    [[ -f $links && ! -L $links ]] && mvc24gb1_valid_ifname "$iface" || return 1
    jq -e --arg i "$iface" '
        type == "array" and
        ([.[] | select(.ifname == $i)] | length) == 1 and
        ([.[] | select(.ifname == $i)] | .[0].ifindex | type == "number") and
        all(.[]; (.linkinfo.info_kind // "") as $k |
          $k != "macvlan" and $k != "ipvlan")
    ' "$links" >/dev/null 2>&1
}

mvc24gb1_render() {
    (( $# == 3 )) || return 1
    local iface=$1 reference=$2 dest=$3
    mvc24gb1_valid_ifname "$iface" || return 1
    [[ -f $reference && ! -L $reference && -f $dest && ! -L $dest &&
       ! -s $dest && -O $dest && $(stat -c '%a:%h' -- "$dest") == 600:1 ]] || return 1
    # Pin known F14 semantics. A modified reference must be explicitly reviewed.
    [[ $(sha256sum "$reference" | cut -d' ' -f1) == \
       b2e817bf3f22853502f547feef07923e2c4ee5449e520cef6c72189611bd7b03 ]] || return 1
    local -a lines=()
    mapfile -t lines < <(grep '^add ' "$reference") || return 1
    (( ${#lines[@]} == 5 )) || return 1
    {
        printf '%s\n' "${lines[@]}"
        printf '%s\n' 'add table netdev mvc_preclone_underlay'
        printf 'add chain netdev mvc_preclone_underlay lowerdev_deny { type filter hook egress device "%s" priority -310; policy drop; }\n' "$iface"
        # DHCP client continuity only. This narrow exception permits the host to
        # renew/reacquire IPv4 after an underlay flap while ordinary physical
        # egress remains denied. Replies are ingress and are not blocked here.
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$iface"
        printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
    } > "$dest" || return 1
    [[ $(grep -c '^add ' "$dest") == 9 ]]
}

mvc24gb1_capture_nft() { (( $# == 1 )) && nft -j -n -s list ruleset > "$1"; }
mvc24gb1_capture_links() { (( $# == 1 )) && ip -j -d link show > "$1"; }
mvc24gb1_capture_routes4() { (( $# == 1 )) && ip -j -4 route show table all > "$1"; }
mvc24gb1_capture_routes6() { (( $# == 1 )) && ip -j -6 route show table all > "$1"; }

mvc24gb1_plan_once() {
    (( $# == 3 )) || return 1
    mvc24gb1_reset
    local iface=$1 reference=$2 scratch=$3 file
    [[ ${MVC24GB1_ATTEMPTED:-no} == no ]] || return 1
    MVC24GB1_ATTEMPTED=yes
    mvc24gb1_scope && mvc24gb1_valid_ifname "$iface" || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c '%a:%h' "$scratch") == 700:2 ]] || return 1
    for file in nft1 nft2 links1 links2 route4a route4b route6a route6b batch; do
        (umask 077; set -C; : > "$scratch/$file") || return 1
        [[ $(stat -c '%a:%h' "$scratch/$file") == 600:1 ]] || return 1
    done
    # Capture before the check, and independently capture again after it.
    mvc24gb1_capture_nft "$scratch/nft1" &&
      mvc24gb1_capture_links "$scratch/links1" &&
      mvc24gb1_capture_routes4 "$scratch/route4a" &&
      mvc24gb1_capture_routes6 "$scratch/route6a" || return 1
    declare -F mvc24op_qg_preflight_snapshot >/dev/null || return 1
    mvc24op_qg_preflight_snapshot "$scratch/nft1" || return 1
    jq -e '[(.nftables[] | .table? | select(.family=="netdev" and .name=="mvc_preclone_underlay"))] | length==0' \
      "$scratch/nft1" >/dev/null 2>&1 || return 1
    mvc24gb1_links_valid "$iface" "$scratch/links1" &&
      mvc24gb1_routes_valid "$iface" "$scratch/route4a" "$scratch/route6a" || return 1
    mvc24gb1_render "$iface" "$reference" "$scratch/batch" || return 1
    # Read-only syntax/kernel acceptability check; NOT an nft commit.
    nft --check --file "$scratch/batch" >/dev/null 2>&1 || return 1
    mvc24gb1_capture_nft "$scratch/nft2" &&
      mvc24gb1_capture_links "$scratch/links2" &&
      mvc24gb1_capture_routes4 "$scratch/route4b" &&
      mvc24gb1_capture_routes6 "$scratch/route6b" || return 1
    for file in 'nft1 nft2' 'links1 links2' 'route4a route4b' 'route6a route6b'; do
        local a b
        read -r a b <<< "$file"
        cmp -s "$scratch/$a" "$scratch/$b" || return 1
    done
    mvc24op_qg_preflight_snapshot "$scratch/nft2" &&
      mvc24gb1_links_valid "$iface" "$scratch/links2" &&
      mvc24gb1_routes_valid "$iface" "$scratch/route4b" "$scratch/route6b" || return 1
    MVC24GB1_STAGE=production-batch-prechecked-readonly-no-authority
    MVC24GB1_AUTHORITY=none
}

mvc24gb1_authorize_install() { return 1; }
mvc24gb1_authorize_clone() { return 1; }
mvc24gb1_authorize_activation() { return 1; }
mvc24gb1_authorize_cleanup() { return 1; }
mvc24gb1_authorize_recovery() { return 1; }
mvc24gb1_authorize_disarm() { return 1; }
