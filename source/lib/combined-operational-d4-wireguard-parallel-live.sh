#!/usr/bin/env bash
# C23AI D4 — PRIVATE operational WireGuard stage layered on the physically
# proven C23AE OpenVPN protected-running state.
#
# This is NOT part of the public vpn-v240 CLI. Authority is admitted only by
# the dedicated local-console C23AI driver after C23U has established the
# protected OpenVPN state under the genuine B2 lock.
#
# First vertical only:
#   * exactly one saved WG peer;
#   * one WG IPv4 source address;
#   * hostname or numeric IPv4 peer endpoint;
#   * RFC1918 IPv4 AllowedIPs, derived from the selected profile;
#   * one temporary root-only NetworkManager keyfile named vpnks-wg;
#   * one owned endpoint /32 route, proto 186 metric 4240;
#   * WG transport direct over the physical underlay;
#   * OpenVPN remains the ordinary/default Internet owner.
#
# Mutation ordering is deliberate:
#   prepare/load pinned profile -> add owned /32 route -> extend guard -> WG up.
# The route is installed while the pure C23AE guard still blocks physical WG
# traffic, so there is no WG-over-OpenVPN activation window.
#
# Normal teardown:
#   install profile-derived private unreachable hold routes -> WG down -> prove
#   down -> restore exact C23AE guard -> delete owned endpoint route -> delete
#   temporary WG profile -> C19 stops OpenVPN -> remove private hold routes.
# The hold routes prevent selected WG destinations from falling back through
# OpenVPN during the D4 -> C19 handoff.
#
# No blind mutation retry is performed after an ambiguous nft/NM/ip outcome.

ubs24gd4_reset() {
    UBS24GD4_STAGE=idle
    UBS24GD4_DETAIL=none
    UBS24GD4_ATTEMPTED=no
    UBS24GD4_RUNTIME=/run/ubs-v240-wireguard
    UBS24GD4_TEMP_NAME=vpnks-wg
    UBS24GD4_TEMP_UUID=
    UBS24GD4_TEMP_FILE=/run/NetworkManager/system-connections/vpnks-wg.nmconnection
    UBS24GD4_SOURCE_UUID=
    UBS24GD4_SOURCE_FILE=
    UBS24GD4_SOURCE_SHA=
    UBS24GD4_WG_SOURCE=
    UBS24GD4_ENDPOINT_IP=
    UBS24GD4_ENDPOINT_PORT=
    UBS24GD4_UNDERLAY=
    UBS24GD4_UNDERLAY_SOURCE=
    UBS24GD4_UNDERLAY_GATEWAY=
    UBS24GD4_ALLOWED_IPS=()
    UBS24GD4_NM_UP_EXIT_STATUS=unset
    UBS24GD4_NM_DOWN_EXIT_STATUS=unset
    UBS24GD4_HOLD_PROTO=187
    UBS24GD4_HOLD_METRIC=4241
}

ubs24gd4_authority_witness() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCU_AUTHORITY:-none} == private-local-console &&
       ${UBS24GCU_APPROVAL:-none} == approved-process-local &&
       ${UBS24GCU_OPERATION:-none} == session &&
       ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
       ${UBS24GCO_AUTHORITY:-none} == private-local-console &&
       ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
       ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid || return 1
    ubs24gcu_live_admission_witness || return 1
}

ubs24gd4_dependencies() {
    local cmd
    for cmd in awk chmod cmp find getent grep ip jq mktemp mv nft nmcli readlink rm rmdir sha256sum stat wg; do
        command -v "$cmd" >/dev/null 2>&1 || return 1
    done
}

ubs24gd4_hash_file() {
    (( $# == 1 )) || return 1
    local file=$1 hash tail
    [[ -f $file && ! -L $file ]] || return 1
    read -r hash tail < <(sha256sum -- "$file") || return 1
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

ubs24gd4_private_runtime_absent() {
    [[ ! -e ${UBS24GD4_RUNTIME:-/run/ubs-v240-wireguard} &&
       ! -L ${UBS24GD4_RUNTIME:-/run/ubs-v240-wireguard} ]]
}

ubs24gd4_temp_profile_absent() {
    local name=${UBS24GD4_TEMP_NAME:-vpnks-wg} rows
    [[ ! -e ${UBS24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} &&
       ! -L ${UBS24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} ]] || return 1
    rows=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE connection show 2>/dev/null) || return 1
    ! awk -F: -v n="$name" '$1==n {found=1} END{exit(found?0:1)}' <<< "$rows"
}

ubs24gd4_write_marker() {
    (( $# == 1 )) || return 1
    local name=$1 dir=${UBS24GD4_RUNTIME:-}
    [[ $name =~ ^[a-z0-9-]+$ && -d $dir && ! -L $dir && -O $dir &&
       $(stat -c '%a' -- "$dir") == 700 ]] || return 1
    [[ ! -e $dir/$name && ! -L $dir/$name ]] || return 1
    (umask 077; set -C; printf '%s\n' "state=$name" > "$dir/$name") || return 1
    chmod 400 -- "$dir/$name"
}

ubs24gd4_publish_intent() {
    (( $# == 0 )) || return 1
    local dir=${UBS24GD4_RUNTIME:-} tmp boot userns netns mntns allowed
    ubs24gd4_authority_witness || return 1
    [[ $(stat -f -c %T /run) == tmpfs &&
       -n ${UBS24GD4_SOURCE_UUID:-} && -n ${UBS24GD4_SOURCE_FILE:-} &&
       -n ${UBS24GD4_SOURCE_SHA:-} && -n ${UBS24GD4_TEMP_UUID:-} &&
       -n ${UBS24GD4_WG_SOURCE:-} && -n ${UBS24GD4_ENDPOINT_IP:-} &&
       -n ${UBS24GD4_ENDPOINT_PORT:-} && -n ${UBS24GD4_UNDERLAY:-} &&
       -n ${UBS24GD4_UNDERLAY_SOURCE:-} && -n ${UBS24GD4_UNDERLAY_GATEWAY:-} &&
       ${#UBS24GD4_ALLOWED_IPS[@]} -ge 1 ]] || return 1
    ubs24gd4_private_runtime_absent || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    allowed=$(IFS=';'; printf '%s;' "${UBS24GD4_ALLOWED_IPS[*]}") || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.intent.XXXXXXXX") || return 1
    if ! printf '%s\n' \
        ubs-v240-c23ai-wireguard-intent-v1 \
        state=prepared-no-wireguard-mutation-yet \
        "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
        "source_uuid=$UBS24GD4_SOURCE_UUID" "source_sha=$UBS24GD4_SOURCE_SHA" \
        "temp_name=$UBS24GD4_TEMP_NAME" "temp_uuid=$UBS24GD4_TEMP_UUID" \
        "wg_source=$UBS24GD4_WG_SOURCE" \
        "endpoint=$UBS24GD4_ENDPOINT_IP:$UBS24GD4_ENDPOINT_PORT" \
        "underlay=$UBS24GD4_UNDERLAY|source=$UBS24GD4_UNDERLAY_SOURCE|gateway=$UBS24GD4_UNDERLAY_GATEWAY" \
        "allowedips=$allowed" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/intent" || return 1
    UBS24GD4_STAGE=intent-published-no-wireguard-mutation-yet
}


# Live C23AI guard candidate adds one property beyond the non-admitting D3
# preview: every selected WG private prefix is explicitly DROPPED on the
# OpenVPN tunnel before the ordinary OpenVPN accept. This prevents a private
# destination from falling back through OpenVPN while WG routes are not yet
# installed or are being removed. Private destinations are therefore either
# on vpnks-wg or fail-closed.
ubs24gd4_write_parallel_guard_candidate() {
    (( $# >= 11 )) || return 1
    local underlay=$1 underlay_source=$2 ovpn_ip=$3 ovpn_port=$4
    local ovpn_tunnel=$5 ovpn_source=$6 wg_tunnel=$7 wg_source=$8 wg_ip=$9 wg_port=${10} out=${11}
    shift 11
    local prefix
    ubs24gd3_guard_parameters "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port" \
      "$ovpn_tunnel" "$ovpn_source" "$wg_tunnel" "$wg_source" "$wg_ip" "$wg_port" "$@" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out && $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    {
      printf '%s\n' 'flush chain inet vpn_v240_preclone_quarantine output_deny'
      printf '%s\n' 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "lo" accept'
      printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$underlay"
      printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay" "$underlay_source" "$wg_ip" "$wg_port"
      for prefix in "$@"; do
        printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s drop\n' \
          "$ovpn_tunnel" "$ovpn_source" "$prefix"
      done
      printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' \
        "$ovpn_tunnel" "$ovpn_source"
      for prefix in "$@"; do
        printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s accept\n' \
          "$wg_tunnel" "$wg_source" "$prefix"
      done
      printf '%s\n' 'flush chain netdev vpn_v240_preclone_underlay lowerdev_deny'
      printf '%s\n' 'add rule netdev vpn_v240_preclone_underlay lowerdev_deny ether type arp accept'
      printf '%s\n' 'add rule netdev vpn_v240_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
      printf 'add rule netdev vpn_v240_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule netdev vpn_v240_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay_source" "$wg_ip" "$wg_port"
    } > "$out"
}

# Canonical exact verifier for the C23AI parallel guard candidate. It checks
# only the three controller-owned tables and requires their complete shape;
# foreign table preservation is checked separately against B2 prestate.
ubs24gd4_parallel_guard_observation() {
    (( $# >= 12 )) || return 1
    local file=$1 underlay=$2 underlay_source=$3 ovpn_ip=$4 ovpn_port=$5
    local ovpn_tunnel=$6 ovpn_source=$7 wg_tunnel=$8 wg_source=$9 wg_ip=${10} wg_port=${11}
    shift 11
    local prefixes_json
    [[ -f $file && ! -L $file ]] || return 1
    ubs24gd3_guard_parameters "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port" \
      "$ovpn_tunnel" "$ovpn_source" "$wg_tunnel" "$wg_source" "$wg_ip" "$wg_port" "$@" || return 1
    prefixes_json=$(printf '%s\n' "$@" | jq -R -s 'split("\n")|map(select(length>0))') || return 1
    jq -e --arg iface "$underlay" --arg src "$underlay_source" \
      --arg od "$ovpn_ip" --argjson op "$ovpn_port" --arg ot "$ovpn_tunnel" --arg os "$ovpn_source" \
      --arg wd "$wg_ip" --argjson wp "$wg_port" --arg wt "$wg_tunnel" --arg ws "$wg_source" \
      --argjson prefixes "$prefixes_json" '
      def m($l;$r): {match:{op:"==",left:$l,right:$r}};
      def meta($k): {meta:{key:$k}};
      def pay($p;$f): {payload:{protocol:$p,field:$f}};
      def ipv4dep:
        . == m(meta("nfproto");"ipv4") or . == m(meta("nfproto");"ip") or
        . == m(pay("ether";"type");"ip") or . == m(pay("ether";"type");2048);
      def tcpdep:
        . == m(meta("l4proto");"tcp") or . == m(pay("ip";"protocol");"tcp") or . == m(pay("ip";"protocol");6);
      def udpdep:
        . == m(meta("l4proto");"udp") or . == m(pay("ip";"protocol");"udp") or . == m(pay("ip";"protocol");17);
      def dep: ipv4dep or tcpdep or udpdep;
      def core: [ .[] | select(dep|not) ];
      def proto_ok($expr;$proto):
        all($expr[]; if tcpdep then $proto=="tcp" elif udpdep then $proto=="udp" else true end);
      def rhs($cidr): ($cidr|split("/")) as $p |
        if ($p[1]|tonumber)==32 then $p[0]
        else {prefix:{addr:$p[0],len:($p[1]|tonumber)}} end;
      def owned($v): ($v|type=="object") and
        (($v.family=="inet" and ($v.table // $v.name // "")=="vpn_v240_preclone_quarantine") or
         ($v.family=="bridge" and ($v.table // $v.name // "")=="vpn_v240_preclone_bridge") or
         ($v.family=="netdev" and ($v.table // $v.name // "")=="vpn_v240_preclone_underlay"));
      def chain($f;$t;$n): [.nftables[]|.chain?|select(.family==$f and .table==$t and .name==$n)];
      def rules($f;$t;$n): [.nftables[]|.rule?|select(.family==$f and .table==$t and .chain==$n)|.expr];
      def arp($v):
        $v == [m(pay("ether";"type");"arp"),{accept:null}] or
        $v == [m(pay("ether";"type");2054),{accept:null}] or
        $v == [m(pay("ether";"type");1544),{accept:null}];
      ([ $prefixes[] | "rule", "rule" ]) as $wg_rule_keys |
      ([.nftables[]|to_entries[]|select(.key!="metainfo" and owned(.value))|.key]|sort)==
        ((["table","table","table","chain","chain","chain","chain",
           "rule","rule","rule","rule","rule","rule","rule","rule","rule"] + $wg_rule_keys)|sort) and
      ([.nftables[]|.chain?|select(owned(.))|[.family,.table,.name]]|sort)==
        ([ ["inet","vpn_v240_preclone_quarantine","output_deny"],
           ["inet","vpn_v240_preclone_quarantine","forward_deny"],
           ["bridge","vpn_v240_preclone_bridge","forward_deny"],
           ["netdev","vpn_v240_preclone_underlay","lowerdev_deny"] ]|sort) and
      ([.nftables[]|.table?|select(owned(.))|[.family,.name]]|sort)==
        ([ ["inet","vpn_v240_preclone_quarantine"], ["bridge","vpn_v240_preclone_bridge"],
           ["netdev","vpn_v240_preclone_underlay"] ]|sort) and
      (chain("inet";"vpn_v240_preclone_quarantine";"output_deny")|length)==1 and
      (chain("inet";"vpn_v240_preclone_quarantine";"output_deny")[0]|
        .hook=="output" and .prio==-310 and .policy=="drop") and
      (chain("inet";"vpn_v240_preclone_quarantine";"forward_deny")|length)==1 and
      (chain("inet";"vpn_v240_preclone_quarantine";"forward_deny")[0]|
        .hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("bridge";"vpn_v240_preclone_bridge";"forward_deny")|length)==1 and
      (chain("bridge";"vpn_v240_preclone_bridge";"forward_deny")[0]|
        .hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("netdev";"vpn_v240_preclone_underlay";"lowerdev_deny")|length)==1 and
      (chain("netdev";"vpn_v240_preclone_underlay";"lowerdev_deny")[0]|
        .hook=="egress" and .dev==$iface and .prio==-310 and .policy=="drop") and
      (rules("inet";"vpn_v240_preclone_quarantine";"output_deny") as $out |
        ($out|map(core)) ==
        ([ [m(meta("oifname");"lo"),{accept:null}],
           [m(meta("oifname");$iface),m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}],
           [m(meta("oifname");$iface),m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$od),m(pay("tcp";"dport");$op),{accept:null}],
           [m(meta("oifname");$iface),m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$wd),m(pay("udp";"dport");$wp),{accept:null}] ] +
         ($prefixes|map([m(meta("oifname");$ot),m(pay("ip";"saddr");$os),m(pay("ip";"daddr");rhs(.)),{drop:null}])) +
         [ [m(meta("oifname");$ot),m(pay("ip";"saddr");$os),{accept:null}] ] +
         ($prefixes|map([m(meta("oifname");$wt),m(pay("ip";"saddr");$ws),m(pay("ip";"daddr");rhs(.)),{accept:null}]))) and
        proto_ok($out[0];"none") and proto_ok($out[1];"udp") and
        proto_ok($out[2];"tcp") and proto_ok($out[3];"udp") and
        all(range(4;($out|length)); proto_ok($out[.];"none"))) and
      (rules("inet";"vpn_v240_preclone_quarantine";"forward_deny")|length)==0 and
      (rules("bridge";"vpn_v240_preclone_bridge";"forward_deny")|length)==0 and
      (rules("netdev";"vpn_v240_preclone_underlay";"lowerdev_deny") as $r |
        ($r|length)==4 and arp($r[0]) and
        ($r[1]|core)==[m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}] and
        ($r[2]|core)==[m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$od),m(pay("tcp";"dport");$op),{accept:null}] and
        ($r[3]|core)==[m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$wd),m(pay("udp";"dport");$wp),{accept:null}] and
        proto_ok($r[1];"udp") and proto_ok($r[2];"tcp") and proto_ok($r[3];"udp"))
    ' "$file" >/dev/null 2>&1
}

ubs24gd4_foreign_policy_unchanged() {
    (( $# == 1 )) || return 1
    local snapshot=$1 pre foreign_before foreign_after
    pre=$(ubs24gb2_runtime) || return 1
    [[ $pre == /run/ubs-v240-controller && -f $pre/prestate.json && ! -L $pre/prestate.json ]] || return 1
    foreign_before=$(ubs24gb2_foreign_projection "$pre/prestate.json") || return 1
    foreign_after=$(ubs24gb2_foreign_projection "$snapshot") || return 1
    [[ $foreign_before == "$foreign_after" ]]
}

ubs24gd4_endpoint_route_observed() {
    (( $# == 0 )) || return 1
    local json get expected_gateway
    json=$(ip -j -N -4 route show exact "$UBS24GD4_ENDPOINT_IP/32" table main) || return 1
    expected_gateway=$UBS24GD4_UNDERLAY_GATEWAY
    [[ $expected_gateway == - ]] && expected_gateway=''
    jq -e --arg dst "$UBS24GD4_ENDPOINT_IP" --arg dev "$UBS24GD4_UNDERLAY" \
      --arg src "$UBS24GD4_UNDERLAY_SOURCE" --arg gw "$expected_gateway" '
        type=="array" and length==1 and
        ((.[0].dst // "") == $dst or (.[0].dst // "") == ($dst + "/32")) and
        (.[0].dev // "") == $dev and (.[0].prefsrc // "") == $src and
        (.[0].gateway // "") == $gw and ((.[0].protocol // "")|tostring) == "186" and
        ((.[0].metric // -1)|tonumber) == 4240 and
        ((.[0].multipath // [])|length) == 0
      ' <<< "$json" >/dev/null 2>&1 || return 1
    get=$(ip -4 route get "$UBS24GD4_ENDPOINT_IP") || return 1
    ubs24b_route_get_matches "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_UNDERLAY" \
      "$UBS24GD4_UNDERLAY_GATEWAY" "$UBS24GD4_UNDERLAY_SOURCE" "$get"
}

ubs24gd4_wg_nm_active() {
    (( $# == 0 )) || return 1
    local line
    line=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE,DEVICE connection show --active 2>/dev/null |
      awk -F: -v u="$UBS24GD4_TEMP_UUID" '$2==u {print; n++} END{if(n!=1) exit 1}') || return 1
    [[ $line == "$UBS24GD4_TEMP_NAME:$UBS24GD4_TEMP_UUID:wireguard:$UBS24GD4_TEMP_NAME" ]]
}

ubs24gd4_wg_kernel_endpoint() {
    (( $# == 0 )) || return 1
    local fw endpoints key ep extra
    fw=$(LC_ALL=C wg show "$UBS24GD4_TEMP_NAME" fwmark 2>/dev/null) || return 1
    [[ $fw == off || $fw == 0 ]] || return 1
    endpoints=$(LC_ALL=C wg show "$UBS24GD4_TEMP_NAME" endpoints 2>/dev/null) || return 1
    [[ -n $endpoints && $endpoints != *$'\n'* && $endpoints == *$'\t'* ]] || return 1
    key=${endpoints%%$'\t'*}; ep=${endpoints#*$'\t'}
    [[ $key =~ ^[A-Za-z0-9+/]{43}=$ && $ep == "$UBS24GD4_ENDPOINT_IP:$UBS24GD4_ENDPOINT_PORT" ]]
}

ubs24gd4_route_get_json_matches() {
    (( $# == 3 )) || return 1
    local target=$1 dev=$2 source=$3 json
    json=$(ip -j -4 route get "$target") || return 1
    jq -e --arg d "$dev" --arg s "$source" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s and
      ((.[0].gateway // "") == "") and ((.[0].multipath // [])|length==0)
    ' <<< "$json" >/dev/null 2>&1
}

ubs24gd4_openvpn_default_route_observed() {
    (( $# == 0 )) || return 1
    local json
    json=$(ip -j -4 route get 1.1.1.1) || return 1
    jq -e --arg d "$UBS24GC11_TUNNEL" --arg s "$UBS24GC11_TUNNEL_SOURCE" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s
    ' <<< "$json" >/dev/null 2>&1
}

ubs24gd4_dual_active_observed() {
    (( $# == 0 )) || return 1
    local scratch first second prefix target route_now
    ubs24gd4_authority_witness || return 1
    ubs24gd4_wg_nm_active && ubs24gd4_wg_kernel_endpoint && ubs24gd4_endpoint_route_observed || return 1
    route_now=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    [[ $route_now == "${UBS24GC6_ROUTE_SNAPSHOT:-}" ]] || return 1
    ubs24gd4_openvpn_default_route_observed || return 1
    for prefix in "${UBS24GD4_ALLOWED_IPS[@]}"; do
        target=${prefix%/*}
        ubs24gd4_route_get_json_matches "$target" "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" || return 1
    done
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c23ai-observe.XXXXXXXX) || return 1
    first=$scratch/first.json second=$scratch/second.json
    if ! ubs24gb1_capture_nft "$first" || ! ubs24gb1_capture_nft "$second" ||
       ! cmp -s -- "$first" "$second" ||
       ! ubs24gd4_parallel_guard_observation "$first" "$UBS24GD4_UNDERLAY" "$UBS24GD4_UNDERLAY_SOURCE" \
          "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" \
          "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_ENDPOINT_PORT" \
          "${UBS24GD4_ALLOWED_IPS[@]}" || ! ubs24gd4_foreign_policy_unchanged "$first"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
}

ubs24gd4_wg_down_observed() {
    (( $# == 0 )) || return 1
    local i
    for ((i=0; i<20; i++)); do
        if ! nmcli --wait 5 --colors no -t -f UUID,TYPE,DEVICE connection show --active 2>/dev/null |
              grep -Fq "$UBS24GD4_TEMP_UUID:wireguard:" &&
           ! ip link show dev "$UBS24GD4_TEMP_NAME" >/dev/null 2>&1 &&
           ! wg show "$UBS24GD4_TEMP_NAME" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ubs24gd4_prepare_from_preflight() {
    (( $# == 8 )) || return 1
    local wg_uuid=$1 source_file=$2 source_sha=$3 wg_source=$4 underlay=$5 underlay_source=$6 gateway=$7 temp_uuid=$8
    [[ ${UBS24GD4_ATTEMPTED:-no} == no ]] || return 1
    ubs24gd4_dependencies && ubs24gd4_private_runtime_absent && ubs24gd4_temp_profile_absent || return 1
    ubs24_valid_uuid "$wg_uuid" && ubs24_valid_uuid "$temp_uuid" &&
      [[ -f $source_file && ! -L $source_file && $(ubs24gd4_hash_file "$source_file") == "$source_sha" ]] || return 1
    wg23_validate_ipv4 "$wg_source" && ubs24gb1_valid_ifname "$underlay" && wg23_validate_ipv4 "$underlay_source" || return 1
    [[ $gateway == - ]] || wg23_validate_ipv4 "$gateway" || return 1
    UBS24GD4_SOURCE_UUID=$wg_uuid UBS24GD4_SOURCE_FILE=$source_file UBS24GD4_SOURCE_SHA=$source_sha
    UBS24GD4_WG_SOURCE=$wg_source UBS24GD4_UNDERLAY=$underlay UBS24GD4_UNDERLAY_SOURCE=$underlay_source
    UBS24GD4_UNDERLAY_GATEWAY=$gateway UBS24GD4_TEMP_UUID=$temp_uuid
    UBS24GD4_STAGE=preflight-bound-no-wireguard-mutation-yet
}

# Resolve the saved endpoint again after OpenVPN is already protected. The
# current resolver is therefore the protected OpenVPN DNS path attested by C17.
# The first bounded answer is selected; the user's current profile has one A
# record. Multiple-peer/multi-address selection remains future scope.
ubs24gd4_resolve_protected_endpoint() {
    (( $# == 0 )) || return 1
    local host port ip prefix
    ubs24gd4_authority_witness || return 1
    [[ $(ubs24gd4_hash_file "$UBS24GD4_SOURCE_FILE") == "$UBS24GD4_SOURCE_SHA" ]] || return 1
    ubs24gd2_validate_keyfile "$UBS24GD4_SOURCE_FILE" "$UBS24GD4_SOURCE_UUID" "$UBS24GD4_UNDERLAY" || return 1
    (( ${#UBS24GD2_ENDPOINT_HOSTS[@]} == 1 && ${#UBS24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    ubs24gd3_keyfile_ipv4_source "$UBS24GD4_SOURCE_FILE" || return 1
    [[ $UBS24GD3_WG_SOURCE_IP == "$UBS24GD4_WG_SOURCE" ]] || return 1
    host=${UBS24GD2_ENDPOINT_HOSTS[0]} port=${UBS24GD2_ENDPOINT_PORTS[0]}
    ubs24gd2_resolve_ipv4_candidates "$host" || return 1
    (( ${#UBS24GD2_RESOLVED_IPS[@]} >= 1 && ${#UBS24GD2_RESOLVED_IPS[@]} <= 16 )) || return 1
    ip=${UBS24GD2_RESOLVED_IPS[0]}
    for prefix in "${UBS24GD2_ALLOWED_IPS[@]}"; do
        ubs24gd3_private_ipv4_prefix "$prefix" && ! ubs24c_cidr_contains "$prefix" "$ip" || return 1
    done
    UBS24GD4_ENDPOINT_IP=$ip UBS24GD4_ENDPOINT_PORT=$port
    UBS24GD4_ALLOWED_IPS=("${UBS24GD2_ALLOWED_IPS[@]}")
    UBS24GD4_STAGE=protected-endpoint-resolved-no-wireguard-mutation-yet
}

ubs24gd4_publish_profile() {
    (( $# == 0 )) || return 1
    local scratch temp hash loaded_uuid loaded_type loaded_iface
    ubs24gd4_authority_witness && ubs24gd4_private_runtime_absent && ubs24gd4_temp_profile_absent || return 1
    [[ ${UBS24GD4_STAGE:-} == protected-endpoint-resolved-no-wireguard-mutation-yet ]] || return 1
    scratch=$(umask 077; mktemp -d /run/ubs-v240-c23ai-profile.XXXXXXXX) || return 1
    temp=$scratch/pinned.nmconnection
    (umask 077; : > "$temp") || { rmdir "$scratch"; return 1; }
    chmod 600 -- "$temp" || { rm -rf -- "$scratch"; return 1; }
    if ! ubs24gd3_write_pinned_profile "$UBS24GD4_SOURCE_FILE" "$UBS24GD4_SOURCE_UUID" "$UBS24GD4_UNDERLAY" \
       "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_ENDPOINT_PORT" "$UBS24GD4_TEMP_NAME" "$UBS24GD4_TEMP_UUID" "$temp"; then
        rm -rf -- "$scratch"; return 1
    fi
    UBS24GD4_STAGE=pinned-profile-built-no-publish-yet
    ubs24gd4_publish_intent || { rm -rf -- "$scratch"; return 1; }
    ubs24gd4_write_marker profile-publish-attempt || { rm -rf -- "$scratch"; return 1; }
    [[ ! -e $UBS24GD4_TEMP_FILE && ! -L $UBS24GD4_TEMP_FILE ]] || { rm -rf -- "$scratch"; return 1; }
    mv -T -- "$temp" "$UBS24GD4_TEMP_FILE" || { rm -rf -- "$scratch"; return 1; }
    rmdir -- "$scratch" || return 1
    chmod 600 -- "$UBS24GD4_TEMP_FILE" || return 1
    UBS24GD4_STAGE=profile-file-published-nm-load-outcome-uncertain
    nmcli --wait 20 connection load "$UBS24GD4_TEMP_FILE" >/dev/null 2>&1 || return 1
    loaded_uuid=$(nmcli --wait 10 -g connection.id connection show uuid "$UBS24GD4_TEMP_UUID" 2>/dev/null) || return 1
    loaded_type=$(nmcli --wait 10 -g connection.type connection show uuid "$UBS24GD4_TEMP_UUID" 2>/dev/null) || return 1
    loaded_iface=$(nmcli --wait 10 -g connection.interface-name connection show uuid "$UBS24GD4_TEMP_UUID" 2>/dev/null) || return 1
    [[ $loaded_uuid == "$UBS24GD4_TEMP_NAME" && $loaded_type == wireguard && $loaded_iface == "$UBS24GD4_TEMP_NAME" ]] || return 1
    UBS24GD4_STAGE=pinned-profile-loaded-inactive
}

ubs24gd4_add_endpoint_route() {
    (( $# == 0 )) || return 1
    local existing
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == pinned-profile-loaded-inactive ]] || return 1
    existing=$(ip -4 route show exact "$UBS24GD4_ENDPOINT_IP/32" table main) || return 1
    [[ -z $existing ]] || return 1
    ubs24b_route_add_argv "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_UNDERLAY" "$UBS24GD4_UNDERLAY_GATEWAY" "$UBS24GD4_UNDERLAY_SOURCE" || return 1
    ubs24gd4_write_marker route-add-attempt || return 1
    UBS24GD4_STAGE=endpoint-route-add-outcome-uncertain
    ip "${UBS24B_ROUTE_ARGV[@]}" || return 1
    ubs24gd4_endpoint_route_observed || return 1
    UBS24GD4_STAGE=owned-endpoint-route-observed
}

ubs24gd4_extend_guard() {
    (( $# == 0 )) || return 1
    local scratch batch before1 before2 after1 after2
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == owned-endpoint-route-observed ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c23ai-guard.XXXXXXXX) || return 1
    batch=$scratch/parallel.nft before1=$scratch/before1.json before2=$scratch/before2.json after1=$scratch/after1.json after2=$scratch/after2.json
    (umask 077; : > "$batch") || { rm -rf -- "$scratch"; return 1; }
    chmod 600 -- "$batch" || { rm -rf -- "$scratch"; return 1; }
    if ! ubs24gb1_capture_nft "$before1" || ! ubs24gb1_capture_nft "$before2" || ! cmp -s -- "$before1" "$before2" ||
       ! ubs24gc11_postshape_observation "$before1" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" ||
       ! ubs24gd4_foreign_policy_unchanged "$before1" ||
       ! ubs24gd4_write_parallel_guard_candidate "$UBS24GD4_UNDERLAY" "$UBS24GD4_UNDERLAY_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" \
          "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" \
          "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_ENDPOINT_PORT" "$batch" "${UBS24GD4_ALLOWED_IPS[@]}" ||
       ! nft --check --file "$batch" >/dev/null 2>&1; then
        rm -rf -- "$scratch"; return 1
    fi
    ubs24gd4_write_marker guard-extend-attempt || { rm -rf -- "$scratch"; return 1; }
    UBS24GD4_STAGE=parallel-guard-commit-outcome-uncertain
    if ! nft --file "$batch" >/dev/null 2>&1; then rm -rf -- "$scratch"; return 1; fi
    if ! ubs24gb1_capture_nft "$after1" || ! ubs24gb1_capture_nft "$after2" || ! cmp -s -- "$after1" "$after2" ||
       ! ubs24gd4_parallel_guard_observation "$after1" "$UBS24GD4_UNDERLAY" "$UBS24GD4_UNDERLAY_SOURCE" \
          "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" \
          "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_ENDPOINT_PORT" \
          "${UBS24GD4_ALLOWED_IPS[@]}" || ! ubs24gd4_foreign_policy_unchanged "$after1"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    UBS24GD4_STAGE=parallel-guard-observed-wg-inactive
}

ubs24gd4_activate_wg() {
    (( $# == 0 )) || return 1
    local rc=0
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == parallel-guard-observed-wg-inactive ]] || return 1
    ubs24gd4_write_marker activation-attempt || return 1
    UBS24GD4_STAGE=wireguard-activation-outcome-uncertain
    set +e
    nmcli --wait 60 connection up uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    UBS24GD4_NM_UP_EXIT_STATUS=$rc
    # A nonzero nmcli result is ambiguous. Do not retry it. Only an exact
    # authoritative active-state observation can turn the attempt into success.
    if ubs24gd4_dual_active_observed; then
        UBS24GD4_STAGE=parallel-wireguard-openvpn-protected-running
        return 0
    fi
    return 1
}

ubs24gd4_start_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GD4_ATTEMPTED:-no} == no ]] || return 1
    UBS24GD4_ATTEMPTED=yes
    UBS24GD4_STAGE=starting-wireguard-stage
    ubs24gd4_resolve_protected_endpoint || return 1
    ubs24gd4_publish_profile || return 1
    ubs24gd4_add_endpoint_route || return 1
    ubs24gd4_extend_guard || return 1
    ubs24gd4_activate_wg
}


ubs24gd4_private_hold_line_matches() {
    (( $# == 2 )) || return 1
    local prefix=$1 output=$2 token i found_proto='' found_metric=''
    local -a parts=()
    ubs24gd3_private_ipv4_prefix "$prefix" || return 1
    [[ -n $output && $output != *$'\n'* && $output != *$'\r'* ]] || return 1
    read -r -a parts <<< "$output"
    [[ ${parts[0]:-} == unreachable && ${parts[1]:-} == "$prefix" ]] || return 1
    for ((i=2; i<${#parts[@]}; i++)); do
        token=${parts[i]}
        case $token in
          proto|metric)
            (( i+1 < ${#parts[@]} )) || return 1
            case $token in
              proto) [[ -z $found_proto ]] || return 1; found_proto=${parts[++i]} ;;
              metric) [[ -z $found_metric ]] || return 1; found_metric=${parts[++i]} ;;
            esac ;;
          table)
            (( i+1 < ${#parts[@]} )) && [[ ${parts[i+1]} == main ]] || return 1
            ((i+=1)) ;;
          *) return 1 ;;
        esac
    done
    [[ $found_proto == "${UBS24GD4_HOLD_PROTO:-187}" && $found_metric == "${UBS24GD4_HOLD_METRIC:-4241}" ]]
}

ubs24gd4_private_hold_exact_observed() {
    (( $# == 1 )) || return 1
    local prefix=$1 json
    ubs24gd3_private_ipv4_prefix "$prefix" || return 1
    json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
    jq -e --arg p "$prefix" --arg proto "${UBS24GD4_HOLD_PROTO:-187}" \
      --argjson metric "${UBS24GD4_HOLD_METRIC:-4241}" '
        type=="array" and length==1 and
        ((((.[0].type // "")|tostring) == "unreachable") or (((.[0].type // "")|tostring) == "7")) and
        ((.[0].dst // "") == $p or (($p|endswith("/32")) and (.[0].dst // "") == ($p|sub("/32$";"")))) and
        ((.[0].protocol // "")|tostring) == $proto and
        ((.[0].metric // -1)|tonumber) == $metric
      ' <<< "$json" >/dev/null 2>&1
}

ubs24gd4_private_hold_routes_state() {
    (( $# == 1 )) || return 1
    local expected=$1 json type prefix metric count=0 profile_prefix candidate
    local -A wanted=() seen=()
    [[ $expected == absent || $expected == full ]] || return 1
    for prefix in "${UBS24GD4_ALLOWED_IPS[@]}"; do
        ubs24gd3_private_ipv4_prefix "$prefix" && [[ -z ${wanted[$prefix]:-} ]] || return 1
        wanted[$prefix]=1
    done
    json=$(ip -j -N -4 route show table all proto "${UBS24GD4_HOLD_PROTO:-187}") || return 1
    jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
    while IFS=$'\t' read -r type prefix metric; do
        [[ -n $prefix ]] || continue
        [[ ( $type == unreachable || $type == 7 ) && $metric == "${UBS24GD4_HOLD_METRIC:-4241}" ]] || return 1
        profile_prefix=$prefix
        if [[ -z ${wanted[$profile_prefix]:-} ]] && wg23_validate_ipv4 "$profile_prefix"; then
            candidate="${profile_prefix}/32"
            [[ -n ${wanted[$candidate]:-} ]] && profile_prefix=$candidate
        fi
        [[ -n ${wanted[$profile_prefix]:-} && -z ${seen[$profile_prefix]:-} ]] || return 1
        ubs24gd4_private_hold_exact_observed "$profile_prefix" || return 1
        seen[$profile_prefix]=1
        ((count+=1))
    done < <(jq -r '.[] | [(.type // "unicast"), (.dst // ""), ((.metric // "")|tostring)] | @tsv' <<< "$json")
    if [[ $expected == absent ]]; then
        (( count == 0 ))
    else
        (( count == ${#UBS24GD4_ALLOWED_IPS[@]} ))
    fi
}

ubs24gd4_add_private_hold_routes() {
    (( $# == 0 )) || return 1
    local prefix rc
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == parallel-wireguard-openvpn-protected-running ]] || return 1
    ubs24gd4_dual_active_observed && ubs24gd4_private_hold_routes_state absent || return 1
    ubs24gd4_write_marker private-hold-route-add-attempt || return 1
    UBS24GD4_STAGE=private-hold-route-add-outcome-uncertain
    for prefix in "${UBS24GD4_ALLOWED_IPS[@]}"; do
        set +e
        ip -4 route add unreachable "$prefix" proto "${UBS24GD4_HOLD_PROTO:-187}" metric "${UBS24GD4_HOLD_METRIC:-4241}" >/dev/null 2>&1
        rc=$?
        set -e
        # No mutation retry. Exact full inventory below is authoritative.
        : "$rc"
    done
    ubs24gd4_private_hold_routes_state full || return 1
    # The live WG route must still win while both routes have the same prefix.
    ubs24gd4_dual_active_observed || return 1
    UBS24GD4_STAGE=private-hold-routes-observed-wireguard-still-active
}

ubs24gd4_disconnect_wg() {
    (( $# == 0 )) || return 1
    local rc
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == private-hold-routes-observed-wireguard-still-active ]] || return 1
    ubs24gd4_private_hold_routes_state full && ubs24gd4_dual_active_observed || return 1
    ubs24gd4_write_marker disconnect-attempt || return 1
    UBS24GD4_STAGE=wireguard-disconnect-outcome-uncertain
    set +e
    nmcli --wait 60 connection down uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    UBS24GD4_NM_DOWN_EXIT_STATUS=$rc
    # Like C19, outcome is based on bounded authoritative post-state, not the
    # client exit status alone. Never issue a second down command.
    ubs24gd4_wg_down_observed && ubs24gd4_private_hold_routes_state full || return 1
    UBS24GD4_STAGE=wireguard-down-parallel-guard-retained-private-hold
}

ubs24gd4_write_openvpn_restore_candidate() {
    (( $# == 7 )) || return 1
    local underlay=$1 source=$2 remote=$3 port=$4 tunnel=$5 tun_source=$6 out=$7
    ubs24gc11_parameters "$underlay" "$source" "$remote" "$port" "$tunnel" "$tun_source" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == '600:1' ]] || return 1

    # D4 -> C11 handback differs from the original C1 -> C11 transition:
    # D4 added a WireGuard transport allowance to both inet OUTPUT and the
    # netdev underlay egress chain. Restore both owner chains atomically so no
    # stale WG physical-egress exception survives after WG is down. Reuse C1's
    # exact underlay reconstruction, then append the proven C11 tunnel rule.
    ubs24gc1_write_batch "$underlay" "$source" "$remote" "$port" "$out" || return 1
    printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' \
      "$tunnel" "$tun_source" >> "$out"
}

ubs24gd4_restore_openvpn_guard() {
    (( $# == 0 )) || return 1
    local scratch batch before1 before2 after1 after2
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == wireguard-down-parallel-guard-retained-private-hold ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c23ai-restore.XXXXXXXX) || return 1
    batch=$scratch/ovpn.nft before1=$scratch/before1.json before2=$scratch/before2.json after1=$scratch/after1.json after2=$scratch/after2.json
    (umask 077; : > "$batch") || { rm -rf -- "$scratch"; return 1; }
    chmod 600 -- "$batch" || { rm -rf -- "$scratch"; return 1; }
    if ! ubs24gb1_capture_nft "$before1" || ! ubs24gb1_capture_nft "$before2" || ! cmp -s -- "$before1" "$before2" ||
       ! ubs24gd4_parallel_guard_observation "$before1" "$UBS24GD4_UNDERLAY" "$UBS24GD4_UNDERLAY_SOURCE" \
          "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" \
          "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" "$UBS24GD4_ENDPOINT_IP" "$UBS24GD4_ENDPOINT_PORT" \
          "${UBS24GD4_ALLOWED_IPS[@]}" || ! ubs24gd4_foreign_policy_unchanged "$before1" ||
       ! ubs24gd4_write_openvpn_restore_candidate "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" \
          "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" "$batch" || ! nft --check --file "$batch" >/dev/null 2>&1; then
        rm -rf -- "$scratch"; return 1
    fi
    ubs24gd4_write_marker guard-restore-attempt || { rm -rf -- "$scratch"; return 1; }
    UBS24GD4_STAGE=openvpn-guard-restore-outcome-uncertain
    if ! nft --file "$batch" >/dev/null 2>&1; then rm -rf -- "$scratch"; return 1; fi
    if ! ubs24gb1_capture_nft "$after1" || ! ubs24gb1_capture_nft "$after2" || ! cmp -s -- "$after1" "$after2" ||
       ! ubs24gc11_postshape_observation "$after1" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" ||
       ! ubs24gd4_foreign_policy_unchanged "$after1"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    ubs24gd4_private_hold_routes_state full || return 1
    UBS24GD4_STAGE=pure-openvpn-guard-restored-route-profile-remain-private-hold
}

ubs24gd4_delete_endpoint_route() {
    (( $# == 0 )) || return 1
    local -a argv
    local shown rc
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == pure-openvpn-guard-restored-route-profile-remain-private-hold ]] || return 1
    ubs24gd4_endpoint_route_observed || return 1
    ubs24gd4_write_marker route-delete-attempt || return 1
    argv=(-4 route del "$UBS24GD4_ENDPOINT_IP/32")
    [[ $UBS24GD4_UNDERLAY_GATEWAY == - ]] || argv+=(via "$UBS24GD4_UNDERLAY_GATEWAY")
    argv+=(dev "$UBS24GD4_UNDERLAY" src "$UBS24GD4_UNDERLAY_SOURCE" proto 186 metric 4240)
    UBS24GD4_STAGE=endpoint-route-delete-outcome-uncertain
    set +e
    ip "${argv[@]}"
    rc=$?
    set -e
    shown=$(ip -4 route show exact "$UBS24GD4_ENDPOINT_IP/32" table main) || return 1
    [[ -z $shown ]] || return 1
    ubs24gd4_private_hold_routes_state full || return 1
    UBS24GD4_STAGE=owned-endpoint-route-absent-profile-remains-private-hold
}

ubs24gd4_delete_profile() {
    (( $# == 0 )) || return 1
    local rc found
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == owned-endpoint-route-absent-profile-remains-private-hold ]] || return 1
    ubs24gd4_wg_down_observed || return 1
    ubs24gd4_write_marker profile-delete-attempt || return 1
    UBS24GD4_STAGE=temporary-profile-delete-outcome-uncertain
    set +e
    nmcli --wait 30 connection delete uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    if nmcli --wait 10 -g connection.uuid connection show uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1; then
        return 1
    fi
    # NM normally removes the keyfile. If the connection is authoritatively
    # absent but the exact root-owned /run keyfile remains, remove only that
    # known temporary file after confirming it still carries our UUID.
    if [[ -e $UBS24GD4_TEMP_FILE || -L $UBS24GD4_TEMP_FILE ]]; then
        [[ -f $UBS24GD4_TEMP_FILE && ! -L $UBS24GD4_TEMP_FILE &&
           $(stat -c '%u:%a:%h' -- "$UBS24GD4_TEMP_FILE") == '0:600:1' &&
           $(ubs24gd2_keyfile_scalar "$UBS24GD4_TEMP_FILE" connection uuid) == "$UBS24GD4_TEMP_UUID" ]] || return 1
        rm -f -- "$UBS24GD4_TEMP_FILE" || return 1
    fi
    ubs24gd4_temp_profile_absent || return 1
    ubs24gd4_private_hold_routes_state full || return 1
    UBS24GD4_STAGE=temporary-profile-absent-pure-openvpn-protected-private-hold
}

ubs24gd4_finish_teardown() {
    (( $# == 0 )) || return 1
    local route_now scratch first second
    ubs24gd4_authority_witness || return 1
    [[ ${UBS24GD4_STAGE:-} == temporary-profile-absent-pure-openvpn-protected-private-hold ]] || return 1
    route_now=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    [[ $route_now == "${UBS24GC6_ROUTE_SNAPSHOT:-}" ]] && ubs24gd4_openvpn_default_route_observed || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c23ai-final.XXXXXXXX) || return 1
    first=$scratch/first.json second=$scratch/second.json
    if ! ubs24gb1_capture_nft "$first" || ! ubs24gb1_capture_nft "$second" || ! cmp -s -- "$first" "$second" ||
       ! ubs24gc11_postshape_observation "$first" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" ||
       ! ubs24gd4_foreign_policy_unchanged "$first"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    ubs24gd4_private_hold_routes_state full || return 1
    [[ -d $UBS24GD4_RUNTIME && ! -L $UBS24GD4_RUNTIME ]] || return 1
    UBS24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold
}

ubs24gd4_stop_once() {
    (( $# == 0 )) || return 1
    ubs24gd4_add_private_hold_routes || return 1
    ubs24gd4_disconnect_wg || return 1
    ubs24gd4_restore_openvpn_guard || return 1
    ubs24gd4_delete_endpoint_route || return 1
    ubs24gd4_delete_profile || return 1
    ubs24gd4_finish_teardown
}



ubs24gd4_post_openvpn_cleanup_witness() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCU_AUTHORITY:-none} == private-local-console &&
       ${UBS24GCU_APPROVAL:-none} == approved-process-local &&
       ${UBS24GCU_OPERATION:-none} == session &&
       ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
       ${UBS24GCO_AUTHORITY:-none} == private-local-console &&
       ${UBS24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
       ${UBS24GCU_STAGE:-} == stopped-c1-held &&
       ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid && ubs24gb4_no_active_vpn || return 1
}

ubs24gd4_release_private_hold_after_openvpn_stop() {
    (( $# == 0 )) || return 1
    local prefix rc output
    ubs24gd4_post_openvpn_cleanup_witness || return 1
    case ${UBS24GD4_STAGE:-} in
      wireguard-residue-removed-openvpn-protected-private-hold|wireguard-residue-removed-openvpn-absent-c11-private-hold) ;;
      *) return 1 ;;
    esac
    ubs24gd4_private_hold_routes_state full || return 1
    ubs24gd4_write_marker private-hold-route-delete-attempt || return 1
    UBS24GD4_STAGE=private-hold-route-delete-outcome-uncertain-openvpn-down
    for prefix in "${UBS24GD4_ALLOWED_IPS[@]}"; do
        set +e
        ip -4 route del unreachable "$prefix" proto "${UBS24GD4_HOLD_PROTO:-187}" metric "${UBS24GD4_HOLD_METRIC:-4241}" >/dev/null 2>&1
        rc=$?
        set -e
        : "$rc"
    done
    ubs24gd4_private_hold_routes_state absent || return 1
    [[ -d $UBS24GD4_RUNTIME && ! -L $UBS24GD4_RUNTIME ]] || return 1
    rm -rf -- "$UBS24GD4_RUNTIME" || return 1
    UBS24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold
}

ubs24gd4_authorize_public_activation() { return 1; }
ubs24gd4_authorize_public_cleanup() { return 1; }
ubs24gd4_authorize_automatic_retry() { return 1; }
ubs24gd4_authorize_automatic_disarm() { return 1; }
