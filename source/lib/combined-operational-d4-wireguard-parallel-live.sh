#!/usr/bin/env bash
# C23AI D4 — PRIVATE operational WireGuard stage layered on the physically
# proven C23AE OpenVPN protected-running state.
#
# This is NOT part of the public mvc CLI. Authority is admitted only by
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

mvc24gd4_reset() {
    MVC24GD4_STAGE=idle
    MVC24GD4_DETAIL=none
    MVC24GD4_ATTEMPTED=no
    MVC24GD4_RUNTIME=/run/mvc-wireguard
    MVC24GD4_TEMP_NAME=vpnks-wg
    MVC24GD4_TEMP_UUID=
    MVC24GD4_TEMP_FILE=/run/NetworkManager/system-connections/vpnks-wg.nmconnection
    MVC24GD4_SOURCE_UUID=
    MVC24GD4_SOURCE_FILE=
    MVC24GD4_SOURCE_SHA=
    MVC24GD4_WG_SOURCE=
    MVC24GD4_ENDPOINT_IP=
    MVC24GD4_ENDPOINT_PORT=
    MVC24GD4_UNDERLAY=
    MVC24GD4_UNDERLAY_SOURCE=
    MVC24GD4_UNDERLAY_GATEWAY=
    MVC24GD4_ALLOWED_IPS=()
    MVC24GD4_NM_UP_EXIT_STATUS=unset
    MVC24GD4_NM_DOWN_EXIT_STATUS=unset
    MVC24GD4_HOLD_PROTO=187
    MVC24GD4_HOLD_METRIC=4241
}

mvc24gd4_authority_witness() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GCU_AUTHORITY:-none} == private-local-console &&
       ${MVC24GCU_APPROVAL:-none} == approved-process-local &&
       ${MVC24GCU_OPERATION:-none} == session &&
       ${MVC24GCO_MODE:-disabled} == private-live-local-console &&
       ${MVC24GCO_AUTHORITY:-none} == private-local-console &&
       ${MVC24GCO_STAGE:-} == protected-openvpn-observed &&
       ${MVC24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid || return 1
    mvc24gcu_live_admission_witness || return 1
}

mvc24gd4_dependencies() {
    local cmd
    for cmd in awk chmod cmp find getent grep ip jq mktemp mv nft nmcli readlink rm rmdir sha256sum stat wg; do
        command -v "$cmd" >/dev/null 2>&1 || return 1
    done
}

mvc24gd4_hash_file() {
    (( $# == 1 )) || return 1
    local file=$1 hash tail
    [[ -f $file && ! -L $file ]] || return 1
    read -r hash tail < <(sha256sum -- "$file") || return 1
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

mvc24gd4_private_runtime_absent() {
    [[ ! -e ${MVC24GD4_RUNTIME:-/run/mvc-wireguard} &&
       ! -L ${MVC24GD4_RUNTIME:-/run/mvc-wireguard} ]]
}

mvc24gd4_temp_profile_absent() {
    local name=${MVC24GD4_TEMP_NAME:-vpnks-wg} rows
    [[ ! -e ${MVC24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} &&
       ! -L ${MVC24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} ]] || return 1
    rows=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE connection show 2>/dev/null) || return 1
    ! awk -F: -v n="$name" '$1==n {found=1} END{exit(found?0:1)}' <<< "$rows"
}

mvc24gd4_write_marker() {
    (( $# == 1 )) || return 1
    local name=$1 dir=${MVC24GD4_RUNTIME:-}
    [[ $name =~ ^[a-z0-9-]+$ && -d $dir && ! -L $dir && -O $dir &&
       $(stat -c '%a' -- "$dir") == 700 ]] || return 1
    [[ ! -e $dir/$name && ! -L $dir/$name ]] || return 1
    (umask 077; set -C; printf '%s\n' "state=$name" > "$dir/$name") || return 1
    chmod 400 -- "$dir/$name"
}

mvc24gd4_publish_intent() {
    (( $# == 0 )) || return 1
    local dir=${MVC24GD4_RUNTIME:-} tmp boot userns netns mntns allowed
    mvc24gd4_authority_witness || return 1
    [[ $(stat -f -c %T /run) == tmpfs &&
       -n ${MVC24GD4_SOURCE_UUID:-} && -n ${MVC24GD4_SOURCE_FILE:-} &&
       -n ${MVC24GD4_SOURCE_SHA:-} && -n ${MVC24GD4_TEMP_UUID:-} &&
       -n ${MVC24GD4_WG_SOURCE:-} && -n ${MVC24GD4_ENDPOINT_IP:-} &&
       -n ${MVC24GD4_ENDPOINT_PORT:-} && -n ${MVC24GD4_UNDERLAY:-} &&
       -n ${MVC24GD4_UNDERLAY_SOURCE:-} && -n ${MVC24GD4_UNDERLAY_GATEWAY:-} &&
       ${#MVC24GD4_ALLOWED_IPS[@]} -ge 1 ]] || return 1
    mvc24gd4_private_runtime_absent || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    allowed=$(IFS=';'; printf '%s;' "${MVC24GD4_ALLOWED_IPS[*]}") || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.intent.XXXXXXXX") || return 1
    if ! printf '%s\n' \
        ubs-v240-c23ai-wireguard-intent-v1 \
        state=prepared-no-wireguard-mutation-yet \
        "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
        "source_uuid=$MVC24GD4_SOURCE_UUID" "source_sha=$MVC24GD4_SOURCE_SHA" \
        "temp_name=$MVC24GD4_TEMP_NAME" "temp_uuid=$MVC24GD4_TEMP_UUID" \
        "wg_source=$MVC24GD4_WG_SOURCE" \
        "endpoint=$MVC24GD4_ENDPOINT_IP:$MVC24GD4_ENDPOINT_PORT" \
        "underlay=$MVC24GD4_UNDERLAY|source=$MVC24GD4_UNDERLAY_SOURCE|gateway=$MVC24GD4_UNDERLAY_GATEWAY" \
        "allowedips=$allowed" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/intent" || return 1
    MVC24GD4_STAGE=intent-published-no-wireguard-mutation-yet
}


# Live C23AI guard candidate adds one property beyond the non-admitting D3
# preview: every selected WG private prefix is explicitly DROPPED on the
# OpenVPN tunnel before the ordinary OpenVPN accept. This prevents a private
# destination from falling back through OpenVPN while WG routes are not yet
# installed or are being removed. Private destinations are therefore either
# on vpnks-wg or fail-closed.
mvc24gd4_write_parallel_guard_candidate() {
    (( $# >= 11 )) || return 1
    local underlay=$1 underlay_source=$2 ovpn_ip=$3 ovpn_port=$4
    local ovpn_tunnel=$5 ovpn_source=$6 wg_tunnel=$7 wg_source=$8 wg_ip=$9 wg_port=${10} out=${11}
    shift 11
    local prefix
    mvc24gd3_guard_parameters "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port" \
      "$ovpn_tunnel" "$ovpn_source" "$wg_tunnel" "$wg_source" "$wg_ip" "$wg_port" "$@" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out && $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    {
      printf '%s\n' 'flush chain inet mvc_preclone_quarantine output_deny'
      printf '%s\n' 'add rule inet mvc_preclone_quarantine output_deny oifname "lo" accept'
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$underlay"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay" "$underlay_source" "$wg_ip" "$wg_port"
      for prefix in "$@"; do
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s drop\n' \
          "$ovpn_tunnel" "$ovpn_source" "$prefix"
      done
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' \
        "$ovpn_tunnel" "$ovpn_source"
      for prefix in "$@"; do
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s accept\n' \
          "$wg_tunnel" "$wg_source" "$prefix"
      done
      printf '%s\n' 'flush chain netdev mvc_preclone_underlay lowerdev_deny'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type arp accept'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
      printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay_source" "$wg_ip" "$wg_port"
    } > "$out"
}

# Canonical exact verifier for the C23AI parallel guard candidate. It checks
# only the three controller-owned tables and requires their complete shape;
# foreign table preservation is checked separately against B2 prestate.
mvc24gd4_parallel_guard_observation() {
    (( $# >= 12 )) || return 1
    local file=$1 underlay=$2 underlay_source=$3 ovpn_ip=$4 ovpn_port=$5
    local ovpn_tunnel=$6 ovpn_source=$7 wg_tunnel=$8 wg_source=$9 wg_ip=${10} wg_port=${11}
    shift 11
    local prefixes_json
    [[ -f $file && ! -L $file ]] || return 1
    mvc24gd3_guard_parameters "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port" \
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
        (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
         ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
         ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
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
        ([ ["inet","mvc_preclone_quarantine","output_deny"],
           ["inet","mvc_preclone_quarantine","forward_deny"],
           ["bridge","mvc_preclone_bridge","forward_deny"],
           ["netdev","mvc_preclone_underlay","lowerdev_deny"] ]|sort) and
      ([.nftables[]|.table?|select(owned(.))|[.family,.name]]|sort)==
        ([ ["inet","mvc_preclone_quarantine"], ["bridge","mvc_preclone_bridge"],
           ["netdev","mvc_preclone_underlay"] ]|sort) and
      (chain("inet";"mvc_preclone_quarantine";"output_deny")|length)==1 and
      (chain("inet";"mvc_preclone_quarantine";"output_deny")[0]|
        .hook=="output" and .prio==-310 and .policy=="drop") and
      (chain("inet";"mvc_preclone_quarantine";"forward_deny")|length)==1 and
      (chain("inet";"mvc_preclone_quarantine";"forward_deny")[0]|
        .hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("bridge";"mvc_preclone_bridge";"forward_deny")|length)==1 and
      (chain("bridge";"mvc_preclone_bridge";"forward_deny")[0]|
        .hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")|length)==1 and
      (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")[0]|
        .hook=="egress" and .dev==$iface and .prio==-310 and .policy=="drop") and
      (rules("inet";"mvc_preclone_quarantine";"output_deny") as $out |
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
      (rules("inet";"mvc_preclone_quarantine";"forward_deny")|length)==0 and
      (rules("bridge";"mvc_preclone_bridge";"forward_deny")|length)==0 and
      (rules("netdev";"mvc_preclone_underlay";"lowerdev_deny") as $r |
        ($r|length)==4 and arp($r[0]) and
        ($r[1]|core)==[m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}] and
        ($r[2]|core)==[m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$od),m(pay("tcp";"dport");$op),{accept:null}] and
        ($r[3]|core)==[m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$wd),m(pay("udp";"dport");$wp),{accept:null}] and
        proto_ok($r[1];"udp") and proto_ok($r[2];"tcp") and proto_ok($r[3];"udp"))
    ' "$file" >/dev/null 2>&1
}

mvc24gd4_foreign_policy_unchanged() {
    (( $# == 1 )) || return 1
    local snapshot=$1 pre foreign_before foreign_after
    pre=$(mvc24gb2_runtime) || return 1
    [[ $pre == /run/mvc-controller && -f $pre/prestate.json && ! -L $pre/prestate.json ]] || return 1
    foreign_before=$(mvc24gb2_foreign_projection "$pre/prestate.json") || return 1
    foreign_after=$(mvc24gb2_foreign_projection "$snapshot") || return 1
    [[ $foreign_before == "$foreign_after" ]]
}

mvc24gd4_endpoint_route_observed() {
    (( $# == 0 )) || return 1
    local json get expected_gateway
    json=$(ip -j -N -4 route show exact "$MVC24GD4_ENDPOINT_IP/32" table main) || return 1
    expected_gateway=$MVC24GD4_UNDERLAY_GATEWAY
    [[ $expected_gateway == - ]] && expected_gateway=''
    jq -e --arg dst "$MVC24GD4_ENDPOINT_IP" --arg dev "$MVC24GD4_UNDERLAY" \
      --arg src "$MVC24GD4_UNDERLAY_SOURCE" --arg gw "$expected_gateway" '
        type=="array" and length==1 and
        ((.[0].dst // "") == $dst or (.[0].dst // "") == ($dst + "/32")) and
        (.[0].dev // "") == $dev and (.[0].prefsrc // "") == $src and
        (.[0].gateway // "") == $gw and ((.[0].protocol // "")|tostring) == "186" and
        ((.[0].metric // -1)|tonumber) == 4240 and
        ((.[0].multipath // [])|length) == 0
      ' <<< "$json" >/dev/null 2>&1 || return 1
    get=$(ip -4 route get "$MVC24GD4_ENDPOINT_IP") || return 1
    mvc24b_route_get_matches "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_UNDERLAY" \
      "$MVC24GD4_UNDERLAY_GATEWAY" "$MVC24GD4_UNDERLAY_SOURCE" "$get"
}

mvc24gd4_wg_nm_active() {
    (( $# == 0 )) || return 1
    local line
    line=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE,DEVICE connection show --active 2>/dev/null |
      awk -F: -v u="$MVC24GD4_TEMP_UUID" '$2==u {print; n++} END{if(n!=1) exit 1}') || return 1
    [[ $line == "$MVC24GD4_TEMP_NAME:$MVC24GD4_TEMP_UUID:wireguard:$MVC24GD4_TEMP_NAME" ]]
}

mvc24gd4_wg_kernel_endpoint() {
    (( $# == 0 )) || return 1
    local fw endpoints key ep extra
    fw=$(LC_ALL=C wg show "$MVC24GD4_TEMP_NAME" fwmark 2>/dev/null) || return 1
    [[ $fw == off || $fw == 0 ]] || return 1
    endpoints=$(LC_ALL=C wg show "$MVC24GD4_TEMP_NAME" endpoints 2>/dev/null) || return 1
    [[ -n $endpoints && $endpoints != *$'\n'* && $endpoints == *$'\t'* ]] || return 1
    key=${endpoints%%$'\t'*}; ep=${endpoints#*$'\t'}
    [[ $key =~ ^[A-Za-z0-9+/]{43}=$ && $ep == "$MVC24GD4_ENDPOINT_IP:$MVC24GD4_ENDPOINT_PORT" ]]
}

mvc24gd4_route_get_json_matches() {
    (( $# == 3 )) || return 1
    local target=$1 dev=$2 source=$3 json
    json=$(ip -j -4 route get "$target") || return 1
    jq -e --arg d "$dev" --arg s "$source" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s and
      ((.[0].gateway // "") == "") and ((.[0].multipath // [])|length==0)
    ' <<< "$json" >/dev/null 2>&1
}

mvc24gd4_openvpn_default_route_observed() {
    (( $# == 0 )) || return 1
    local json
    json=$(ip -j -4 route get 1.1.1.1) || return 1
    jq -e --arg d "$MVC24GC11_TUNNEL" --arg s "$MVC24GC11_TUNNEL_SOURCE" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s
    ' <<< "$json" >/dev/null 2>&1
}

mvc24gd4_dual_active_observed() {
    (( $# == 0 )) || return 1
    local scratch first second prefix target route_now
    mvc24gd4_authority_witness || return 1
    mvc24gd4_wg_nm_active && mvc24gd4_wg_kernel_endpoint && mvc24gd4_endpoint_route_observed || return 1
    route_now=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    [[ $route_now == "${MVC24GC6_ROUTE_SNAPSHOT:-}" ]] || return 1
    mvc24gd4_openvpn_default_route_observed || return 1
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        target=${prefix%/*}
        mvc24gd4_route_get_json_matches "$target" "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" || return 1
    done
    scratch=$(umask 077; mktemp -d /dev/shm/mvc-c23ai-observe.XXXXXXXX) || return 1
    first=$scratch/first.json second=$scratch/second.json
    if ! mvc24gb1_capture_nft "$first" || ! mvc24gb1_capture_nft "$second" ||
       ! cmp -s -- "$first" "$second" ||
       ! mvc24gd4_parallel_guard_observation "$first" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" \
          "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" \
          "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" \
          "${MVC24GD4_ALLOWED_IPS[@]}" || ! mvc24gd4_foreign_policy_unchanged "$first"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
}

mvc24gd4_wg_down_observed() {
    (( $# == 0 )) || return 1
    local i
    for ((i=0; i<20; i++)); do
        if ! nmcli --wait 5 --colors no -t -f UUID,TYPE,DEVICE connection show --active 2>/dev/null |
              grep -Fq "$MVC24GD4_TEMP_UUID:wireguard:" &&
           ! ip link show dev "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 &&
           ! wg show "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mvc24gd4_prepare_from_preflight() {
    (( $# == 8 )) || return 1
    local wg_uuid=$1 source_file=$2 source_sha=$3 wg_source=$4 underlay=$5 underlay_source=$6 gateway=$7 temp_uuid=$8
    [[ ${MVC24GD4_ATTEMPTED:-no} == no ]] || return 1
    mvc24gd4_dependencies && mvc24gd4_private_runtime_absent && mvc24gd4_temp_profile_absent || return 1
    mvc24_valid_uuid "$wg_uuid" && mvc24_valid_uuid "$temp_uuid" &&
      [[ -f $source_file && ! -L $source_file && $(mvc24gd4_hash_file "$source_file") == "$source_sha" ]] || return 1
    wg23_validate_ipv4 "$wg_source" && mvc24gb1_valid_ifname "$underlay" && wg23_validate_ipv4 "$underlay_source" || return 1
    [[ $gateway == - ]] || wg23_validate_ipv4 "$gateway" || return 1
    MVC24GD4_SOURCE_UUID=$wg_uuid MVC24GD4_SOURCE_FILE=$source_file MVC24GD4_SOURCE_SHA=$source_sha
    MVC24GD4_WG_SOURCE=$wg_source MVC24GD4_UNDERLAY=$underlay MVC24GD4_UNDERLAY_SOURCE=$underlay_source
    MVC24GD4_UNDERLAY_GATEWAY=$gateway MVC24GD4_TEMP_UUID=$temp_uuid
    MVC24GD4_STAGE=preflight-bound-no-wireguard-mutation-yet
}

# Resolve the saved endpoint again after OpenVPN is already protected. The
# current resolver is therefore the protected OpenVPN DNS path attested by C17.
# The first bounded answer is selected; the user's current profile has one A
# record. Multiple-peer/multi-address selection remains future scope.
mvc24gd4_resolve_protected_endpoint() {
    (( $# == 0 )) || return 1
    local host port ip prefix
    mvc24gd4_authority_witness || return 1
    [[ $(mvc24gd4_hash_file "$MVC24GD4_SOURCE_FILE") == "$MVC24GD4_SOURCE_SHA" ]] || return 1
    mvc24gd2_validate_keyfile "$MVC24GD4_SOURCE_FILE" "$MVC24GD4_SOURCE_UUID" "$MVC24GD4_UNDERLAY" || return 1
    (( ${#MVC24GD2_ENDPOINT_HOSTS[@]} == 1 && ${#MVC24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    mvc24gd3_keyfile_ipv4_source "$MVC24GD4_SOURCE_FILE" || return 1
    [[ $MVC24GD3_WG_SOURCE_IP == "$MVC24GD4_WG_SOURCE" ]] || return 1
    host=${MVC24GD2_ENDPOINT_HOSTS[0]} port=${MVC24GD2_ENDPOINT_PORTS[0]}
    mvc24gd2_resolve_ipv4_candidates "$host" || return 1
    (( ${#MVC24GD2_RESOLVED_IPS[@]} >= 1 && ${#MVC24GD2_RESOLVED_IPS[@]} <= 16 )) || return 1
    ip=${MVC24GD2_RESOLVED_IPS[0]}
    for prefix in "${MVC24GD2_ALLOWED_IPS[@]}"; do
        mvc24gd3_private_ipv4_prefix "$prefix" && ! mvc24c_cidr_contains "$prefix" "$ip" || return 1
    done
    MVC24GD4_ENDPOINT_IP=$ip MVC24GD4_ENDPOINT_PORT=$port
    MVC24GD4_ALLOWED_IPS=("${MVC24GD2_ALLOWED_IPS[@]}")
    MVC24GD4_STAGE=protected-endpoint-resolved-no-wireguard-mutation-yet
}

mvc24gd4_publish_profile() {
    (( $# == 0 )) || return 1
    local scratch temp hash loaded_uuid loaded_type loaded_iface
    mvc24gd4_authority_witness && mvc24gd4_private_runtime_absent && mvc24gd4_temp_profile_absent || return 1
    [[ ${MVC24GD4_STAGE:-} == protected-endpoint-resolved-no-wireguard-mutation-yet ]] || return 1
    scratch=$(umask 077; mktemp -d /run/mvc-c23ai-profile.XXXXXXXX) || return 1
    temp=$scratch/pinned.nmconnection
    (umask 077; : > "$temp") || { rmdir "$scratch"; return 1; }
    chmod 600 -- "$temp" || { rm -rf -- "$scratch"; return 1; }
    if ! mvc24gd3_write_pinned_profile "$MVC24GD4_SOURCE_FILE" "$MVC24GD4_SOURCE_UUID" "$MVC24GD4_UNDERLAY" \
       "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" "$MVC24GD4_TEMP_NAME" "$MVC24GD4_TEMP_UUID" "$temp"; then
        rm -rf -- "$scratch"; return 1
    fi
    MVC24GD4_STAGE=pinned-profile-built-no-publish-yet
    mvc24gd4_publish_intent || { rm -rf -- "$scratch"; return 1; }
    mvc24gd4_write_marker profile-publish-attempt || { rm -rf -- "$scratch"; return 1; }
    [[ ! -e $MVC24GD4_TEMP_FILE && ! -L $MVC24GD4_TEMP_FILE ]] || { rm -rf -- "$scratch"; return 1; }
    mv -T -- "$temp" "$MVC24GD4_TEMP_FILE" || { rm -rf -- "$scratch"; return 1; }
    rmdir -- "$scratch" || return 1
    chmod 600 -- "$MVC24GD4_TEMP_FILE" || return 1
    MVC24GD4_STAGE=profile-file-published-nm-load-outcome-uncertain
    nmcli --wait 20 connection load "$MVC24GD4_TEMP_FILE" >/dev/null 2>&1 || return 1
    loaded_uuid=$(nmcli --wait 10 -g connection.id connection show uuid "$MVC24GD4_TEMP_UUID" 2>/dev/null) || return 1
    loaded_type=$(nmcli --wait 10 -g connection.type connection show uuid "$MVC24GD4_TEMP_UUID" 2>/dev/null) || return 1
    loaded_iface=$(nmcli --wait 10 -g connection.interface-name connection show uuid "$MVC24GD4_TEMP_UUID" 2>/dev/null) || return 1
    [[ $loaded_uuid == "$MVC24GD4_TEMP_NAME" && $loaded_type == wireguard && $loaded_iface == "$MVC24GD4_TEMP_NAME" ]] || return 1
    MVC24GD4_STAGE=pinned-profile-loaded-inactive
}

mvc24gd4_add_endpoint_route() {
    (( $# == 0 )) || return 1
    local existing
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == pinned-profile-loaded-inactive ]] || return 1
    existing=$(ip -4 route show exact "$MVC24GD4_ENDPOINT_IP/32" table main) || return 1
    [[ -z $existing ]] || return 1
    mvc24b_route_add_argv "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_GATEWAY" "$MVC24GD4_UNDERLAY_SOURCE" || return 1
    mvc24gd4_write_marker route-add-attempt || return 1
    MVC24GD4_STAGE=endpoint-route-add-outcome-uncertain
    ip "${MVC24B_ROUTE_ARGV[@]}" || return 1
    mvc24gd4_endpoint_route_observed || return 1
    MVC24GD4_STAGE=owned-endpoint-route-observed
}

mvc24gd4_extend_guard() {
    (( $# == 0 )) || return 1
    local scratch batch before1 before2 after1 after2
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == owned-endpoint-route-observed ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/mvc-c23ai-guard.XXXXXXXX) || return 1
    batch=$scratch/parallel.nft before1=$scratch/before1.json before2=$scratch/before2.json after1=$scratch/after1.json after2=$scratch/after2.json
    (umask 077; : > "$batch") || { rm -rf -- "$scratch"; return 1; }
    chmod 600 -- "$batch" || { rm -rf -- "$scratch"; return 1; }
    if ! mvc24gb1_capture_nft "$before1" || ! mvc24gb1_capture_nft "$before2" || ! cmp -s -- "$before1" "$before2" ||
       ! mvc24gc11_postshape_observation "$before1" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" ||
       ! mvc24gd4_foreign_policy_unchanged "$before1" ||
       ! mvc24gd4_write_parallel_guard_candidate "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" \
          "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" \
          "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" "$batch" "${MVC24GD4_ALLOWED_IPS[@]}" ||
       ! nft --check --file "$batch" >/dev/null 2>&1; then
        rm -rf -- "$scratch"; return 1
    fi
    mvc24gd4_write_marker guard-extend-attempt || { rm -rf -- "$scratch"; return 1; }
    MVC24GD4_STAGE=parallel-guard-commit-outcome-uncertain
    if ! nft --file "$batch" >/dev/null 2>&1; then rm -rf -- "$scratch"; return 1; fi
    if ! mvc24gb1_capture_nft "$after1" || ! mvc24gb1_capture_nft "$after2" || ! cmp -s -- "$after1" "$after2" ||
       ! mvc24gd4_parallel_guard_observation "$after1" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" \
          "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" \
          "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" \
          "${MVC24GD4_ALLOWED_IPS[@]}" || ! mvc24gd4_foreign_policy_unchanged "$after1"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    MVC24GD4_STAGE=parallel-guard-observed-wg-inactive
}

mvc24gd4_activate_wg() {
    (( $# == 0 )) || return 1
    local rc=0
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == parallel-guard-observed-wg-inactive ]] || return 1
    mvc24gd4_write_marker activation-attempt || return 1
    MVC24GD4_STAGE=wireguard-activation-outcome-uncertain
    set +e
    nmcli --wait 60 connection up uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    MVC24GD4_NM_UP_EXIT_STATUS=$rc
    # A nonzero nmcli result is ambiguous. Do not retry it. Only an exact
    # authoritative active-state observation can turn the attempt into success.
    if mvc24gd4_dual_active_observed; then
        MVC24GD4_STAGE=parallel-wireguard-openvpn-protected-running
        return 0
    fi
    return 1
}

mvc24gd4_start_once() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GD4_ATTEMPTED:-no} == no ]] || return 1
    MVC24GD4_ATTEMPTED=yes
    MVC24GD4_STAGE=starting-wireguard-stage
    mvc24gd4_resolve_protected_endpoint || return 1
    mvc24gd4_publish_profile || return 1
    mvc24gd4_add_endpoint_route || return 1
    mvc24gd4_extend_guard || return 1
    mvc24gd4_activate_wg
}


mvc24gd4_private_hold_line_matches() {
    (( $# == 2 )) || return 1
    local prefix=$1 output=$2 token i found_proto='' found_metric=''
    local -a parts=()
    mvc24gd3_private_ipv4_prefix "$prefix" || return 1
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
    [[ $found_proto == "${MVC24GD4_HOLD_PROTO:-187}" && $found_metric == "${MVC24GD4_HOLD_METRIC:-4241}" ]]
}

mvc24gd4_private_hold_exact_observed() {
    (( $# == 1 )) || return 1
    local prefix=$1 json
    mvc24gd3_private_ipv4_prefix "$prefix" || return 1
    json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
    jq -e --arg p "$prefix" --arg proto "${MVC24GD4_HOLD_PROTO:-187}" \
      --argjson metric "${MVC24GD4_HOLD_METRIC:-4241}" '
        type=="array" and length==1 and
        ((((.[0].type // "")|tostring) == "unreachable") or (((.[0].type // "")|tostring) == "7")) and
        ((.[0].dst // "") == $p or (($p|endswith("/32")) and (.[0].dst // "") == ($p|sub("/32$";"")))) and
        ((.[0].protocol // "")|tostring) == $proto and
        ((.[0].metric // -1)|tonumber) == $metric
      ' <<< "$json" >/dev/null 2>&1
}

mvc24gd4_private_hold_routes_state() {
    (( $# == 1 )) || return 1
    local expected=$1 json type prefix metric count=0 profile_prefix candidate
    local -A wanted=() seen=()
    [[ $expected == absent || $expected == full ]] || return 1
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        mvc24gd3_private_ipv4_prefix "$prefix" && [[ -z ${wanted[$prefix]:-} ]] || return 1
        wanted[$prefix]=1
    done
    json=$(ip -j -N -4 route show table all proto "${MVC24GD4_HOLD_PROTO:-187}") || return 1
    jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
    while IFS=$'\t' read -r type prefix metric; do
        [[ -n $prefix ]] || continue
        [[ ( $type == unreachable || $type == 7 ) && $metric == "${MVC24GD4_HOLD_METRIC:-4241}" ]] || return 1
        profile_prefix=$prefix
        if [[ -z ${wanted[$profile_prefix]:-} ]] && wg23_validate_ipv4 "$profile_prefix"; then
            candidate="${profile_prefix}/32"
            [[ -n ${wanted[$candidate]:-} ]] && profile_prefix=$candidate
        fi
        [[ -n ${wanted[$profile_prefix]:-} && -z ${seen[$profile_prefix]:-} ]] || return 1
        mvc24gd4_private_hold_exact_observed "$profile_prefix" || return 1
        seen[$profile_prefix]=1
        ((count+=1))
    done < <(jq -r '.[] | [(.type // "unicast"), (.dst // ""), ((.metric // "")|tostring)] | @tsv' <<< "$json")
    if [[ $expected == absent ]]; then
        (( count == 0 ))
    else
        (( count == ${#MVC24GD4_ALLOWED_IPS[@]} ))
    fi
}

mvc24gd4_add_private_hold_routes() {
    (( $# == 0 )) || return 1
    local prefix rc
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == parallel-wireguard-openvpn-protected-running ]] || return 1
    mvc24gd4_dual_active_observed && mvc24gd4_private_hold_routes_state absent || return 1
    mvc24gd4_write_marker private-hold-route-add-attempt || return 1
    MVC24GD4_STAGE=private-hold-route-add-outcome-uncertain
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        set +e
        ip -4 route add unreachable "$prefix" proto "${MVC24GD4_HOLD_PROTO:-187}" metric "${MVC24GD4_HOLD_METRIC:-4241}" >/dev/null 2>&1
        rc=$?
        set -e
        # No mutation retry. Exact full inventory below is authoritative.
        : "$rc"
    done
    mvc24gd4_private_hold_routes_state full || return 1
    # The live WG route must still win while both routes have the same prefix.
    mvc24gd4_dual_active_observed || return 1
    MVC24GD4_STAGE=private-hold-routes-observed-wireguard-still-active
}

mvc24gd4_disconnect_wg() {
    (( $# == 0 )) || return 1
    local rc
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == private-hold-routes-observed-wireguard-still-active ]] || return 1
    mvc24gd4_private_hold_routes_state full && mvc24gd4_dual_active_observed || return 1
    mvc24gd4_write_marker disconnect-attempt || return 1
    MVC24GD4_STAGE=wireguard-disconnect-outcome-uncertain
    set +e
    nmcli --wait 60 connection down uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    MVC24GD4_NM_DOWN_EXIT_STATUS=$rc
    # Like C19, outcome is based on bounded authoritative post-state, not the
    # client exit status alone. Never issue a second down command.
    mvc24gd4_wg_down_observed && mvc24gd4_private_hold_routes_state full || return 1
    MVC24GD4_STAGE=wireguard-down-parallel-guard-retained-private-hold
}

mvc24gd4_write_openvpn_restore_candidate() {
    (( $# == 7 )) || return 1
    local underlay=$1 source=$2 remote=$3 port=$4 tunnel=$5 tun_source=$6 out=$7
    mvc24gc11_parameters "$underlay" "$source" "$remote" "$port" "$tunnel" "$tun_source" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == '600:1' ]] || return 1

    # D4 -> C11 handback differs from the original C1 -> C11 transition:
    # D4 added a WireGuard transport allowance to both inet OUTPUT and the
    # netdev underlay egress chain. Restore both owner chains atomically so no
    # stale WG physical-egress exception survives after WG is down. Reuse C1's
    # exact underlay reconstruction, then append the proven C11 tunnel rule.
    mvc24gc1_write_batch "$underlay" "$source" "$remote" "$port" "$out" || return 1
    printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' \
      "$tunnel" "$tun_source" >> "$out"
}

mvc24gd4_restore_openvpn_guard() {
    (( $# == 0 )) || return 1
    local scratch batch before1 before2 after1 after2
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == wireguard-down-parallel-guard-retained-private-hold ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/mvc-c23ai-restore.XXXXXXXX) || return 1
    batch=$scratch/ovpn.nft before1=$scratch/before1.json before2=$scratch/before2.json after1=$scratch/after1.json after2=$scratch/after2.json
    (umask 077; : > "$batch") || { rm -rf -- "$scratch"; return 1; }
    chmod 600 -- "$batch" || { rm -rf -- "$scratch"; return 1; }
    if ! mvc24gb1_capture_nft "$before1" || ! mvc24gb1_capture_nft "$before2" || ! cmp -s -- "$before1" "$before2" ||
       ! mvc24gd4_parallel_guard_observation "$before1" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" \
          "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" \
          "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" \
          "${MVC24GD4_ALLOWED_IPS[@]}" || ! mvc24gd4_foreign_policy_unchanged "$before1" ||
       ! mvc24gd4_write_openvpn_restore_candidate "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" \
          "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" "$batch" || ! nft --check --file "$batch" >/dev/null 2>&1; then
        rm -rf -- "$scratch"; return 1
    fi
    mvc24gd4_write_marker guard-restore-attempt || { rm -rf -- "$scratch"; return 1; }
    MVC24GD4_STAGE=openvpn-guard-restore-outcome-uncertain
    if ! nft --file "$batch" >/dev/null 2>&1; then rm -rf -- "$scratch"; return 1; fi
    if ! mvc24gb1_capture_nft "$after1" || ! mvc24gb1_capture_nft "$after2" || ! cmp -s -- "$after1" "$after2" ||
       ! mvc24gc11_postshape_observation "$after1" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" ||
       ! mvc24gd4_foreign_policy_unchanged "$after1"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    mvc24gd4_private_hold_routes_state full || return 1
    MVC24GD4_STAGE=pure-openvpn-guard-restored-route-profile-remain-private-hold
}

mvc24gd4_delete_endpoint_route() {
    (( $# == 0 )) || return 1
    local -a argv
    local shown rc
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == pure-openvpn-guard-restored-route-profile-remain-private-hold ]] || return 1
    mvc24gd4_endpoint_route_observed || return 1
    mvc24gd4_write_marker route-delete-attempt || return 1
    argv=(-4 route del "$MVC24GD4_ENDPOINT_IP/32")
    [[ $MVC24GD4_UNDERLAY_GATEWAY == - ]] || argv+=(via "$MVC24GD4_UNDERLAY_GATEWAY")
    argv+=(dev "$MVC24GD4_UNDERLAY" src "$MVC24GD4_UNDERLAY_SOURCE" proto 186 metric 4240)
    MVC24GD4_STAGE=endpoint-route-delete-outcome-uncertain
    set +e
    ip "${argv[@]}"
    rc=$?
    set -e
    shown=$(ip -4 route show exact "$MVC24GD4_ENDPOINT_IP/32" table main) || return 1
    [[ -z $shown ]] || return 1
    mvc24gd4_private_hold_routes_state full || return 1
    MVC24GD4_STAGE=owned-endpoint-route-absent-profile-remains-private-hold
}

mvc24gd4_delete_profile() {
    (( $# == 0 )) || return 1
    local rc found
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == owned-endpoint-route-absent-profile-remains-private-hold ]] || return 1
    mvc24gd4_wg_down_observed || return 1
    mvc24gd4_write_marker profile-delete-attempt || return 1
    MVC24GD4_STAGE=temporary-profile-delete-outcome-uncertain
    set +e
    nmcli --wait 30 connection delete uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    if nmcli --wait 10 -g connection.uuid connection show uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1; then
        return 1
    fi
    # NM normally removes the keyfile. If the connection is authoritatively
    # absent but the exact root-owned /run keyfile remains, remove only that
    # known temporary file after confirming it still carries our UUID.
    if [[ -e $MVC24GD4_TEMP_FILE || -L $MVC24GD4_TEMP_FILE ]]; then
        [[ -f $MVC24GD4_TEMP_FILE && ! -L $MVC24GD4_TEMP_FILE &&
           $(stat -c '%u:%a:%h' -- "$MVC24GD4_TEMP_FILE") == '0:600:1' &&
           $(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection uuid) == "$MVC24GD4_TEMP_UUID" ]] || return 1
        rm -f -- "$MVC24GD4_TEMP_FILE" || return 1
    fi
    mvc24gd4_temp_profile_absent || return 1
    mvc24gd4_private_hold_routes_state full || return 1
    MVC24GD4_STAGE=temporary-profile-absent-pure-openvpn-protected-private-hold
}

mvc24gd4_finish_teardown() {
    (( $# == 0 )) || return 1
    local route_now scratch first second
    mvc24gd4_authority_witness || return 1
    [[ ${MVC24GD4_STAGE:-} == temporary-profile-absent-pure-openvpn-protected-private-hold ]] || return 1
    route_now=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    [[ $route_now == "${MVC24GC6_ROUTE_SNAPSHOT:-}" ]] && mvc24gd4_openvpn_default_route_observed || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/mvc-c23ai-final.XXXXXXXX) || return 1
    first=$scratch/first.json second=$scratch/second.json
    if ! mvc24gb1_capture_nft "$first" || ! mvc24gb1_capture_nft "$second" || ! cmp -s -- "$first" "$second" ||
       ! mvc24gc11_postshape_observation "$first" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" ||
       ! mvc24gd4_foreign_policy_unchanged "$first"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    mvc24gd4_private_hold_routes_state full || return 1
    [[ -d $MVC24GD4_RUNTIME && ! -L $MVC24GD4_RUNTIME ]] || return 1
    MVC24GD4_STAGE=wireguard-residue-removed-openvpn-protected-private-hold
}

mvc24gd4_stop_once() {
    (( $# == 0 )) || return 1
    mvc24gd4_add_private_hold_routes || return 1
    mvc24gd4_disconnect_wg || return 1
    mvc24gd4_restore_openvpn_guard || return 1
    mvc24gd4_delete_endpoint_route || return 1
    mvc24gd4_delete_profile || return 1
    mvc24gd4_finish_teardown
}



mvc24gd4_post_openvpn_cleanup_witness() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GCU_AUTHORITY:-none} == private-local-console &&
       ${MVC24GCU_APPROVAL:-none} == approved-process-local &&
       ${MVC24GCU_OPERATION:-none} == session &&
       ${MVC24GCO_MODE:-disabled} == private-live-local-console &&
       ${MVC24GCO_AUTHORITY:-none} == private-local-console &&
       ${MVC24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
       ${MVC24GCU_STAGE:-} == stopped-c1-held &&
       ${MVC24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid && mvc24gb4_no_active_vpn || return 1
}

mvc24gd4_release_private_hold_after_openvpn_stop() {
    (( $# == 0 )) || return 1
    local prefix rc output
    mvc24gd4_post_openvpn_cleanup_witness || return 1
    case ${MVC24GD4_STAGE:-} in
      wireguard-residue-removed-openvpn-protected-private-hold|wireguard-residue-removed-openvpn-absent-c11-private-hold) ;;
      *) return 1 ;;
    esac
    mvc24gd4_private_hold_routes_state full || return 1
    mvc24gd4_write_marker private-hold-route-delete-attempt || return 1
    MVC24GD4_STAGE=private-hold-route-delete-outcome-uncertain-openvpn-down
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        set +e
        ip -4 route del unreachable "$prefix" proto "${MVC24GD4_HOLD_PROTO:-187}" metric "${MVC24GD4_HOLD_METRIC:-4241}" >/dev/null 2>&1
        rc=$?
        set -e
        : "$rc"
    done
    mvc24gd4_private_hold_routes_state absent || return 1
    [[ -d $MVC24GD4_RUNTIME && ! -L $MVC24GD4_RUNTIME ]] || return 1
    rm -rf -- "$MVC24GD4_RUNTIME" || return 1
    MVC24GD4_STAGE=wireguard-teardown-complete-openvpn-stopped-no-private-hold
}

mvc24gd4_authorize_public_activation() { return 1; }
mvc24gd4_authorize_public_cleanup() { return 1; }
mvc24gd4_authorize_automatic_retry() { return 1; }
mvc24gd4_authorize_automatic_disarm() { return 1; }
