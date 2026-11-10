#!/usr/bin/env bash
# C23BJ Stage 2 — standalone protected WireGuard compatibility lifecycle.
#
# Reuses the proven D2/D3 profile semantics and D4 immutable WireGuard intent,
# profile publication and endpoint-route ownership, but deliberately does NOT
# reuse D4's OpenVPN-dependent parallel guard.  The standalone guard permits
# only loopback, DHCP, the pinned WG UDP transport and profile-derived private
# AllowedIPs over vpnks-wg.  Ordinary physical/Wi-Fi Internet stays fail-closed.

mvc24gwg_reset() {
    MVC24GWG_STAGE=idle
    MVC24GWG_ATTEMPTED=no
    MVC24GWG_GUARD_BATCH=
    MVC24GWG_RELEASE_BATCH=
}

mvc24gwg_policy_file() {
    local base
    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd) || return 1
    printf '%s\n' "$base/vpn-v240-preclone-quarantine-offline.nft"
}

mvc24gwg_parameters() {
    (( $# >= 6 )) || return 1
    local underlay=$1 underlay_source=$2 wg_tunnel=$3 wg_source=$4 endpoint_ip=$5 endpoint_port=$6
    shift 6
    local prefix
    mvc24gb1_valid_ifname "$underlay" && mvc24gd3_valid_temp_ifname "$wg_tunnel" &&
      [[ $underlay != "$wg_tunnel" && $underlay != lo ]] || return 1
    wg23_validate_ipv4 "$underlay_source" && wg23_validate_ipv4 "$wg_source" &&
      wg23_validate_ipv4 "$endpoint_ip" || return 1
    [[ $endpoint_port =~ ^[0-9]+$ ]] && (( 10#$endpoint_port >= 1 && 10#$endpoint_port <= 65535 )) || return 1
    (( $# >= 1 && $# <= 512 )) || return 1
    mvc24gd2_disjoint_ipv4_prefixes "$@" || return 1
    mvc24gd3_endpoint_not_captured "$endpoint_ip" "$@" || return 1
    for prefix in "$@"; do
        mvc24gd3_private_ipv4_prefix "$prefix" || return 1
        ! mvc24c_cidr_contains "$prefix" "$underlay_source" || return 1
    done
}

mvc24gwg_write_guard_candidate() {
    (( $# >= 7 )) || return 1
    local underlay=$1 underlay_source=$2 wg_tunnel=$3 wg_source=$4 endpoint_ip=$5 endpoint_port=$6 out=$7
    shift 7
    local prefix
    mvc24gwg_parameters "$underlay" "$underlay_source" "$wg_tunnel" "$wg_source" "$endpoint_ip" "$endpoint_port" "$@" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out && $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    {
      printf '%s\n' 'flush chain inet mvc_preclone_quarantine output_deny'
      printf '%s\n' 'add rule inet mvc_preclone_quarantine output_deny oifname "lo" accept'
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$underlay"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay" "$underlay_source" "$endpoint_ip" "$endpoint_port"
      for prefix in "$@"; do
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s accept\n' \
          "$wg_tunnel" "$wg_source" "$prefix"
      done
      printf '%s\n' 'flush chain netdev mvc_preclone_underlay lowerdev_deny'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type arp accept'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
      printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay_source" "$endpoint_ip" "$endpoint_port"
    } > "$out"
}

mvc24gwg_guard_observation() {
    (( $# >= 8 )) || return 1
    local file=$1 underlay=$2 underlay_source=$3 wg_tunnel=$4 wg_source=$5 endpoint_ip=$6 endpoint_port=$7
    shift 7
    local prefixes_json
    [[ -f $file && ! -L $file ]] || return 1
    mvc24gwg_parameters "$underlay" "$underlay_source" "$wg_tunnel" "$wg_source" "$endpoint_ip" "$endpoint_port" "$@" || return 1
    prefixes_json=$(printf '%s\n' "$@" | jq -R -s 'split("\n")|map(select(length>0))') || return 1
    jq -e --arg iface "$underlay" --arg src "$underlay_source" \
      --arg wt "$wg_tunnel" --arg ws "$wg_source" --arg wd "$endpoint_ip" --argjson wp "$endpoint_port" \
      --argjson prefixes "$prefixes_json" '
      def m($l;$r): {match:{op:"==",left:$l,right:$r}};
      def meta($k): {meta:{key:$k}};
      def pay($p;$f): {payload:{protocol:$p,field:$f}};
      def ipv4dep:
        . == m(meta("nfproto");"ipv4") or . == m(meta("nfproto");"ip") or
        . == m(pay("ether";"type");"ip") or . == m(pay("ether";"type");2048);
      def udpdep:
        . == m(meta("l4proto");"udp") or . == m(pay("ip";"protocol");"udp") or . == m(pay("ip";"protocol");17);
      def dep: ipv4dep or udpdep;
      def core: [ .[] | select(dep|not) ];
      def proto_ok($expr;$proto): all($expr[]; if udpdep then $proto=="udp" else true end);
      def rhs($cidr): ($cidr|split("/")) as $p |
        if ($p[1]|tonumber)==32 then $p[0] else {prefix:{addr:$p[0],len:($p[1]|tonumber)}} end;
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
      ([ $prefixes[] | "rule" ]) as $wg_rule_keys |
      ([.nftables[]|to_entries[]|select(.key!="metainfo" and owned(.value))|.key]|sort)==
        ((["table","table","table","chain","chain","chain","chain","rule","rule","rule","rule","rule","rule"] + $wg_rule_keys)|sort) and
      ([.nftables[]|.chain?|select(owned(.))|[.family,.table,.name]]|sort)==
        ([ ["inet","mvc_preclone_quarantine","output_deny"],
           ["inet","mvc_preclone_quarantine","forward_deny"],
           ["bridge","mvc_preclone_bridge","forward_deny"],
           ["netdev","mvc_preclone_underlay","lowerdev_deny"] ]|sort) and
      (chain("inet";"mvc_preclone_quarantine";"output_deny")|length)==1 and
      (chain("inet";"mvc_preclone_quarantine";"output_deny")[0]|.hook=="output" and .prio==-310 and .policy=="drop") and
      (chain("inet";"mvc_preclone_quarantine";"forward_deny")|length)==1 and
      (chain("inet";"mvc_preclone_quarantine";"forward_deny")[0]|.hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("bridge";"mvc_preclone_bridge";"forward_deny")|length)==1 and
      (chain("bridge";"mvc_preclone_bridge";"forward_deny")[0]|.hook=="forward" and .prio==-310 and .policy=="drop") and
      (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")|length)==1 and
      (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")[0]|.hook=="egress" and .dev==$iface and .prio==-310 and .policy=="drop") and
      (rules("inet";"mvc_preclone_quarantine";"output_deny") as $out |
        ($out|map(core)) ==
          ([ [m(meta("oifname");"lo"),{accept:null}],
             [m(meta("oifname");$iface),m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}],
             [m(meta("oifname");$iface),m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$wd),m(pay("udp";"dport");$wp),{accept:null}] ] +
           ($prefixes|map([m(meta("oifname");$wt),m(pay("ip";"saddr");$ws),m(pay("ip";"daddr");rhs(.)),{accept:null}]))) and
        proto_ok($out[0];"none") and proto_ok($out[1];"udp") and proto_ok($out[2];"udp") and
        all(range(3;($out|length)); proto_ok($out[.];"none"))) and
      (rules("inet";"mvc_preclone_quarantine";"forward_deny")|length)==0 and
      (rules("bridge";"mvc_preclone_bridge";"forward_deny")|length)==0 and
      (rules("netdev";"mvc_preclone_underlay";"lowerdev_deny") as $r |
        ($r|length)==3 and arp($r[0]) and
        ($r[1]|core)==[m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}] and
        ($r[2]|core)==[m(pay("ip";"saddr");$src),m(pay("ip";"daddr");$wd),m(pay("udp";"dport");$wp),{accept:null}] and
        proto_ok($r[1];"udp") and proto_ok($r[2];"udp"))
    ' "$file" >/dev/null 2>&1
}

mvc24gwg_capture_guard() {
    (( $# == 1 )) || return 1
    mvc24gb1_capture_nft "$1"
}

mvc24gwg_guard_exact_now() {
    (( $# == 0 )) || return 1
    local scratch a b good=1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-wg-protected-observe.XXXXXXXX) || return 1
    a=$scratch/a.json; b=$scratch/b.json
    if ! mvc24gwg_capture_guard "$a" || ! mvc24gwg_capture_guard "$b" || ! cmp -s -- "$a" "$b" ||
       ! mvc24gwg_guard_observation "$a" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" \
          "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" \
          "${MVC24GD4_ALLOWED_IPS[@]}" || ! mvc24gd4_foreign_policy_unchanged "$a"; then
        good=0
    fi
    rm -f -- "$a" "$b" >/dev/null 2>&1 || good=0
    rmdir -- "$scratch" >/dev/null 2>&1 || good=0
    (( good == 1 ))
}

mvc24gwg_write_release_batch() {
    (( $# == 1 )) || return 1
    local out=$1
    [[ -f $out && ! -L $out && -O $out && ! -s $out && $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    printf '%s\n' \
      'delete table inet mvc_preclone_quarantine' \
      'delete table bridge mvc_preclone_bridge' \
      'delete table netdev mvc_preclone_underlay' > "$out"
}

mvc24gwg_owned_tables_absent_now() {
    (( $# == 0 )) || return 1
    local scratch a b before after good=1 pre=/run/mvc-controller/prestate.json
    [[ -f $pre && ! -L $pre ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-wg-release-observe.XXXXXXXX) || return 1
    a=$scratch/a.json; b=$scratch/b.json
    if ! mvc24gb1_capture_nft "$a" || ! mvc24gb1_capture_nft "$b" || ! cmp -s -- "$a" "$b" ||
       ! mvc24gc23t_owned_tables_absent "$a" || ! mvc24gc23t_owned_tables_absent "$b"; then
        good=0
    else
        before=$(mvc24gb2_foreign_projection "$pre") || good=0
        after=$(mvc24gb2_foreign_projection "$a") || good=0
        [[ $before == "$after" ]] || good=0
    fi
    rm -f -- "$a" "$b" >/dev/null 2>&1 || good=0
    rmdir -- "$scratch" >/dev/null 2>&1 || good=0
    (( good == 1 ))
}

mvc24gwg_publish_release_intent() {
    (( $# == 0 )) || return 1
    local runtime=${MVC24GD4_RUNTIME:-/run/mvc-wireguard} batch tmp boot intent_sha prepare_sha
    [[ -d $runtime && ! -L $runtime && -f $runtime/intent && ! -L $runtime/intent &&
       ! -e $runtime/protected-release-intent && ! -L $runtime/protected-release-intent ]] || return 1
    batch=$runtime/protected-release.nft
    : > "$batch" || return 1
    chmod 600 -- "$batch" || return 1
    mvc24gwg_write_release_batch "$batch" || return 1
    nft --check --file "$batch" >/dev/null 2>&1 || return 1
    chmod 400 -- "$batch" || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    intent_sha=$(mvc24gd4_hash_file "$runtime/intent") || return 1
    prepare_sha=$(mvc24gd4_hash_file /run/mvc-controller/prepare-intent) || return 1
    tmp=$runtime/.protected-release-intent.tmp
    : > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-wireguard-protected-release-v1 \
      state=nft-delete-attempted-once-outcome-uncertain "boot=$boot" \
      "d4_intent=$intent_sha" "controller_prepare=$prepare_sha" \
      "batch=$(mvc24gd4_hash_file "$batch")" > "$tmp" || return 1
    mv -T -- "$tmp" "$runtime/protected-release-intent" || return 1
}

mvc24gwg_release_intent_valid() {
    (( $# == 0 )) || return 1
    local runtime=${MVC24GD4_RUNTIME:-/run/mvc-wireguard} boot
    local -a rows=()
    [[ -f $runtime/protected-release-intent && ! -L $runtime/protected-release-intent &&
       -f $runtime/protected-release.nft && ! -L $runtime/protected-release.nft ]] || return 1
    mapfile -t rows < "$runtime/protected-release-intent" || return 1
    (( ${#rows[@]} == 6 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    [[ ${rows[0]} == ubs-v240-wireguard-protected-release-v1 &&
       ${rows[1]} == state=nft-delete-attempted-once-outcome-uncertain &&
       ${rows[2]} == "boot=$boot" &&
       ${rows[3]} == "d4_intent=$(mvc24gd4_hash_file "$runtime/intent")" &&
       ${rows[4]} == "controller_prepare=$(mvc24gd4_hash_file /run/mvc-controller/prepare-intent)" &&
       ${rows[5]} == "batch=$(mvc24gd4_hash_file "$runtime/protected-release.nft")" ]]
}

mvc24gwg_preflight_readonly() {
    (( $# == 1 )) || return 1
    local wg_name=$1 underlay source_sha temp_uuid endpoint host port ip prefix
    [[ ${MVC24GWG_ATTEMPTED:-no} == no ]] || return 1
    MVC24GWG_STAGE=preflight-fixed-live-roots
    mvc24pubc_fixed_live_roots_absent || return 1
    MVC24GWG_STAGE=preflight-profile-identity
    mvc24pub_bind_wireguard_name "$wg_name" || return 1
    MVC24GWG_STAGE=preflight-underlay
    mvc24gb4_no_active_vpn || return 1
    underlay=$(mvc24gb4_underlay) || return 1
    MVC24GWG_STAGE=preflight-wireguard
    mvc24gd2_assess_saved_profile "$MVC24PUB_WG_UUID" "$underlay" || return 1
    (( ${MVC24GD2_PEER_COUNT:-0} == 1 && ${#MVC24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    mvc24gd3_keyfile_ipv4_source "$MVC24GD2_KEYFILE" || return 1
    for prefix in "${MVC24GD2_ALLOWED_IPS[@]}"; do mvc24gd3_private_ipv4_prefix "$prefix" || return 1; done
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    source_sha=$(mvc24gd4_hash_file "$MVC24GD2_KEYFILE") || return 1
    temp_uuid=$(cat /proc/sys/kernel/random/uuid) || return 1
    mvc24_valid_uuid "$temp_uuid" || return 1
    endpoint=${MVC24GD2_ENDPOINT_CANDIDATES[0]:-}
    [[ $endpoint == *:* && $endpoint != *:*:* ]] || return 1
    ip=${endpoint%:*}; port=${endpoint##*:}
    wg23_validate_ipv4 "$ip" && [[ $port =~ ^[0-9]+$ ]] || return 1

    MVC24PUBC_MODE=wireguard-protected
    MVC24PUBC_WG_NAME=$wg_name
    MVC24PUBC_OVPN_NAME=-
    MVC24PUBC_WG_UUID=$MVC24PUB_WG_UUID
    MVC24PUBC_OVPN_UUID=-
    MVC24PUBC_UNDERLAY=$underlay
    MVC24PUBC_NM_OWNER=-
    MVC24PUBC_SOURCE_FILE=$MVC24GD2_KEYFILE
    MVC24PUBC_SOURCE_SHA=$source_sha
    MVC24PUBC_WG_SOURCE=$MVC24GD3_WG_SOURCE_IP
    MVC24PUBC_TEMP_UUID=$temp_uuid

    mvc24gd4_prepare_from_preflight "$MVC24PUBC_WG_UUID" "$MVC24PUBC_SOURCE_FILE" "$MVC24PUBC_SOURCE_SHA" \
      "$MVC24PUBC_WG_SOURCE" "$underlay" "$MVC24GD2_UNDERLAY_SOURCE" "$MVC24GD2_UNDERLAY_GATEWAY" "$temp_uuid" || return 1
    MVC24GD4_ENDPOINT_IP=$ip
    MVC24GD4_ENDPOINT_PORT=$port
    MVC24GD4_ALLOWED_IPS=("${MVC24GD2_ALLOWED_IPS[@]}")
    MVC24GD4_STAGE=protected-endpoint-resolved-no-wireguard-mutation-yet
    mvc24pubc_fixed_live_roots_absent || return 1
    MVC24GWG_STAGE=fresh-public-wireguard-protected-readonly-eligible
}

mvc24gwg_install_b2() {
    (( $# == 0 )) || return 1
    local policy
    policy=$(mvc24gwg_policy_file) || return 1
    [[ ${MVC24GWG_STAGE:-} == authorizing-public-connect ]] || return 1
    mvc24pub_connect_admission_witness || return 1
    MVC24GWG_STAGE=b2-install-outcome-uncertain
    mvc24gb2_install_once "$MVC24PUBC_UNDERLAY" "$policy" || return 1
    [[ ${MVC24GB2_STAGE:-} == host-deny-all-attested-observation-only && ${MVC24GB2_AUTHORITY:-} == none ]] || return 1
    MVC24GWG_STAGE=b2-quarantine-observed
}

mvc24gwg_extend_guard() {
    (( $# == 0 )) || return 1
    local scratch batch before1 before2 after1 after2
    [[ ${MVC24GD4_STAGE:-} == owned-endpoint-route-observed && ${MVC24GWG_STAGE:-} == b2-quarantine-observed ]] || return 1
    mvc24gd4_authority_witness || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-wg-protected-guard.XXXXXXXX) || return 1
    batch=$scratch/protected.nft; before1=$scratch/before1.json; before2=$scratch/before2.json; after1=$scratch/after1.json; after2=$scratch/after2.json
    : > "$batch" || { rm -rf -- "$scratch"; return 1; }
    chmod 600 -- "$batch" || { rm -rf -- "$scratch"; return 1; }
    if ! mvc24gb1_capture_nft "$before1" || ! mvc24gb1_capture_nft "$before2" || ! cmp -s -- "$before1" "$before2" ||
       ! mvc24gb2_poststate_valid "$before1" "$MVC24GD4_UNDERLAY" || ! mvc24gd4_foreign_policy_unchanged "$before1" ||
       ! mvc24gwg_write_guard_candidate "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" "$MVC24GD4_TEMP_NAME" \
          "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" "$batch" "${MVC24GD4_ALLOWED_IPS[@]}" ||
       ! nft --check --file "$batch" >/dev/null 2>&1; then
        rm -rf -- "$scratch"; return 1
    fi
    mvc24gd4_write_marker protected-guard-attempt || { rm -rf -- "$scratch"; return 1; }
    MVC24GWG_STAGE=protected-guard-commit-outcome-uncertain
    if ! nft --file "$batch" >/dev/null 2>&1; then rm -rf -- "$scratch"; return 1; fi
    if ! mvc24gb1_capture_nft "$after1" || ! mvc24gb1_capture_nft "$after2" || ! cmp -s -- "$after1" "$after2" ||
       ! mvc24gwg_guard_observation "$after1" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" "$MVC24GD4_TEMP_NAME" \
          "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" "${MVC24GD4_ALLOWED_IPS[@]}" ||
       ! mvc24gd4_foreign_policy_unchanged "$after1"; then
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch"
    MVC24GWG_STAGE=protected-guard-observed-wg-inactive
}

mvc24gwg_authority_witness() {
    (( $# == 0 )) || return 1
    if [[ ${MVC24PUBC_MODE:-none} == wireguard-protected &&
          ${MVC24PUBC_OPERATION:-none} == connect &&
          ${MVC24PUBC_APPROVAL:-none} == approved-process-local &&
          ${MVC24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        mvc24pub_connect_admission_witness && mvc24gb2_root_scope && mvc24gb2_lock_valid
        return
    fi
    if [[ ${MVC24PUBD_SESSION_MODE:-none} == wireguard-protected &&
          ${MVC24PUBD_OPERATION:-none} == disconnect &&
          ${MVC24PUBD_APPROVAL:-none} == approved-process-local &&
          ${MVC24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]]; then
        case ${MVC24PUBD_STAGE:-idle} in
          reobserving-wireguard-protected|stopping-wireguard-protected) ;;
          *) return 1 ;;
        esac
        mvc24gb2_root_scope && mvc24gb2_lock_valid
        return
    fi
    return 1
}

mvc24gwg_active_observed() {
    (( $# == 0 )) || return 1
    local prefix target
    mvc24gwg_authority_witness && mvc24gd4_wg_nm_active && mvc24gd4_wg_kernel_endpoint && mvc24gd4_endpoint_route_observed || return 1
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        target=${prefix%/*}
        mvc24gd4_route_get_json_matches "$target" "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" || return 1
    done
    mvc24gwg_guard_exact_now
}

mvc24gwg_activate() {
    (( $# == 0 )) || return 1
    local rc
    [[ ${MVC24GWG_STAGE:-} == protected-guard-observed-wg-inactive ]] || return 1
    mvc24gd4_write_marker activation-attempt || return 1
    MVC24GWG_STAGE=wireguard-activation-outcome-uncertain
    set +e
    nmcli --wait 60 connection up uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    MVC24GD4_NM_UP_EXIT_STATUS=$rc
    if mvc24gwg_active_observed; then
        MVC24GWG_STAGE=wireguard-only-protected-running
        return 0
    fi
    return 1
}

mvc24gwg_start_once() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GWG_ATTEMPTED:-no} == no ]] || return 1
    MVC24GWG_ATTEMPTED=yes
    mvc24gwg_install_b2 || return 1
    # D4 profile/intent and endpoint-route helpers are transport-generic once
    # the endpoint is already pinned by the standalone read-only preflight.
    mvc24gd4_publish_profile || return 1
    mvc24gd4_add_endpoint_route || return 1
    mvc24gwg_extend_guard || return 1
    mvc24gwg_activate
}

mvc24gwg_temp_profile_inventory_absent() {
    local rows
    rows=$(nmcli --wait 10 --colors no -t -f UUID,TYPE,NAME connection show 2>/dev/null) || return 1
    ! awk -F: -v u="$MVC24GD4_TEMP_UUID" -v n="$MVC24GD4_TEMP_NAME" '$1==u || $3==n {found=1} END{exit(found?0:1)}' <<< "$rows"
}

mvc24gwg_delete_route_once() {
    local -a argv
    local shown rc
    mvc24gd4_endpoint_route_observed || return 1
    argv=(-4 route del "$MVC24GD4_ENDPOINT_IP/32")
    [[ $MVC24GD4_UNDERLAY_GATEWAY == - ]] || argv+=(via "$MVC24GD4_UNDERLAY_GATEWAY")
    argv+=(dev "$MVC24GD4_UNDERLAY" src "$MVC24GD4_UNDERLAY_SOURCE" proto 186 metric 4240)
    set +e; ip "${argv[@]}" >/dev/null 2>&1; rc=$?; set -e
    : "$rc"
    shown=$(ip -4 route show exact "$MVC24GD4_ENDPOINT_IP/32" table main) || return 1
    [[ -z $shown ]]
}

mvc24gwg_delete_profile_once() {
    local rc
    if ! mvc24gwg_temp_profile_inventory_absent; then
        set +e; nmcli --wait 30 connection delete uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1; rc=$?; set -e
        : "$rc"
    fi
    mvc24gwg_temp_profile_inventory_absent || return 1
    if [[ -e ${MVC24GD4_TEMP_FILE:-} || -L ${MVC24GD4_TEMP_FILE:-} ]]; then
        [[ -f $MVC24GD4_TEMP_FILE && ! -L $MVC24GD4_TEMP_FILE ]] || return 1
        local observed
        observed=$(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection uuid) || return 1
        [[ $observed == "$MVC24GD4_TEMP_UUID" ]] || return 1
        rm -f -- "$MVC24GD4_TEMP_FILE" || return 1
    fi
    [[ ! -e ${MVC24GD4_TEMP_FILE:-} && ! -L ${MVC24GD4_TEMP_FILE:-} ]]
}

mvc24gwg_release_guard_once() {
    (( $# == 0 )) || return 1
    local runtime=${MVC24GD4_RUNTIME:-/run/mvc-wireguard} rc
    if [[ ! -f $runtime/protected-release-intent ]]; then
        mvc24gwg_publish_release_intent || return 1
    fi
    mvc24gwg_release_intent_valid || return 1
    if mvc24gwg_owned_tables_absent_now; then return 0; fi
    set +e; nft --file "$runtime/protected-release.nft" >/dev/null 2>&1; rc=$?; set -e
    : "$rc"
    mvc24gwg_owned_tables_absent_now
}

mvc24gwg_controller_topology_restored() {
    (( $# == 0 )) || return 1
    local dir scratch links r4 r6 ok=1
    dir=$(mvc24gb2_runtime) || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-wg-topology.XXXXXXXX) || return 1
    links=$scratch/links.json; r4=$scratch/routes4.json; r6=$scratch/routes6.json
    if ! mvc24gb1_capture_links "$links" || ! mvc24gb1_capture_routes4 "$r4" || ! mvc24gb1_capture_routes6 "$r6"; then
        ok=0
    elif ! cmp -s -- "$links" "$dir/links.json"; then
        ok=0
    elif ! cmp -s -- "$r4" "$dir/routes4.json"; then
        # C23BK: reuse C23T's physically proven narrow NetworkManager
        # connectivity-penalty equivalence. The only accepted difference is
        # exactly one saved underlay default route whose current metric is the
        # saved integer metric + 20000; every other route field/order/member
        # remains byte-semantically identical.
        if ! mvc24gc23t_routes4_nm_connectivity_penalty_equivalent "$dir/routes4.json" "$r4"; then
            ok=0
        fi
    fi
    if (( ok == 1 )) && ! cmp -s -- "$r6" "$dir/routes6.json"; then
        ok=0
    fi
    rm -f -- "$links" "$r4" "$r6" >/dev/null 2>&1 || ok=0
    rmdir -- "$scratch" >/dev/null 2>&1 || ok=0
    (( ok == 1 ))
}

mvc24gwg_network_clean_retirement_pending_observed() {
    (( $# == 0 )) || return 1
    mvc24gwg_owned_tables_absent_now || return 1
    mvc24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    ! wg show "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    mvc24gwg_controller_topology_restored
}

mvc24gwg_retire_runtime_once() {
    (( $# == 0 )) || return 1
    local runtime=${MVC24GD4_RUNTIME:-/run/mvc-wireguard} controller public
    controller=$(mvc24gb2_runtime) || return 1
    public=$(mvc24pub_session_runtime_root) || return 1
    mvc24gwg_owned_tables_absent_now && mvc24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    ! wg show "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    mvc24gwg_controller_topology_restored || return 1
    rm -rf -- "$runtime" || return 1
    [[ ! -e $runtime && ! -L $runtime ]] || return 1
    mvc24gb2_close
    rm -rf -- "$controller" || return 1
    [[ ! -e $controller && ! -L $controller ]] || return 1
    [[ -d $public && ! -L $public && -f $public/transaction && ! -L $public/transaction ]] || return 1
    rm -f -- "$public/transaction" || return 1
    rmdir -- "$public" || return 1
    [[ ! -e $public && ! -L $public ]]
}

mvc24gwg_stop_once() {
    (( $# == 0 )) || return 1
    local rc
    mvc24gwg_active_observed || return 1
    MVC24GWG_STAGE=wireguard-disconnect-outcome-uncertain
    set +e; nmcli --wait 60 connection down uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1; rc=$?; set -e
    : "$rc"
    mvc24gd4_wg_down_observed || return 1
    mvc24gwg_guard_exact_now || return 1
    MVC24GWG_STAGE=wireguard-down-protected-guard-retained
    mvc24gwg_delete_route_once || return 1
    mvc24gwg_delete_profile_once || return 1
    MVC24GWG_STAGE=wireguard-residue-removed-protected-guard-retained
    mvc24gwg_release_guard_once || return 1
    MVC24GWG_STAGE=guard-released-runtime-retirement-pending
    mvc24gwg_retire_runtime_once || return 1
    MVC24GWG_STAGE=wireguard-only-protected-complete-sameboot-ready
}
