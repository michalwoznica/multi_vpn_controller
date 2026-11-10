#!/usr/bin/env bash
# Gate C11: PRIVATE / NON-ADMITTING candidate for a single atomic C1 ->
# IPv4 tunnel-OUTPUT rule change. Pure construction and read-only verification.
# This file NEVER calls nft to commit; it has no host/production entry point.
# Forward, bridge and netdev protections stay unchanged; IPv6 is not admitted.
# DNS correctness, remote peer authenticity and teardown are NOT proven here.

mvc24gc11_reset() {
    MVC24GC11_STAGE=unverified
    MVC24GC11_AUTHORITY=none
    MVC24GC11_TUNNEL=
    MVC24GC11_TUNNEL_SOURCE=
}
mvc24gc11_authorize_public_activation() { return 1; }
mvc24gc11_authorize_traffic() { return 1; }
mvc24gc11_authorize_commit() { return 1; }
mvc24gc11_authorize_cleanup() { return 1; }
mvc24gc11_authorize_disarm() { return 1; }
mvc24gc11_authorize_retry() { return 1; }
mvc24gc11_authorize_secret_export() { return 1; }

# B1 deliberately rejects tun*/wg* as PHYSICAL underlays. C11 must not
# reuse that validator for the tunnel: doing so rejects every tun* candidate.
# Keep both roles independently constrained; only the tunnel may use this
# prefix, and only a kernel-valid, literal interface name is accepted.
mvc24gc11_valid_tunnel_ifname() {
    (( $# == 1 )) || return 1
    local tunnel=$1
    [[ $tunnel =~ ^tun[a-zA-Z0-9_.-]*$ && ${#tunnel} -le 15 ]]
}

mvc24gc11_parameters() {
    (( $# == 6 )) || return 1
    local underlay=$1 source=$2 remote=$3 port=$4 tunnel=$5 tun_source=$6
    mvc24gc1_parameters "$underlay" "$source" "$remote" "$port" || return 1
    mvc24gc11_valid_tunnel_ifname "$tunnel" &&
      [[ $tunnel != "$underlay" ]] && mvc24gc1_ipv4 "$tun_source" &&
      [[ $tun_source != "$source" ]] || return 1
}

# Exactly FIVE commands, as one prospective nft --file transaction.
# Explicitly retains the existing pinned transport exception. No wildcard
# WAN allow, no IPv6 allow, and NO changes to FORWARD, bridge or netdev hooks.
mvc24gc11_write_candidate() {
    (( $# == 7 )) || return 1
    local underlay=$1 source=$2 remote=$3 port=$4 tunnel=$5 tun_source=$6 out=$7
    mvc24gc11_parameters "$underlay" "$source" "$remote" "$port" "$tunnel" "$tun_source" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == '600:1' ]] || return 1
    {
        printf '%s\n' 'flush chain inet mvc_preclone_quarantine output_deny'
        printf '%s\n' 'add rule inet mvc_preclone_quarantine output_deny oifname "lo" accept'
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$underlay"
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' "$underlay" "$source" "$remote" "$port"
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' "$tunnel" "$tun_source"
    } > "$out"
}

# Prospective *post-commit* nft JSON, NOT permission to commit. Reject any
# extra or changed owned rules, including permissive FORWARD, bridge, netdev,
# IPv6 and physical-interface exceptions. Numeric EtherType ARP compatibility
# is identical to kernel-confirmed C1 (symbolic, 2054, byte-swapped 1544).
mvc24gc11_postshape_observation() {
    (( $# == 7 )) || return 1
    local file=$1 underlay=$2 source=$3 remote=$4 port=$5 tunnel=$6 tun_source=$7
    mvc24gc11_parameters "$underlay" "$source" "$remote" "$port" "$tunnel" "$tun_source" || return 1
    [[ -f $file && ! -L $file ]] || return 1
    jq -e --arg iface "$underlay" --arg src "$source" --arg dst "$remote" \
       --argjson port "$port" --arg tun "$tunnel" --arg tun_src "$tun_source" '
       def matchv($left;$right): {match:{op:"==",left:$left,right:$right}};
       def meta($key): {meta:{key:$key}};
       def payload($protocol;$field): {payload:{protocol:$protocol,field:$field}};
       def owned($v): ($v|type=="object") and
         (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
          ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
          ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
       def ipv4dep: . == matchv(meta("nfproto");"ipv4") or
          . == matchv(meta("nfproto");"ip") or
          . == matchv(payload("ether";"type");"ip") or
          . == matchv(payload("ether";"type");2048);
       def tcpdep: . == matchv(meta("l4proto");"tcp") or
          . == matchv(payload("ip";"protocol");"tcp") or
          . == matchv(payload("ip";"protocol");6);
       def udpdep: . == matchv(meta("l4proto");"udp") or
          . == matchv(payload("ip";"protocol");"udp") or
          . == matchv(payload("ip";"protocol");17);
       def expr($value;$expected;$extra;$proto):
          ($value|type)=="array" and ($value|length)<=($expected|length)+$extra and
          ($value|last)=={accept:null} and
          ([ $value[] | select((ipv4dep or
             (if $proto=="tcp" then tcpdep elif $proto=="udp" then udpdep else false end))|not) ] == $expected);
       def arp($value):
          $value == [matchv(payload("ether";"type");"arp"),{accept:null}] or
          $value == [matchv(payload("ether";"type");2054),{accept:null}] or
          $value == [matchv(payload("ether";"type");1544),{accept:null}];
       def chain($family;$table;$name):
          [.nftables[] | .chain? | select(.family==$family and .table==$table and .name==$name)];
       def rules($family;$table;$name):
          [.nftables[] | .rule? | select(.family==$family and .table==$table and .chain==$name) | .expr];
       (.nftables|type)=="array" and
       ([.nftables[]|to_entries[]|select(.key!="metainfo" and owned(.value))|.key]|sort)==
          (["table","table","table","chain","chain","chain","chain","rule","rule","rule","rule","rule","rule","rule"]|sort) and
       ([.nftables[]|.table?|select(owned(.))|[.family,.name]]|sort)==
          ([ ["inet","mvc_preclone_quarantine"], ["bridge","mvc_preclone_bridge"],
             ["netdev","mvc_preclone_underlay"] ]|sort) and
       (chain("inet";"mvc_preclone_quarantine";"output_deny")|length)==1 and
       (chain("inet";"mvc_preclone_quarantine";"output_deny")[0]|
          .hook=="output" and .prio== -310 and .policy=="drop") and
       (chain("inet";"mvc_preclone_quarantine";"forward_deny")|length)==1 and
       (chain("inet";"mvc_preclone_quarantine";"forward_deny")[0]|
          .hook=="forward" and .prio== -310 and .policy=="drop") and
       (chain("bridge";"mvc_preclone_bridge";"forward_deny")|length)==1 and
       (chain("bridge";"mvc_preclone_bridge";"forward_deny")[0]|
          .hook=="forward" and .prio== -310 and .policy=="drop") and
       (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")|length)==1 and
       (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")[0]|
          .hook=="egress" and .dev==$iface and .prio== -310 and .policy=="drop") and
       (rules("inet";"mvc_preclone_quarantine";"output_deny") as $out|
          ($out|length)==4 and
          $out[0]==[matchv(meta("oifname");"lo"),{accept:null}] and
          expr($out[1];[matchv(meta("oifname");$iface),
             matchv(payload("udp";"sport");68),matchv(payload("udp";"dport");67),
             {accept:null}];3;"udp") and
          expr($out[2];[matchv(meta("oifname");$iface),
             matchv(payload("ip";"saddr");$src),matchv(payload("ip";"daddr");$dst),
             matchv(payload("tcp";"dport");$port),{accept:null}];3;"tcp") and
          expr($out[3];[matchv(meta("oifname");$tun),
             matchv(payload("ip";"saddr");$tun_src),{accept:null}];1;"none")) and
       (rules("netdev";"mvc_preclone_underlay";"lowerdev_deny") as $dev|
          ($dev|length)==3 and arp($dev[0]) and
          expr($dev[1];[matchv(payload("udp";"sport");68),
             matchv(payload("udp";"dport");67),{accept:null}];3;"udp") and
          expr($dev[2];[matchv(payload("ip";"saddr");$src),
             matchv(payload("ip";"daddr");$dst),matchv(payload("tcp";"dport");$port),
             {accept:null}];3;"tcp"))
    ' "$file" >/dev/null 2>&1
}

# Source the C9/C7/C6/C5 libraries first. This bridge generates only a
# *prospective* nft batch. Even a successful positive candidate cannot be
# installed: commit/traffic witnesses always deny; no nft writer is present.
mvc24gc11_candidate_after_c9() {
    (( $# == 1 )) || return 1
    local out=$1 nm1 nm2 route1 route2 underlay source tunnel tun_source
    MVC24GC11_STAGE=unverified
    MVC24GC11_AUTHORITY=none
    MVC24GC11_TUNNEL= MVC24GC11_TUNNEL_SOURCE=
    [[ ${MVC24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard &&
       ${MVC24GC9_AUTHORITY:-} == none &&
       ${MVC24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${MVC24GC7_AUTHORITY:-} == none &&
       ${MVC24GC8_STAGE:-} == nm-source-clone-metadata-consistent-password-delivery-unproven &&
       ${MVC24GC8_AUTHORITY:-} == none &&
       ${MVC24GC6_STAGE:-} == nm-active-and-selected-ipv4-tun-observed-no-traffic-authority &&
       ${MVC24GC6_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid || return 1
    # The typed GetSettings capture layer still requires the legacy
    # MVC24S_LOCK_HELD assertion. C9's dynamically scoped marker ends when C9
    # returns, but C11 runs later under the same genuine B2 flock. Re-bind the
    # marker only after independently proving that real lock here; the marker
    # itself grants no authority and cannot substitute for the flock witness.
    local MVC24S_LOCK_HELD=1
    mvc24gc3_transition_records_valid && mvc24gc5_guard_witness &&
       mvc24gc5_prepared_profile_witness && mvc24gc7_read_intent || return 1
    [[ ${MVC24GC7_CLONE_UUID:-} == "${MVC24GA3_PREPARED_CLONE_UUID:-}" &&
       ${MVC24GC7_NM_OWNER:-} == "${MVC24GC5_NM_OWNER:-}" ]] || return 1
    nm1=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") || return 1
    route1=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    route2=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    nm2=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") || return 1
    [[ -n $nm1 && $nm1 == "$nm2" && $nm1 == "${MVC24GC6_NM_SNAPSHOT:-}" &&
       -n $route1 && $route1 == "$route2" && $route1 == "${MVC24GC6_ROUTE_SNAPSHOT:-}" ]] || return 1
    IFS='|' read -r underlay source tunnel tun_source <<< "$route1"
    mvc24gc11_parameters "$underlay" "$source" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$tunnel" "$tun_source" &&
       [[ $underlay == "$MVC24GC3_IFACE" && $source == "$MVC24GC3_SOURCE" ]] || return 1
    mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness &&
       mvc24gc3_transition_records_valid && mvc24gc7_read_intent || return 1
    mvc24gc11_write_candidate "$underlay" "$source" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$tunnel" "$tun_source" "$out" || return 1
    MVC24GC11_TUNNEL=$tunnel MVC24GC11_TUNNEL_SOURCE=$tun_source
    MVC24GC11_STAGE=prospective-ipv4-host-tunnel-output-only-no-commit-authority
}
