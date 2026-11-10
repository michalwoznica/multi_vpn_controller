#!/usr/bin/env bash
# Gate C1 — quarantined host -> pinned OpenVPN TCP underlay bootstrap.
# This library is NOT imported by the public controller/maintenance driver.
# Both independent authority witnesses below are DENY by default. They must
# never be overridden by environment variables or caller-supplied booleans.
# No clone, VPN start, policy disarm or cleanup authority is conferred.
# Requires B1/B2 libraries sourced first. Bash-only production dependencies.

mvc24gc1_reset() {
    MVC24GC1_ATTEMPTED=no
    MVC24GC1_STAGE=unverified
    MVC24GC1_AUTHORITY=none
}

mvc24gc1_guard_witness() {
    declare -F mvc24gc2_guard_witness >/dev/null && mvc24gc2_guard_witness
}
mvc24gc1_endpoint_witness() {
    declare -F mvc24gc2_endpoint_witness >/dev/null && mvc24gc2_endpoint_witness "$@"
}

mvc24gc1_ipv4() {
    (( $# == 1 )) && [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local -a octets
    IFS=. read -r -a octets <<< "$1"
    (( ${#octets[@]} == 4 )) || return 1
    local octet
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( 10#$octet <= 255 )) || return 1
    done
}

mvc24gc1_port() {
    (( $# == 1 )) && [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 ))
}

mvc24gc1_parameters() {
    (( $# == 4 )) || return 1
    mvc24gb1_valid_ifname "$1" && mvc24gc1_ipv4 "$2" &&
       mvc24gc1_ipv4 "$3" && mvc24gc1_port "$4" && [[ $2 != "$3" ]]
}

# Exactly eight statements, in ONE nft --file transaction. Forwarding hooks
# remain unchanged (drop). Base-chain policy remains drop, even on an error.
# Explicit ARP is required for IPv4 next-hop discovery; not arbitrary IP/DNS.
mvc24gc1_write_batch() {
    (( $# == 5 )) || return 1
    local iface=$1 source=$2 remote=$3 port=$4 out=$5
    mvc24gc1_parameters "$iface" "$source" "$remote" "$port" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == '600:1' ]] || return 1
    {
        printf '%s\n' 'flush chain inet mvc_preclone_quarantine output_deny'
        printf '%s\n' 'add rule inet mvc_preclone_quarantine output_deny oifname "lo" accept'
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$iface"
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' "$iface" "$source" "$remote" "$port"
        printf '%s\n' 'flush chain netdev mvc_preclone_underlay lowerdev_deny'
        printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type arp accept'
        printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
        printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s tcp dport %s accept\n' "$source" "$remote" "$port"
    } > "$out"
}

mvc24gc1_batch_valid() {
    (( $# == 5 )) || return 1
    local expected=$5 scratch
    [[ -f $expected && ! -L $expected ]] || return 1
    scratch=$(mktemp "$(dirname -- "$expected")/.ubs-v240-c1-verify.XXXXXXXX") || return 1
    chmod 600 "$scratch" || { rm -f "$scratch"; return 1; }
    mvc24gc1_write_batch "$1" "$2" "$3" "$4" "$scratch" || { rm -f "$scratch"; return 1; }
    cmp -s "$scratch" "$expected"
    local ok=$?
    rm -f "$scratch"
    return "$ok"
}

# Strict prospective nft JSON witness. Reject unknown/extra owned objects,
# modified hooks, chain policies, match expressions and rule ordering.
# nftables can emit *additional restrictive protocol dependencies* when it
# lowers source-rule syntax to kernel expressions. The small explicit whitelist
# below strips only those precise narrowing matches (IPv4/TCP), never arbitrary
# expressions, verdicts, or wildcard protocol values. A mismatch stays closed.
mvc24gc1_postshape_observation() {
    (( $# == 5 )) || return 1
    local file=$1 iface=$2 source=$3 remote=$4 port=$5
    mvc24gc1_parameters "$iface" "$source" "$remote" "$port" || return 1
    [[ -f $file && ! -L $file ]] || return 1
    jq -e --arg iface "$iface" --arg src "$source" --arg dst "$remote" --argjson port "$port" '
       def matchv($left;$right): {match:{op:"==",left:$left,right:$right}};
       def meta($key): {meta:{key:$key}};
       def payload($protocol;$field): {payload:{protocol:$protocol,field:$field}};
       def owned($v): ($v|type=="object") and
         (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
          ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
          ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
       # These are equivalent *restrictive* auto-inserted dependencies, not
       # standalone accept rules. In particular udp, ipv6, unknown numeric
       # protocol values and arbitrary extra expressions are never stripped.
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
       def endpoint_expr($expr;$want;$proto):
          ($expr|type)=="array" and ($expr|length)<=($want|length)+3 and
          ($expr|last)=={accept:null} and
          ([ $expr[] | select((ipv4dep or (if $proto=="tcp" then tcpdep else udpdep end))|not) ] == $want);
       # Numeric nft -n output can expose ARP (0x0806) as its native
       # little-endian ether_type value 0x0608 (1544) on x86.
       # Accept these *specific* ARP representations, not other EtherTypes.
       def arp_expr($expr):
          $expr == [matchv(payload("ether";"type");"arp"),{accept:null}] or
          $expr == [matchv(payload("ether";"type");2054),{accept:null}] or
          $expr == [matchv(payload("ether";"type");1544),{accept:null}];
       def chain($family;$table;$chain):
         [.nftables[] | .chain? | select(.family==$family and .table==$table and .name==$chain)];
       def rules($family;$table;$chain):
         [.nftables[] | .rule? | select(.family==$family and .table==$table and .chain==$chain) | .expr];
       (.nftables|type)=="array" and
       ([.nftables[] | to_entries[] | select(.key!="metainfo" and owned(.value)) | .key] | sort) ==
         (["table","table","table","chain","chain","chain","chain","rule","rule","rule","rule","rule","rule"] | sort) and
       ([.nftables[] | .table? | select(owned(.)) | [.family,.name]] | sort) ==
         ([ ["inet","mvc_preclone_quarantine"], ["bridge","mvc_preclone_bridge"],
            ["netdev","mvc_preclone_underlay"] ] | sort) and
       (chain("inet";"mvc_preclone_quarantine";"output_deny")|length)==1 and
        (chain("inet";"mvc_preclone_quarantine";"output_deny")[0] |
            .hook=="output" and .prio== -310 and .policy=="drop") and
       (chain("inet";"mvc_preclone_quarantine";"forward_deny")|length)==1 and
       (chain("inet";"mvc_preclone_quarantine";"forward_deny")[0] |
            .hook=="forward" and .prio== -310 and .policy=="drop") and
       (chain("bridge";"mvc_preclone_bridge";"forward_deny")|length)==1 and
       (chain("bridge";"mvc_preclone_bridge";"forward_deny")[0] |
            .hook=="forward" and .prio== -310 and .policy=="drop") and
       (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")|length)==1 and
       (chain("netdev";"mvc_preclone_underlay";"lowerdev_deny")[0] |
            .hook=="egress" and .dev==$iface and .prio== -310 and .policy=="drop") and
       (rules("inet";"mvc_preclone_quarantine";"output_deny") as $out |
          ($out|length)==3 and
          $out[0] == [matchv(meta("oifname");"lo"), {accept:null}] and
          endpoint_expr($out[1];[matchv(meta("oifname");$iface),
            matchv(payload("udp";"sport");68),matchv(payload("udp";"dport");67),{accept:null}];"udp") and
          endpoint_expr($out[2];[matchv(meta("oifname");$iface),
            matchv(payload("ip";"saddr");$src),
            matchv(payload("ip";"daddr");$dst),
            matchv(payload("tcp";"dport");$port),{accept:null}];"tcp")) and
       (rules("netdev";"mvc_preclone_underlay";"lowerdev_deny") as $underlay |
          ($underlay|length)==3 and arp_expr($underlay[0]) and
          endpoint_expr($underlay[1];[
            matchv(payload("udp";"sport");68),matchv(payload("udp";"dport");67),{accept:null}];"udp") and
          endpoint_expr($underlay[2];[
            matchv(payload("ip";"saddr");$src),
            matchv(payload("ip";"daddr");$dst),
            matchv(payload("tcp";"dport");$port),{accept:null}];"tcp"))
    ' "$file" >/dev/null 2>&1
}

# Journal published before the SINGLE commit attempt. If nft returns an error
# after issuing the command, do not retry, delete any guard, or assume failure.
# The root runtime remains for later independent reconciliation.
mvc24gc1_transition_once() {
    (( $# == 4 )) || return 1
    [[ ${MVC24GC1_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC1_ATTEMPTED=yes
    MVC24GC1_STAGE=blocked-unverified
    MVC24GC1_AUTHORITY=none
    local iface=$1 source=$2 remote=$3 port=$4 dir scratch first second fbefore fafter
    mvc24gc1_parameters "$iface" "$source" "$remote" "$port" || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid && mvc24gb2_attest || return 1
    [[ ${MVC24GB2_STAGE:-} == host-deny-all-attested-observation-only ]] || return 1
    [[ $(mvc24gb2_derive_iface) == "$iface" ]] || return 1
    mvc24gc1_guard_witness && mvc24gc1_endpoint_witness "$iface" "$source" "$remote" "$port" || return 1
    dir=$(mvc24gb2_runtime) || return 1
    [[ ! -e $dir/transition.nft && ! -L $dir/transition.nft &&
       ! -e $dir/transition-attempt && ! -L $dir/transition-attempt ]] || return 1
    scratch=$(mktemp -d /run/mvc-c1.XXXXXXXX) || return 1
    chmod 700 "$scratch" || return 1
    (umask 077; : > "$scratch/transition.nft") || return 1
    chmod 600 "$scratch/transition.nft" || return 1
    mvc24gc1_write_batch "$iface" "$source" "$remote" "$port" "$scratch/transition.nft" || return 1
    nft --check --file "$scratch/transition.nft" >/dev/null 2>&1 || return 1
    first=$scratch/pre1.json; second=$scratch/pre2.json
    mvc24gb1_capture_nft "$first" && mvc24gb1_capture_nft "$second" &&
       cmp -s "$first" "$second" && mvc24gb2_poststate_valid "$first" "$iface" || return 1
    fbefore=$(mvc24gb2_foreign_projection "$dir/prestate.json") || return 1
    fafter=$(mvc24gb2_foreign_projection "$first") || return 1
    [[ $fbefore == "$fafter" ]] || return 1
    # Confirm ownership and provenance again before irreversible publication.
    mvc24gb2_attest && mvc24gc1_guard_witness &&
        mvc24gc1_endpoint_witness "$iface" "$source" "$remote" "$port" || return 1
    (umask 077; set -C; : > "$dir/transition.nft") || return 1
    chmod 400 "$dir/transition.nft" || return 1
    cp "$scratch/transition.nft" "$dir/transition.nft" || return 1
    mvc24gc1_batch_valid "$iface" "$source" "$remote" "$port" "$dir/transition.nft" || return 1
    local boot prepared committed batch
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    prepared=$(sha256sum "$dir/prepare-intent") || return 1
    committed=$(sha256sum "$dir/commit-attempt") || return 1
    batch=$(sha256sum "$dir/transition.nft") || return 1
    (umask 077; set -C; : > "$dir/transition-attempt") || return 1
    chmod 400 "$dir/transition-attempt" || return 1
    printf '%s\n' 'ubs-v240-c1-transition-attempt-v1' 'state=attempted-once' \
        "boot=$boot" "prepare=${prepared%% *}" "commit=${committed%% *}" \
        "batch=${batch%% *}" > "$dir/transition-attempt" || return 1
    MVC24GC1_STAGE=transition-commit-attempted-no-vpn-authority
    nft --file "$dir/transition.nft" >/dev/null 2>&1 || return 1
    mvc24gb1_capture_nft "$scratch/post1.json" &&
       mvc24gb1_capture_nft "$scratch/post2.json" &&
       cmp -s "$scratch/post1.json" "$scratch/post2.json" &&
       mvc24gc1_postshape_observation "$scratch/post1.json" "$iface" "$source" "$remote" "$port" || return 1
    fafter=$(mvc24gb2_foreign_projection "$scratch/post1.json") || return 1
    [[ $fbefore == "$fafter" ]] || return 1
    # Still not a security-admitting witness: exact kernel rule expressions and
    # independent NM source/endpoint binding need validation before C1 can be
    # used for host activation.
    MVC24GC1_STAGE=bootstrap-shape-observed-nonadmitting
    MVC24GC1_AUTHORITY=none
    rm -rf -- "$scratch" || return 1
}

mvc24gc1_authorize_clone() { return 1; }
mvc24gc1_authorize_activation() { return 1; }
mvc24gc1_authorize_cleanup() { return 1; }
mvc24gc1_authorize_disarm() { return 1; }
mvc24gc1_authorize_recovery() { return 1; }
