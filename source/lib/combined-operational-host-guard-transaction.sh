#!/usr/bin/env bash
# Release Gate B2: host-targeted one-shot quarantine transaction and same-boot
# observation-only reattachment. NOT sourced by the public VPN entry point.
# No host-install command is exposed yet. Never activates VPN, changes DNS or
# allows guard release. Operator-reviewed integration is a separate release gate.
#
# Dependencies (source first): combined-operational-preclone-quarantine-offline.sh
# combined-operational-host-guard-plan.sh
# This module has no environmental authority switches or alternate runtime path.

ubs24gb2_reset() {
    UBS24GB2_STAGE=unverified
    UBS24GB2_AUTHORITY=none
    UBS24GB2_FD=''
    UBS24GB2_ATTEMPTED=no
}

ubs24gb2_runtime() { printf '%s\n' /run/mvc-controller; }

ubs24gb2_root_scope() {
    (( $# == 0 )) && [[ $EUID == 0 ]] || return 1
    [[ $(stat -f -c '%T' /run) == tmpfs &&
       $(readlink /proc/self/ns/net) == "$(readlink /proc/1/ns/net)" &&
       $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" &&
       $(awk '{print $1 ":" $2 ":" $3}' /proc/self/uid_map) == '0:0:4294967295' ]]
}

ubs24gb2_runtime_shape() {
    (( $# == 0 )) || return 1
    local dir file mode
    dir=$(ubs24gb2_runtime) || return 1
    [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir") == '0:700:2' ]] || return 1
    local -a entries=()
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    # C1 may append exactly two one-shot records. This only recognises their
    # filesystem shape; it does NOT grant C1 or release authority. Callers
    # must separately attest the transition journal and live kernel policy.
    (( ${#entries[@]} == 8 || ${#entries[@]} == 10 )) || return 1
    if (( ${#entries[@]} == 10 )); then
        for file in transition.nft transition-attempt; do
            [[ -f $dir/$file && ! -L $dir/$file &&
               $(stat -c '%u:%a:%h' -- "$dir/$file") == '0:400:1' ]] || return 1
        done
    fi
    for file in controller.lock prestate.json batch.nft links.json routes4.json routes6.json prepare-intent commit-attempt; do
        [[ -f $dir/$file && ! -L $dir/$file ]] || return 1
        mode=400
        [[ $file == controller.lock ]] && mode=600
        [[ $(stat -c '%u:%a:%h' -- "$dir/$file") == "0:$mode:1" ]] || return 1
    done
}

ubs24gb2_lock_valid() {
    (( $# == 0 )) && [[ ${UBS24GB2_FD:-} =~ ^[0-9]+$ ]] || return 1
    local dir
    dir=$(ubs24gb2_runtime) || return 1
    [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$UBS24GB2_FD") == \
       "$(stat -c '%d:%i' -- "$dir/controller.lock")" ]]
}

# The intent authenticates original host scope, policy, lowerdev and prestate.
# Only root-held locking + direct kernel observations may later justify a
# surviving-guard finding; a copied record never grants permission on its own.
ubs24gb2_records_valid() {
    (( $# == 0 )) || return 1
    local dir iface='' boot userns netns mntns
    local -a prepared=() committed=()
    dir=$(ubs24gb2_runtime) || return 1
    ubs24gb2_root_scope && ubs24gb2_runtime_shape && ubs24gb2_lock_valid || return 1
    mapfile -t prepared < "$dir/prepare-intent" || return 1
    mapfile -t committed < "$dir/commit-attempt" || return 1
    (( ${#prepared[@]} == 12 && ${#committed[@]} == 4 )) || return 1
    iface=${prepared[6]#underlay=}
    ubs24gb1_valid_ifname "$iface" || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${prepared[0]} == ubs-v240-b2-host-prepare-v1 &&
       ${prepared[1]} == state=prepared-no-activation &&
       ${prepared[2]} == "boot=$boot" &&
       ${prepared[3]} == "userns=$userns" &&
       ${prepared[4]} == "netns=$netns" &&
       ${prepared[5]} == "mntns=$mntns" &&
       ${prepared[6]} == "underlay=$iface" &&
       ${prepared[7]} == "pre=$(sha256sum "$dir/prestate.json" | cut -d' ' -f1)" &&
       ${prepared[8]} == "batch=$(sha256sum "$dir/batch.nft" | cut -d' ' -f1)" &&
       ${prepared[9]} == "links=$(sha256sum "$dir/links.json" | cut -d' ' -f1)" &&
       ${prepared[10]} == "route4=$(sha256sum "$dir/routes4.json" | cut -d' ' -f1)" &&
       ${prepared[11]} == "route6=$(sha256sum "$dir/routes6.json" | cut -d' ' -f1)" ]] || return 1
    [[ ${committed[0]} == ubs-v240-b2-host-commit-attempt-v1 &&
       ${committed[1]} == state=attempted-exactly-once &&
       ${committed[2]} == "boot=$boot" &&
       ${committed[3]} == "prepare=$(sha256sum "$dir/prepare-intent" | cut -d' ' -f1)" ]] || return 1
    ubs24gb2_batch_valid "$iface" "$dir/batch.nft" || return 1
    ubs24op_qg_preflight_snapshot "$dir/prestate.json" &&
        ubs24gb2_prestate_netdev_absent "$dir/prestate.json" &&
        ubs24gb1_links_valid "$iface" "$dir/links.json" &&
        ubs24gb1_routes_valid "$iface" "$dir/routes4.json" "$dir/routes6.json"
}

ubs24gb2_batch_valid() {
    (( $# == 2 )) || return 1
    local iface=$1 batch=$2 base line expected
    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1
    [[ -n $base && -f $base && ! -L $base && -f $batch && ! -L $batch ]] || return 1
    [[ $(sha256sum "$base" | cut -d' ' -f1) == \
       b2e817bf3f22853502f547feef07923e2c4ee5449e520cef6c72189611bd7b03 ]] || return 1
    local -a original=() actual=()
    mapfile -t original < <(grep '^add ' -- "$base") || return 1
    mapfile -t actual < "$batch" || return 1
    (( ${#original[@]} == 5 && ${#actual[@]} == 9 )) || return 1
    local i
    for (( i=0; i<5; i++ )); do [[ ${actual[i]} == "${original[i]}" ]] || return 1; done
    [[ ${actual[5]} == 'add table netdev mvc_preclone_underlay' &&
       ${actual[6]} == "add chain netdev mvc_preclone_underlay lowerdev_deny { type filter hook egress device \"$iface\" priority -310; policy drop; }" &&
       ${actual[7]} == "add rule inet mvc_preclone_quarantine output_deny oifname \"$iface\" ip protocol udp udp sport 68 udp dport 67 accept" &&
       ${actual[8]} == 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept' ]]
}

ubs24gb2_prestate_netdev_absent() {
    (( $# == 1 )) && jq -e '
       [ .nftables[] | to_entries[] | select(.key != "metainfo") | .value |
          select(type=="object" and .family=="netdev" and
              (.table // .name // "")=="mvc_preclone_underlay") ] | length==0
    ' -- "$1" >/dev/null 2>&1
}

ubs24gb2_poststate_valid() {
    (( $# == 2 )) || return 1
    local file=$1 iface=$2
    [[ -f $file && ! -L $file ]] && ubs24gb1_valid_ifname "$iface" || return 1
    jq -e --arg iface "$iface" '
      def m($l;$r): {match:{op:"==",left:$l,right:$r}};
      def meta($k): {meta:{key:$k}};
      def pay($p;$f): {payload:{protocol:$p,field:$f}};
      def dep:
        . == m(meta("nfproto");"ipv4") or . == m(meta("nfproto");"ip") or
        . == m(pay("ether";"type");"ip") or . == m(pay("ether";"type");2048) or
        . == m(meta("l4proto");"udp") or . == m(pay("ip";"protocol");"udp") or
        . == m(pay("ip";"protocol");17);
      def core($expr): [ $expr[] | select(dep|not) ];
      def owned($v): ($v|type=="object") and
        (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
         ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
         ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
      def chain($f;$t;$n): [.nftables[]|.chain?|select(.family==$f and .table==$t and .name==$n)];
      def rules($f;$t;$n): [.nftables[]|.rule?|select(.family==$f and .table==$t and .chain==$n)|.expr];
      (.nftables|type)=="array" and
      ([.nftables[]|to_entries[]|select(.key!="metainfo" and owned(.value))|.key]|sort)==
        (["table","table","table","chain","chain","chain","chain","rule","rule"]|sort) and
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
      (rules("inet";"mvc_preclone_quarantine";"output_deny")|map(core(.)))==
        [[m(meta("oifname");$iface),m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}]] and
      (rules("inet";"mvc_preclone_quarantine";"forward_deny")|length)==0 and
      (rules("bridge";"mvc_preclone_bridge";"forward_deny")|length)==0 and
      (rules("netdev";"mvc_preclone_underlay";"lowerdev_deny")|map(core(.)))==
        [[m(pay("udp";"sport");68),m(pay("udp";"dport");67),{accept:null}]]
    ' -- "$file" >/dev/null 2>&1
}

ubs24gb2_foreign_projection() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    jq -ecS '
      def ours($v):
        ($v | type=="object") and
        (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
         ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
         ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
      if type!="object" or ((keys-["nftables"])|length)!=0 or (.nftables|type)!="array" or
        any(.nftables[]; type!="object" or (keys|length)!=1 or
          (keys[0] | IN("metainfo","table","chain","rule","set","element","flowtable","map","counter","quota","limit","ct helper","ct timeout","ct expectation","synproxy") | not))
      then error("invalid snapshot")
      else [.nftables[] | to_entries[0] as $e | select($e.key!="metainfo" and (ours($e.value)|not))] end
    ' -- "$1" 2>/dev/null
}

ubs24gb2_derive_iface() {
    (( $# == 0 )) || return 1
    local dir
    dir=$(ubs24gb2_runtime) || return 1
    [[ -f $dir/prepare-intent ]] || return 1
    local line
    line=$(sed -n '7p' "$dir/prepare-intent") || return 1
    [[ $line == underlay=* ]] || return 1
    local iface=${line#underlay=}
    ubs24gb1_valid_ifname "$iface" || return 1
    printf '%s\n' "$iface"
}

# This function observes the real kernel directly twice. Its status is only
# attested deny-all protection: NOT an activation-ready VPN firewall policy.
ubs24gb2_attest() {
    (( $# == 0 )) || return 1
    UBS24GB2_STAGE=blocked-unverified
    UBS24GB2_AUTHORITY=none
    local dir scratch first second links r4 r6 iface foreign_before foreign_after
    dir=$(ubs24gb2_runtime) || return 1
    ubs24gb2_records_valid || return 1
    iface=$(ubs24gb2_derive_iface) || return 1
    scratch=$(mktemp -d /run/mvc-b2-observe.XXXXXXXX) || return 1
    chmod 700 "$scratch" || return 1
    first=$scratch/nft1; second=$scratch/nft2
    links=$scratch/links; r4=$scratch/route4; r6=$scratch/route6
    if ! ubs24gb1_capture_nft "$first" || ! ubs24gb1_capture_nft "$second" ||
       ! cmp -s "$first" "$second" ||
       ! ubs24gb2_poststate_valid "$first" "$iface" ||
       ! ubs24gb2_poststate_valid "$second" "$iface" ||
       ! ubs24gb1_capture_links "$links" ||
       ! ubs24gb1_capture_routes4 "$r4" ||
       ! ubs24gb1_capture_routes6 "$r6" ||
       ! cmp -s "$links" "$dir/links.json" ||
       ! cmp -s "$r4" "$dir/routes4.json" ||
       ! cmp -s "$r6" "$dir/routes6.json"; then
        rm -f -- "$first" "$second" "$links" "$r4" "$r6"; rmdir "$scratch"
        return 1
    fi
    foreign_before=$(ubs24gb2_foreign_projection "$dir/prestate.json") || return 1
    foreign_after=$(ubs24gb2_foreign_projection "$first") || return 1
    if [[ $foreign_before != "$foreign_after" ]] || ! ubs24gb2_records_valid; then
        rm -f -- "$first" "$second" "$links" "$r4" "$r6"; rmdir "$scratch"
        return 1
    fi
    rm -f -- "$first" "$second" "$links" "$r4" "$r6" || return 1
    rmdir -- "$scratch" || return 1
    UBS24GB2_STAGE=host-deny-all-attested-observation-only
}

ubs24gb2_reopen() {
    (( $# == 0 )) || return 1
    [[ -z ${UBS24GB2_FD:-} ]] || return 1
    local dir fd
    dir=$(ubs24gb2_runtime) || return 1
    ubs24gb2_root_scope && ubs24gb2_runtime_shape || return 1
    exec {fd}< "$dir/controller.lock" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    UBS24GB2_FD=$fd
    if ! ubs24gb2_attest; then
        ubs24gb2_close
        return 1
    fi
}

ubs24gb2_close() {
    if [[ ${UBS24GB2_FD:-} =~ ^[0-9]+$ ]]; then
        exec {UBS24GB2_FD}>&- || :
    fi
    UBS24GB2_FD=''
    UBS24GB2_STAGE=unverified
    UBS24GB2_AUTHORITY=none
}

ubs24gb2_install_once() {
    (( $# == 2 )) || return 1
    local iface=$1 base=$2 dir scratch file fd stamp first second
    [[ ${UBS24GB2_ATTEMPTED:-no} == no ]] || return 1
    UBS24GB2_ATTEMPTED=yes
    UBS24GB2_STAGE=blocked-unverified
    UBS24GB2_AUTHORITY=none
    ubs24gb2_root_scope && ubs24gb1_valid_ifname "$iface" || return 1
    dir=$(ubs24gb2_runtime) || return 1
    [[ ! -e $dir && ! -L $dir ]] || return 1
    scratch=$(mktemp -d /run/mvc-b2-plan.XXXXXXXX) || return 1
    chmod 700 -- "$scratch" || return 1
    # B1 includes two direct kernel + route/link captures and nft --check.
    ubs24gb1_plan_once "$iface" "$base" "$scratch" || return 1
    mkdir -m 700 -- "$dir" || return 1
    for file in prestate.json batch.nft links.json routes4.json routes6.json; do
        case $file in
            prestate.json) cp -- "$scratch/nft1" "$dir/$file" ;;
            batch.nft) cp -- "$scratch/batch" "$dir/$file" ;;
            links.json) cp -- "$scratch/links1" "$dir/$file" ;;
            routes4.json) cp -- "$scratch/route4a" "$dir/$file" ;;
            routes6.json) cp -- "$scratch/route6a" "$dir/$file" ;;
        esac || return 1
        chmod 400 -- "$dir/$file" || return 1
    done
    (umask 077; set -C; : > "$dir/controller.lock") || return 1
    exec {fd}< "$dir/controller.lock" || return 1
    flock -n "$fd" || return 1
    UBS24GB2_FD=$fd
    [[ $(stat -c '%u:%a:%h' -- "$dir/controller.lock") == '0:600:1' ]] || return 1
    # Revalidate kernel and routing while holding the exclusive lock.
    ubs24gb1_capture_nft "$scratch/locked-nft" || return 1
    ubs24gb1_capture_links "$scratch/locked-links" || return 1
    ubs24gb1_capture_routes4 "$scratch/locked-route4" || return 1
    ubs24gb1_capture_routes6 "$scratch/locked-route6" || return 1
    cmp -s "$scratch/locked-nft" "$dir/prestate.json" &&
      cmp -s "$scratch/locked-links" "$dir/links.json" &&
      cmp -s "$scratch/locked-route4" "$dir/routes4.json" &&
      cmp -s "$scratch/locked-route6" "$dir/routes6.json" || return 1
    stamp=$(mktemp "$dir/.prepare.XXXXXXXX") || return 1
    printf '%s\n' ubs-v240-b2-host-prepare-v1 state=prepared-no-activation \
        "boot=$(cat /proc/sys/kernel/random/boot_id)" \
        "userns=$(readlink /proc/self/ns/user)" \
        "netns=$(readlink /proc/self/ns/net)" \
        "mntns=$(readlink /proc/self/ns/mnt)" \
        "underlay=$iface" \
        "pre=$(sha256sum "$dir/prestate.json" | cut -d' ' -f1)" \
        "batch=$(sha256sum "$dir/batch.nft" | cut -d' ' -f1)" \
        "links=$(sha256sum "$dir/links.json" | cut -d' ' -f1)" \
        "route4=$(sha256sum "$dir/routes4.json" | cut -d' ' -f1)" \
        "route6=$(sha256sum "$dir/routes6.json" | cut -d' ' -f1)" > "$stamp" || return 1
    chmod 400 "$stamp" || return 1
    ln -- "$stamp" "$dir/prepare-intent" || return 1
    rm -f -- "$stamp" || return 1
    stamp=$(mktemp "$dir/.attempt.XXXXXXXX") || return 1
    printf '%s\n' ubs-v240-b2-host-commit-attempt-v1 state=attempted-exactly-once \
        "boot=$(cat /proc/sys/kernel/random/boot_id)" \
        "prepare=$(sha256sum "$dir/prepare-intent" | cut -d' ' -f1)" > "$stamp" || return 1
    chmod 400 "$stamp" || return 1
    ln -- "$stamp" "$dir/commit-attempt" || return 1
    rm -f -- "$stamp" || return 1
    ubs24gb2_records_valid || return 1
    # From here ANY error is ambiguous; NEVER retry or automatically delete.
    UBS24GB2_STAGE=commit-attempted-uncertain
    nft --file "$dir/batch.nft" >/dev/null 2>&1 || return 1
    ubs24gb2_attest || return 1
    UBS24GB2_STAGE=host-deny-all-attested-observation-only
    # Scratch contains only read-only observations. No guard/journal deletion.
    for file in nft1 nft2 links1 links2 route4a route4b route6a route6b batch locked-nft locked-links locked-route4 locked-route6; do
        rm -f -- "$scratch/$file" || return 1
    done
    rmdir -- "$scratch" || return 1
}

ubs24gb2_authorize_activation() { return 1; }
ubs24gb2_authorize_clone() { return 1; }
ubs24gb2_authorize_cleanup() { return 1; }
ubs24gb2_authorize_recovery() { return 1; }
ubs24gb2_authorize_disarm() { return 1; }
