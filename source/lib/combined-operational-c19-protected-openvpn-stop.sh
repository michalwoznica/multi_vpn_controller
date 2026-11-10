#!/usr/bin/env bash
# C19 PRIVATE / DEFAULT-DENY: C11 -> C1 guarded OUTPUT handback BEFORE NM down.
# Release-critical disconnect component; NOT imported by a public or host entry.
# No DNS writes, no killswitch disarm, no journal removal, no retry after intent.
# An interrupted transaction must be inspected manually while guard persists.

ubs24gc19_reset() {
    UBS24GC19_ATTEMPTED=no
    UBS24GC19_STAGE=unverified
    UBS24GC19_AUTHORITY=none
    UBS24GC19_NM_STOP_EXIT_STATUS=unattempted
    UBS24GC19_POST_STOP_OBSERVATION=unverified
}
ubs24gc19_admission_witness() { return 1; }
ubs24gc19_authorize_public_stop() { return 1; }
ubs24gc19_authorize_disarm() { return 1; }
ubs24gc19_authorize_cleanup() { return 1; }
ubs24gc19_authorize_retry() { return 1; }
ubs24gc19_authorize_traffic() { return 1; }
ubs24gc19_authorize_secret_export() { return 1; }
ubs24gc19_runtime() { printf '%s\n' /run/ubs-v240-disconnect; }

# Change ONLY host OUTPUT; restore the exact current C1 host shape: loopback,
# narrow DHCPv4 client continuity, and the pinned OpenVPN TCP endpoint.
# The inet FORWARD, bridge FORWARD and underlay netdev tables remain untouched.
ubs24gc19_write_c1_handback() {
    (( $# == 5 )) || return 1
    local iface=$1 source=$2 remote=$3 port=$4 out=$5
    ubs24gc1_parameters "$iface" "$source" "$remote" "$port" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    {
        printf '%s\n' 'flush chain inet vpn_v240_preclone_quarantine output_deny'
        printf '%s\n' 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "lo" accept'
        printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$iface"
        printf 'add rule inet vpn_v240_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' \
            "$iface" "$source" "$remote" "$port"
    } > "$out"
}

# Only accept the original same-boot C13/C7/C1 session, exact pre/post
# firewall states and unchanged foreign nftables policy.
ubs24gc19_kernel_witness() {
    (( $# == 3 )) || return 1
    local state=$1 first=$2 second=$3 pre before after
    [[ -f $first && -f $second && ! -L $first && ! -L $second ]] || return 1
    cmp -s -- "$first" "$second" || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
        ubs24gc3_transition_records_valid && ubs24gc13_intent_valid || return 1
    case "$state" in
        c11)
            ubs24gc11_postshape_observation "$first" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
                "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" &&
            ubs24gc11_postshape_observation "$second" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
                "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" || return 1
            ;;
        c1)
            ubs24gc1_postshape_observation "$first" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
                "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" &&
            ubs24gc1_postshape_observation "$second" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
                "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" || return 1
            ;;
        *) return 1 ;;
    esac
    pre=$(ubs24gb2_runtime) || return 1
    [[ $pre == /run/ubs-v240-controller ]] || return 1
    before=$(ubs24gb2_foreign_projection "$pre/prestate.json") || return 1
    after=$(ubs24gb2_foreign_projection "$first") || return 1
    [[ $before == "$after" ]] && ubs24gb2_lock_valid
}

ubs24gc19_intent_valid() {
    (( $# == 0 )) || return 1
    local dir first
    dir=$(ubs24gc19_runtime) || return 1
    [[ $dir == /run/ubs-v240-disconnect && -d $dir && ! -L $dir &&
       $(stat -c '%u:%a:%h' -- "$dir") == 0:700:2 ]] || return 1
    [[ -f $dir/attempt && ! -L $dir/attempt &&
       $(stat -c '%u:%a:%h' -- "$dir/attempt") == 0:400:1 ]] || return 1
    first=$(sed -n '1p' -- "$dir/attempt") || return 1
    case $first in
      ubs-v240-c19-openvpn-stop-v1) ubs24gc19_normal_intent_valid ;;
      ubs-v241-c24a-openvpn-absent-stop-v1) ubs24gc19_absent_intent_valid ;;
      *) return 1 ;;
    esac
}

ubs24gc19_normal_intent_valid() {
    (( $# == 0 )) || return 1
    local dir boot userns netns mntns c13 c1
    local -a records=() entries=()
    dir=$(ubs24gc19_runtime) || return 1
    [[ $dir == /run/ubs-v240-disconnect && -d $dir && ! -L $dir &&
       $(stat -c '%u:%a:%h' -- "$dir") == 0:700:2 ]] || return 1
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$dir/attempt" ]] || return 1
    [[ -f $dir/attempt && ! -L $dir/attempt &&
       $(stat -c '%u:%a:%h' -- "$dir/attempt") == 0:400:1 ]] || return 1
    mapfile -t records < "$dir/attempt" || return 1
    (( ${#records[@]} == 11 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c13=$(ubs24gc13_hash_file /run/ubs-v240-output-transition/attempt) || return 1
    c1=$(ubs24gc13_hash_file /run/ubs-v240-controller/transition-attempt) || return 1
    [[ ${records[0]} == ubs-v240-c19-openvpn-stop-v1 &&
       ${records[1]} == state=handback-commit-attempted-outcome-uncertain &&
       ${records[2]} == "boot=$boot" &&
       ${records[3]} == "userns=$userns" &&
       ${records[4]} == "netns=$netns" &&
       ${records[5]} == "mntns=$mntns" &&
       ${records[6]} == "c13=$c13" &&
       ${records[7]} == "c1=$c1" &&
       ${records[8]} == handback_sha=* &&
       ${records[9]} == "clone=${UBS24GC7_CLONE_UUID:-}" &&
       ${records[10]} == "nm_owner=${UBS24GC7_NM_OWNER:-}" ]] || return 1
    ubs24gc13_sha_valid "${records[8]#handback_sha=}" &&
      ubs24ga_uuid_valid "${UBS24GC7_CLONE_UUID:-}" &&
      ubs24gc7_nm_owner_valid "${UBS24GC7_NM_OWNER:-}"
}

# v2.4.1 C24A: an already-published session may lose OpenVPN independently
# (for example when the Wi-Fi underlay drops and NetworkManager terminates the
# temporary VPN).  This intent does not claim that C19 stopped OpenVPN.  It
# records that exact same-boot public ownership was authenticated, OpenVPN was
# independently observed absent, and the controller issued only the C11 -> C1
# firewall handback.  C23T may then use the same post-stop finalizer because its
# hard prerequisites remain identical: no active VPN, exact C1, unchanged
# foreign policy, exact owned clone identity and the original B2 lock.
ubs24gc19_absent_intent_valid() {
    (( $# == 0 )) || return 1
    local dir boot userns netns mntns c13 c1 marker_kind marker_path marker_sha current_marker_sha
    local -a records=() entries=()
    dir=$(ubs24gc19_runtime) || return 1
    [[ $dir == /run/ubs-v240-disconnect && -d $dir && ! -L $dir &&
       $(stat -c '%u:%a:%h' -- "$dir") == 0:700:2 ]] || return 1
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$dir/attempt" ]] || return 1
    mapfile -t records < "$dir/attempt" || return 1
    (( ${#records[@]} == 13 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c13=$(ubs24gc13_hash_file /run/ubs-v240-output-transition/attempt) || return 1
    c1=$(ubs24gc13_hash_file /run/ubs-v240-controller/transition-attempt) || return 1
    marker_kind=${records[11]#marker=}
    case $marker_kind in active|transaction) ;; *) return 1 ;; esac
    marker_path=/run/ubs-v240-public-session/$marker_kind
    [[ -f $marker_path && ! -L $marker_path &&
       $(stat -c '%u:%a:%h' -- "$marker_path") == 0:400:1 ]] || return 1
    marker_sha=${records[12]#marker_sha=}
    ubs24gc13_sha_valid "$marker_sha" || return 1
    current_marker_sha=$(ubs24gc13_hash_file "$marker_path") || return 1
    [[ ${records[0]} == ubs-v241-c24a-openvpn-absent-stop-v1 &&
       ${records[1]} == state=c11-handback-attempted-openvpn-already-absent &&
       ${records[2]} == "boot=$boot" &&
       ${records[3]} == "userns=$userns" &&
       ${records[4]} == "netns=$netns" &&
       ${records[5]} == "mntns=$mntns" &&
       ${records[6]} == "c13=$c13" &&
       ${records[7]} == "c1=$c1" &&
       ${records[8]} == handback_sha=* &&
       ${records[9]} == "clone=${UBS24GC7_CLONE_UUID:-}" &&
       ${records[10]} == "nm_owner=${UBS24GC7_NM_OWNER:-}" &&
       ${records[11]} == "marker=$marker_kind" &&
       $current_marker_sha == "$marker_sha" ]] || return 1
    ubs24gc13_sha_valid "${records[8]#handback_sha=}" &&
      ubs24ga_uuid_valid "${UBS24GC7_CLONE_UUID:-}" &&
      ubs24gc7_nm_owner_valid "${UBS24GC7_NM_OWNER:-}"
}

ubs24gc19_publish_intent() {
    (( $# == 1 )) || return 1
    local batch=$1 dir tmp boot userns netns mntns c13 c1 digest
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
        ubs24gc3_transition_records_valid && ubs24gc13_intent_valid || return 1
    [[ $(stat -f -c %T /run) == tmpfs && -f $batch && ! -L $batch && -O $batch &&
       $(stat -c '%a:%h' -- "$batch") == 600:1 ]] || return 1
    dir=$(ubs24gc19_runtime) || return 1
    [[ $dir == /run/ubs-v240-disconnect && ! -e $dir && ! -L $dir ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c13=$(ubs24gc13_hash_file /run/ubs-v240-output-transition/attempt) || return 1
    c1=$(ubs24gc13_hash_file /run/ubs-v240-controller/transition-attempt) || return 1
    digest=$(ubs24gc13_hash_file "$batch") || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.attempt.XXXXXXXX") || return 1
    if ! printf '%s\n' ubs-v240-c19-openvpn-stop-v1 \
        state=handback-commit-attempted-outcome-uncertain \
        "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
        "c13=$c13" "c1=$c1" "handback_sha=$digest" \
        "clone=$UBS24GC7_CLONE_UUID" "nm_owner=$UBS24GC7_NM_OWNER" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    [[ ! -e $dir/attempt && ! -L $dir/attempt ]] || return 1
    mv -T -- "$tmp" "$dir/attempt" || return 1
    ubs24gc19_intent_valid
}

# v2.4.1 C24A: publish the one-shot C11 -> C1 handback intent for a
# same-boot public session whose OpenVPN clone/tunnel has already disappeared.
# The public marker remains live and is hash-bound into this intent so C23T can
# later authenticate the same published session without pretending NM stop was
# issued by C19.
ubs24gc19_publish_absent_intent() {
    (( $# == 2 )) || return 1
    local batch=$1 marker_kind=$2 dir tmp boot userns netns mntns c13 c1 digest marker_path marker_sha
    case $marker_kind in active|transaction) ;; *) return 1 ;; esac
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
      ubs24gc3_transition_records_valid && ubs24gc13_intent_valid || return 1
    [[ $(stat -f -c %T /run) == tmpfs && -f $batch && ! -L $batch && -O $batch &&
       $(stat -c '%a:%h' -- "$batch") == 600:1 ]] || return 1
    marker_path=/run/ubs-v240-public-session/$marker_kind
    [[ -f $marker_path && ! -L $marker_path &&
       $(stat -c '%u:%a:%h' -- "$marker_path") == 0:400:1 ]] || return 1
    dir=$(ubs24gc19_runtime) || return 1
    [[ $dir == /run/ubs-v240-disconnect && ! -e $dir && ! -L $dir ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c13=$(ubs24gc13_hash_file /run/ubs-v240-output-transition/attempt) || return 1
    c1=$(ubs24gc13_hash_file /run/ubs-v240-controller/transition-attempt) || return 1
    digest=$(ubs24gc13_hash_file "$batch") || return 1
    marker_sha=$(ubs24gc13_hash_file "$marker_path") || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.attempt.XXXXXXXX") || return 1
    if ! printf '%s\n' ubs-v241-c24a-openvpn-absent-stop-v1 \
        state=c11-handback-attempted-openvpn-already-absent \
        "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
        "c13=$c13" "c1=$c1" "handback_sha=$digest" \
        "clone=$UBS24GC7_CLONE_UUID" "nm_owner=$UBS24GC7_NM_OWNER" \
        "marker=$marker_kind" "marker_sha=$marker_sha" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    [[ ! -e $dir/attempt && ! -L $dir/attempt ]] || return 1
    mv -T -- "$tmp" "$dir/attempt" || return 1
    ubs24gc19_intent_valid
}

ubs24gc19_candidate_matches_intent() {
    (( $# == 1 )) || return 1
    local recorded digest
    ubs24gc19_intent_valid || return 1
    recorded=$(sed -n '9p' -- "$(ubs24gc19_runtime)/attempt") || return 1
    digest=$(ubs24gc13_hash_file "$1") || return 1
    [[ $recorded == "handback_sha=$digest" ]]
}

ubs24gc19_nm_stop() {
    (( $# == 1 )) && ubs24ga_uuid_valid "$1" || return 1
    LC_ALL=C nmcli --wait 35 --colors no --terse connection down uuid "$1" \
        </dev/null >/dev/null 2>&1
}

# A NetworkManager disconnect request is a one-shot mutation whose command
# result can be ambiguous. Never retry it. Instead, while exact C1 remains
# installed, bound only READ-ONLY observation of the authoritative post-state.
ubs24gc19_disconnect_pause() {
    (( $# == 0 )) || return 1
    sleep 1
}

ubs24gc19_post_disconnect_witness() {
    (( $# == 2 )) || return 1
    local first=$1 second=$2
    ubs24gb4_no_active_vpn &&
      ubs24gb1_capture_nft "$first" && ubs24gb1_capture_nft "$second" &&
      ubs24gc19_kernel_witness c1 "$first" "$second" &&
      ubs24gc19_intent_valid
}

ubs24gc19_observe_disconnect_poststate() {
    (( $# == 2 )) || return 1
    local first=$1 second=$2 attempt max_attempts=20
    for (( attempt=1; attempt<=max_attempts; attempt++ )); do
        if ubs24gc19_post_disconnect_witness "$first" "$second"; then
            UBS24GC19_POST_STOP_OBSERVATION=verified
            return 0
        fi
        if (( attempt < max_attempts )); then
            UBS24GC19_POST_STOP_OBSERVATION=waiting-readonly-poststate
            ubs24gc19_disconnect_pause || {
                UBS24GC19_POST_STOP_OBSERVATION=pause-failed
                return 1
            }
        fi
    done
    UBS24GC19_POST_STOP_OBSERVATION=not-verified
    return 1
}

# No public entry point. First atomically remove general tunnel OUTPUT,
# verify exact C1 twice, THEN (and only then) request NM disconnect once.
# Never disarm; C1 guard remains installed after NM disconnect.
ubs24gc19_execute_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GC19_ATTEMPTED:-no} == no ]] || return 1
    UBS24GC19_ATTEMPTED=yes
    UBS24GC19_STAGE=refused-or-unverified
    UBS24GC19_AUTHORITY=none
    ubs24gc19_admission_witness || return 1
    [[ ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority &&
       ${UBS24GC17_AUTHORITY:-} == none &&
       ${UBS24GC13_STAGE:-} == atomic-ipv4-tunnel-output-observed-dns-unverified &&
       ${UBS24GC13_AUTHORITY:-} == none &&
       ( ${UBS24GC16_STAGE:-} == direct-glibc-vpn-dns-observed-no-traffic-authority ||
         ${UBS24GC16_STAGE:-} == conditional-arch-nss-vpn-dns-observed-no-traffic-authority ) &&
       ${UBS24GC16_AUTHORITY:-} == none ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
        ubs24gc3_transition_records_valid && ubs24gc7_read_intent &&
        ubs24gc13_intent_valid || return 1
    [[ ! -e /run/ubs-v240-disconnect && ! -L /run/ubs-v240-disconnect &&
       $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local scratch batch a b nm route success=1 expected
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c19.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c %a -- "$scratch") == 700 ]] || return 1
    batch=$scratch/handback.nft a=$scratch/first.json b=$scratch/second.json
    if ! (umask 077; set -C; : > "$batch") ||
       ! ubs24gc19_write_c1_handback "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
           "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$batch" ||
       ! nft --check --file "$batch" >/dev/null 2>&1; then success=0; fi
    if (( success == 1 )); then
        nm=$(ubs24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || success=0
        route=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || success=0
        expected="$UBS24GC3_IFACE|$UBS24GC3_SOURCE|$UBS24GC11_TUNNEL|$UBS24GC11_TUNNEL_SOURCE"
        [[ -n ${nm:-} && $nm == "${UBS24GC6_NM_SNAPSHOT:-}" &&
           $route == "$expected" && $route == "${UBS24GC6_ROUTE_SNAPSHOT:-}" ]] || success=0
    fi
    if (( success == 1 )); then
        ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" &&
          ubs24gc19_kernel_witness c11 "$a" "$b" || success=0
    fi
    if (( success == 1 )); then
        ubs24gc19_publish_intent "$batch" &&
          ubs24gc19_candidate_matches_intent "$batch" || success=0
    fi
    if (( success == 1 )); then
        UBS24GC19_STAGE=handback-commit-attempted-uncertain
        if ! nft --file "$batch" >/dev/null 2>&1; then success=0; fi
    fi
    if (( success == 1 )); then
        ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" &&
          ubs24gc19_kernel_witness c1 "$a" "$b" && ubs24gc19_intent_valid || success=0
    fi
    if (( success == 1 )); then
        UBS24GC19_STAGE=c1-quarantine-verified-nm-disconnect-attempted-uncertain
        # Invoke NetworkManager exactly once. Its process exit status is
        # diagnostic evidence, not proof of mutation outcome: classify only
        # from the authoritative host post-state while C1 remains fail-closed.
        local nm_stop_rc
        if ubs24gc19_nm_stop "$UBS24GC7_CLONE_UUID"; then
            nm_stop_rc=0
        else
            nm_stop_rc=$?
        fi
        UBS24GC19_NM_STOP_EXIT_STATUS=$nm_stop_rc
        ubs24gc19_observe_disconnect_poststate "$a" "$b" || success=0
    fi
    rm -f -- "$batch" "$a" "$b" || success=0
    rmdir -- "$scratch" || success=0
    if (( success == 1 )); then
        UBS24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority
        return 0
    fi
    return 1
}
