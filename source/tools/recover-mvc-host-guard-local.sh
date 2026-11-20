#!/usr/bin/env bash
# Manual emergency recovery for the MVC B4 maintenance quarantine.
#
# --rollback remains the independent B4 break-glass action: it can disarm the
# three MVC quarantine tables even when normal lifecycle journals are damaged.
#
# --finalization-inspect is READ-ONLY. --rollback keeps the B4 disarm
# independent, then attempts authenticated lifecycle finalization. --finalize
# resumes or performs only that post-disarm finalization when B4 is already off.
# Failed-session evidence is archived before any profile mutation; live public
# authority is retired last and only after final managed-network safety is proven.
set -euo pipefail
umask 077
export LC_ALL=C

mvc_er_usage() {
    printf '%s\n' 'Usage: recover-mvc-host-guard-local.sh --inspect|--rollback|--finalization-inspect|--finalize' >&2
    exit 2
}

mvc_er_public_root() { printf '%s\n' /run/mvc-public-session; }
mvc_er_controller_root() { printf '%s\n' /run/mvc-controller; }
mvc_er_activation_root() { printf '%s\n' /run/mvc-activation; }
mvc_er_output_root() { printf '%s\n' /run/mvc-output-transition; }
mvc_er_disconnect_root() { printf '%s\n' /run/mvc-disconnect; }
mvc_er_completion_root() { printf '%s\n' /run/mvc-completion; }
mvc_er_wireguard_root() { printf '%s\n' /run/mvc-wireguard; }
mvc_er_archive_root() { printf '%s\n' /run/mvc-recovered; }
mvc_er_recovery_plan_path() { printf '%s/recovery-plan\n' "$(mvc_er_public_root)"; }
mvc_er_controller_prepare_path() { printf '%s\n' /run/mvc-controller/prepare-intent; }
mvc_er_controller_transition_path() { printf '%s\n' /run/mvc-controller/transition-attempt; }
mvc_er_activation_path() { printf '%s\n' /run/mvc-activation/attempt; }
mvc_er_output_path() { printf '%s\n' /run/mvc-output-transition/attempt; }
mvc_er_d4_intent_path() { printf '%s\n' /run/mvc-wireguard/intent; }
mvc_er_wg_keyfile_path() { printf '%s\n' /run/NetworkManager/system-connections/vpnks-wg.nmconnection; }

mvc_er_valid_uuid() {
    (( $# == 1 )) && [[ $1 =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]
}

mvc_er_valid_ifname() {
    (( $# == 1 )) && [[ $1 =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$ &&
        $1 != lo && $1 != tun* && $1 != wg* ]]
}

mvc_er_secure_dir() {
    (( $# == 2 )) || return 1
    local path=$1 mode=$2
    [[ -d $path && ! -L $path && $(stat -c '%u:%a' -- "$path" 2>/dev/null) == "0:$mode" ]]
}

mvc_er_secure_file() {
    (( $# == 2 )) || return 1
    local path=$1 mode=$2
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path" 2>/dev/null) == "0:$mode:1" ]]
}

mvc_er_hash_file() {
    (( $# == 1 )) || return 1
    local path=$1 hash tail
    [[ -f $path && ! -L $path ]] || return 1
    read -r hash tail < <(sha256sum -- "$path") || return 1
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

mvc_er_root_scope() {
    (( $# == 0 )) || return 1
    [[ $EUID == 0 && $(stat -f -c %T /run) == tmpfs ]] || return 1
    [[ $(readlink /proc/self/ns/net) == "$(readlink /proc/1/ns/net)" &&
       $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || return 1
    [[ $(awk '{print $1 ":" $2 ":" $3}' /proc/self/uid_map) == '0:0:4294967295' ]]
}

# Read-only snapshot of table names; reject invalid nft JSON. Match ONLY the
# three hard-coded tables owned by B4. Never interpolate discovered names into
# arbitrary nft commands.
mvc_er_owned_tables() {
    local json
    json=$(nft -j list tables) || return 1
    jq -r '
      if type != "object" or (.nftables | type) != "array" or
         any(.nftables[]; type != "object" or (keys | length) != 1)
      then error("malformed nft list-tables JSON")
      else
        [.nftables[] | .table? | select(type == "object") |
           select((.family == "inet" and .name == "mvc_preclone_quarantine") or
                  (.family == "bridge" and .name == "mvc_preclone_bridge") or
                  (.family == "netdev" and .name == "mvc_preclone_underlay")) |
           "\(.family):\(.name)"] | unique | join("\n")
      end
    ' <<< "$json"
}

mvc_er_b4_all_absent() {
    (( $# == 0 )) || return 1
    local tables
    tables=$(mvc_er_owned_tables) || return 1
    [[ -z $tables ]]
}

mvc_er_fixed_roots_safe() {
    (( $# == 0 )) || return 1
    local path
    for path in \
        "$(mvc_er_controller_root)" "$(mvc_er_activation_root)" \
        "$(mvc_er_output_root)" "$(mvc_er_disconnect_root)" \
        "$(mvc_er_completion_root)" "$(mvc_er_wireguard_root)" \
        "$(mvc_er_public_root)"; do
        if [[ -e $path || -L $path ]]; then
            mvc_er_secure_dir "$path" 700 || return 1
        fi
    done
}

mvc_er_fixed_roots_all_absent() {
    (( $# == 0 )) || return 1
    local path
    for path in \
        "$(mvc_er_controller_root)" "$(mvc_er_activation_root)" \
        "$(mvc_er_output_root)" "$(mvc_er_disconnect_root)" \
        "$(mvc_er_completion_root)" "$(mvc_er_wireguard_root)" \
        "$(mvc_er_public_root)"; do
        [[ ! -e $path && ! -L $path ]] || return 1
    done
}

mvc_er_session_not_busy() {
    (( $# == 0 )) || return 1
    [[ ${MVC_ER_LOCKS_HELD:-no} == yes ]] && return 0
    local controller public lock fd
    controller=$(mvc_er_controller_root) || return 1
    public=$(mvc_er_public_root) || return 1
    if [[ -e $controller || -L $controller ]]; then
        mvc_er_secure_dir "$controller" 700 || return 1
        lock=$controller/controller.lock
        mvc_er_secure_file "$lock" 600 || return 1
        exec {fd}< "$lock" || return 1
        if ! flock -n "$fd"; then
            exec {fd}>&-
            return 1
        fi
        exec {fd}>&-
    fi
    if [[ -f $public/split.lock && ! -L $public/split.lock ]]; then
        mvc_er_secure_file "$public/split.lock" 600 || return 1
        exec {fd}< "$public/split.lock" || return 1
        if ! flock -n "$fd"; then
            exec {fd}>&-
            return 1
        fi
        exec {fd}>&-
    fi
}

# Recovery finalization must not retire authority while any VPN/tunnel is live,
# including unmanaged/foreign ones. Unlike admission/guard acceptance, an empty
# NetworkManager active set is acceptable here: recovery may finish while the
# ordinary underlay is currently down, and any later connect still runs normal
# strict admission from the beginning.
mvc_er_no_active_vpn_or_tunnel() {
    (( $# == 0 )) || return 1
    local active wg_interfaces links nm_type pgrep_status
    active=$(nmcli -t -f TYPE connection show --active) || return 1
    if [[ -n $active ]]; then
        while IFS= read -r nm_type; do
            case ${nm_type,,} in
                vpn|wireguard|tun|tap|ppp) return 1 ;;
                ethernet|wifi|802-3-ethernet|802-11-wireless|loopback|bridge|vlan|bond|dummy) ;;
                *) return 1 ;;
            esac
        done <<< "$active"
    fi
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

mvc_er_managed_routes_absent() {
    (( $# == 0 )) || return 1
    local r186 r187
    r186=$(ip -j -N -4 route show table all proto 186) || return 1
    r187=$(ip -j -N -4 route show table all proto 187) || return 1
    jq -e 'type=="array" and length==0' <<< "$r186" >/dev/null 2>&1 &&
      jq -e 'type=="array" and length==0' <<< "$r187" >/dev/null 2>&1
}

mvc_er_ipv6_no_default() {
    (( $# == 0 )) || return 1
    local routes6
    routes6=$(ip -j -6 route show table all) || return 1
    jq -e 'type=="array" and all(.[]; .dst != "default")' <<< "$routes6" >/dev/null 2>&1
}

mvc_er_nm_profiles() {
    (( $# == 0 )) || return 1
    nmcli -t -f UUID,TYPE,NAME connection show
}

mvc_er_openvpn_clone_inventory() {
    (( $# == 0 )) || return 1
    local profiles clone=${MVC_ER_OVPN_CLONE_UUID:--} uuid_count name_count exact_count
    MVC_ER_OVPN_CLONE_STATUS=not-applicable
    profiles=$(mvc_er_nm_profiles) || return 1
    if [[ $clone == - ]]; then
        name_count=$(awk -F: '$3=="vpnks-ovpn"{n++} END{print n+0}' <<< "$profiles")
        (( name_count == 0 )) || return 1
        return 0
    fi
    mvc_er_valid_uuid "$clone" || return 1
    uuid_count=$(awk -F: -v u="$clone" '$1==u{n++} END{print n+0}' <<< "$profiles")
    name_count=$(awk -F: '$3=="vpnks-ovpn"{n++} END{print n+0}' <<< "$profiles")
    exact_count=$(awk -F: -v u="$clone" '$1==u && $2=="vpn" && $3=="vpnks-ovpn"{n++} END{print n+0}' <<< "$profiles")
    if (( uuid_count == 0 && name_count == 0 )); then
        MVC_ER_OVPN_CLONE_STATUS=absent
        return 0
    fi
    if (( uuid_count == 1 && name_count == 1 && exact_count == 1 )); then
        MVC_ER_OVPN_CLONE_STATUS=inactive-authenticated-residue
        return 0
    fi
    return 1
}

mvc_er_wireguard_residue_absent() {
    (( $# == 0 )) || return 1
    local profiles temp=${MVC_ER_WG_TEMP_UUID:--} name_count uuid_count keyfile
    profiles=$(mvc_er_nm_profiles) || return 1
    name_count=$(awk -F: '$3=="vpnks-wg"{n++} END{print n+0}' <<< "$profiles")
    (( name_count == 0 )) || return 1
    if [[ $temp != - ]]; then
        mvc_er_valid_uuid "$temp" || return 1
        uuid_count=$(awk -F: -v u="$temp" '$1==u{n++} END{print n+0}' <<< "$profiles")
        (( uuid_count == 0 )) || return 1
    fi
    keyfile=$(mvc_er_wg_keyfile_path) || return 1
    [[ ! -e $keyfile && ! -L $keyfile ]]
}

mvc_er_sameboot_rows() {
    (( $# == 1 )) || return 1
    local -n rows_ref=$1
    local boot userns netns mntns
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${rows_ref[2]:-} == "boot=$boot" && ${rows_ref[3]:-} == "userns=$userns" &&
       ${rows_ref[4]:-} == "netns=$netns" && ${rows_ref[5]:-} == "mntns=$mntns" ]]
}

mvc_er_hash_matches() {
    (( $# == 2 )) || return 1
    local path=$1 expected=$2 actual
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
    actual=$(mvc_er_hash_file "$path") || return 1
    [[ $actual == "$expected" ]]
}

mvc_er_d4_evidence() {
    (( $# == 2 )) || return 1
    local expected=$1 required=$2 path root
    MVC_ER_D4_STATUS=historical-only
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
    path=$(mvc_er_d4_intent_path) || return 1
    root=$(mvc_er_wireguard_root) || return 1
    if [[ -e $path || -L $path ]]; then
        mvc_er_secure_file "$path" 400 || return 1
        mvc_er_hash_matches "$path" "$expected" || return 1
        MVC_ER_D4_STATUS=live-authenticated-evidence
        return 0
    fi
    [[ ! -e $root && ! -L $root ]] || return 1
    [[ $required == no ]]
}

mvc_er_parse_active_marker() {
    (( $# == 0 )) || return 1
    local runtime file entry prepare transition activation output d4
    local -a rows=() entries=()
    runtime=$(mvc_er_public_root) || return 1
    file=$runtime/active
    mvc_er_secure_dir "$runtime" 700 || return 1
    mvc_er_secure_file "$file" 400 || return 1
    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$file" ]] || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    [[ ${rows[0]} == mvc-public-active-v1 && ${rows[1]} == state=dual-active-published &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == ovpn_source_uuid=* && ${rows[7]} == ovpn_clone_uuid=* &&
       ${rows[8]} == wg_source_uuid=* && ${rows[9]} == wg_temp_uuid=* && ${rows[10]} == underlay=* &&
       ${rows[11]} == controller_prepare_sha=* && ${rows[12]} == controller_transition_sha=* &&
       ${rows[13]} == activation_sha=* && ${rows[14]} == output_sha=* && ${rows[15]} == d4_intent_sha=* ]] || return 1
    mvc_er_sameboot_rows rows || return 1

    MVC_ER_OVPN_SOURCE_UUID=${rows[6]#ovpn_source_uuid=}
    MVC_ER_OVPN_CLONE_UUID=${rows[7]#ovpn_clone_uuid=}
    MVC_ER_WG_SOURCE_UUID=${rows[8]#wg_source_uuid=}
    MVC_ER_WG_TEMP_UUID=${rows[9]#wg_temp_uuid=}
    MVC_ER_UNDERLAY=${rows[10]#underlay=}
    mvc_er_valid_uuid "$MVC_ER_OVPN_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_OVPN_CLONE_UUID" &&
      mvc_er_valid_uuid "$MVC_ER_WG_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_WG_TEMP_UUID" &&
      mvc_er_valid_ifname "$MVC_ER_UNDERLAY" || return 1

    prepare=${rows[11]#controller_prepare_sha=}
    transition=${rows[12]#controller_transition_sha=}
    activation=${rows[13]#activation_sha=}
    output=${rows[14]#output_sha=}
    d4=${rows[15]#d4_intent_sha=}
    mvc_er_hash_matches "$(mvc_er_controller_prepare_path)" "$prepare" &&
      mvc_er_hash_matches "$(mvc_er_controller_transition_path)" "$transition" &&
      mvc_er_hash_matches "$(mvc_er_activation_path)" "$activation" &&
      mvc_er_hash_matches "$(mvc_er_output_path)" "$output" || return 1
    mvc_er_d4_evidence "$d4" no || return 1

    MVC_ER_SESSION_MODE=combined
    MVC_ER_MARKER_KIND=active
    MVC_ER_TRANSACTION_STATE=dual-active-observed
}

mvc_er_parse_transaction_marker() {
    (( $# == 0 )) || return 1
    local runtime file state entry base prepare transition activation output d4 seen_tx=0 seen_lock=0
    local -a rows=() entries=()
    runtime=$(mvc_er_public_root) || return 1
    file=$runtime/transaction
    mvc_er_secure_dir "$runtime" 700 || return 1
    mvc_er_secure_file "$file" 400 || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    [[ ${rows[0]} == mvc-public-transaction-v1 && ${rows[1]} == state=* &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == ovpn_source_uuid=* && ${rows[7]} == ovpn_clone_uuid=* &&
       ${rows[8]} == wg_source_uuid=* && ${rows[9]} == wg_temp_uuid=* && ${rows[10]} == underlay=* &&
       ${rows[11]} == controller_prepare_sha=* && ${rows[12]} == controller_transition_sha=* &&
       ${rows[13]} == activation_sha=* && ${rows[14]} == output_sha=* && ${rows[15]} == d4_intent_sha=* ]] || return 1
    mvc_er_sameboot_rows rows || return 1
    state=${rows[1]#state=}
    case $state in
        prepared-before-mutation|wireguard-split-prepared)
            MVC_ER_PARSE_DETAIL=partial-start-not-supported
            return 2
            ;;
        openvpn-protected|dual-active-observed|wireguard-protected|wireguard-split) ;;
        *) return 1 ;;
    esac

    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    if [[ $state == wireguard-split ]]; then
        (( ${#entries[@]} == 2 )) || return 1
        for entry in "${entries[@]}"; do
            base=${entry##*/}
            case $base in
                transaction) seen_tx=$((seen_tx+1)) ;;
                split.lock) seen_lock=$((seen_lock+1)) ;;
                *) return 1 ;;
            esac
        done
        (( seen_tx == 1 && seen_lock == 1 )) || return 1
        mvc_er_secure_file "$runtime/split.lock" 600 || return 1
    else
        (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$file" ]] || return 1
    fi

    MVC_ER_OVPN_SOURCE_UUID=${rows[6]#ovpn_source_uuid=}
    MVC_ER_OVPN_CLONE_UUID=${rows[7]#ovpn_clone_uuid=}
    MVC_ER_WG_SOURCE_UUID=${rows[8]#wg_source_uuid=}
    MVC_ER_WG_TEMP_UUID=${rows[9]#wg_temp_uuid=}
    MVC_ER_UNDERLAY=${rows[10]#underlay=}
    mvc_er_valid_ifname "$MVC_ER_UNDERLAY" || return 1
    prepare=${rows[11]#controller_prepare_sha=}
    transition=${rows[12]#controller_transition_sha=}
    activation=${rows[13]#activation_sha=}
    output=${rows[14]#output_sha=}
    d4=${rows[15]#d4_intent_sha=}

    case $state in
        openvpn-protected)
            mvc_er_valid_uuid "$MVC_ER_OVPN_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_OVPN_CLONE_UUID" || return 1
            [[ $MVC_ER_WG_SOURCE_UUID == - && $MVC_ER_WG_TEMP_UUID == - && $d4 == - ]] || return 1
            mvc_er_hash_matches "$(mvc_er_controller_prepare_path)" "$prepare" &&
              mvc_er_hash_matches "$(mvc_er_controller_transition_path)" "$transition" &&
              mvc_er_hash_matches "$(mvc_er_activation_path)" "$activation" &&
              mvc_er_hash_matches "$(mvc_er_output_path)" "$output" || return 1
            MVC_ER_D4_STATUS=not-applicable
            MVC_ER_SESSION_MODE=openvpn-only
            ;;
        dual-active-observed)
            mvc_er_valid_uuid "$MVC_ER_OVPN_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_OVPN_CLONE_UUID" &&
              mvc_er_valid_uuid "$MVC_ER_WG_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_WG_TEMP_UUID" || return 1
            mvc_er_hash_matches "$(mvc_er_controller_prepare_path)" "$prepare" &&
              mvc_er_hash_matches "$(mvc_er_controller_transition_path)" "$transition" &&
              mvc_er_hash_matches "$(mvc_er_activation_path)" "$activation" &&
              mvc_er_hash_matches "$(mvc_er_output_path)" "$output" || return 1
            mvc_er_d4_evidence "$d4" no || return 1
            MVC_ER_SESSION_MODE=combined
            ;;
        wireguard-protected)
            [[ $MVC_ER_OVPN_SOURCE_UUID == - && $MVC_ER_OVPN_CLONE_UUID == - &&
               $transition == - && $activation == - && $output == - ]] || return 1
            mvc_er_valid_uuid "$MVC_ER_WG_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_WG_TEMP_UUID" || return 1
            mvc_er_hash_matches "$(mvc_er_controller_prepare_path)" "$prepare" || return 1
            mvc_er_d4_evidence "$d4" yes || return 1
            MVC_ER_SESSION_MODE=wireguard-protected
            ;;
        wireguard-split)
            [[ $MVC_ER_OVPN_SOURCE_UUID == - && $MVC_ER_OVPN_CLONE_UUID == - &&
               $prepare == - && $transition == - && $activation == - && $output == - ]] || return 1
            mvc_er_valid_uuid "$MVC_ER_WG_SOURCE_UUID" && mvc_er_valid_uuid "$MVC_ER_WG_TEMP_UUID" || return 1
            mvc_er_d4_evidence "$d4" yes || return 1
            MVC_ER_SESSION_MODE=wireguard-split
            ;;
    esac
    MVC_ER_MARKER_KIND=transaction
    MVC_ER_TRANSACTION_STATE=$state
}

mvc_er_parse_session_marker() {
    (( $# == 0 )) || return 1
    local runtime rc
    runtime=$(mvc_er_public_root) || return 1
    MVC_ER_PARSE_DETAIL=unverified
    if [[ -f $runtime/active && ! -L $runtime/active ]]; then
        mvc_er_parse_active_marker
        return $?
    fi
    if [[ -f $runtime/transaction && ! -L $runtime/transaction ]]; then
        if mvc_er_parse_transaction_marker; then
            return 0
        else
            rc=$?
            return "$rc"
        fi
    fi
    return 1
}

mvc_er_reset_classifier() {
    MVC_ER_REASON=unverified
    MVC_ER_SESSION_MODE=none
    MVC_ER_MARKER_KIND=none
    MVC_ER_TRANSACTION_STATE=none
    MVC_ER_OVPN_SOURCE_UUID=-
    MVC_ER_OVPN_CLONE_UUID=-
    MVC_ER_WG_SOURCE_UUID=-
    MVC_ER_WG_TEMP_UUID=-
    MVC_ER_UNDERLAY=-
    MVC_ER_D4_STATUS=unverified
    MVC_ER_OVPN_CLONE_STATUS=unverified
    MVC_ER_PARSE_DETAIL=unverified
}

mvc_er_block() {
    (( $# == 1 )) || return 1
    MVC_ER_REASON=$1
    return 1
}

mvc_er_finalization_classify() {
    (( $# == 0 )) || return 1
    local runtime rc
    mvc_er_reset_classifier
    mvc_er_root_scope || { mvc_er_block root-scope-not-proven; return 1; }
    mvc_er_b4_all_absent || { mvc_er_block b4-still-present-or-unreadable; return 1; }
    mvc_er_fixed_roots_safe || { mvc_er_block unsafe-live-runtime-root; return 1; }
    mvc_er_session_not_busy || { mvc_er_block live-session-lock-busy-or-invalid; return 1; }
    mvc_er_no_active_vpn_or_tunnel || { mvc_er_block active-or-foreign-vpn-tunnel-remains; return 1; }
    mvc_er_managed_routes_absent || { mvc_er_block mvc-proto-186-or-187-route-remains; return 1; }
    mvc_er_ipv6_no_default || { mvc_er_block ipv6-default-route-present-or-unreadable; return 1; }

    runtime=$(mvc_er_public_root) || { mvc_er_block public-session-root-unavailable; return 1; }
    if [[ ! -e $runtime && ! -L $runtime ]]; then
        mvc_er_fixed_roots_all_absent || { mvc_er_block live-mvc-root-without-public-session-authority; return 1; }
        MVC_ER_OVPN_CLONE_UUID=-
        MVC_ER_WG_TEMP_UUID=-
        mvc_er_openvpn_clone_inventory || { mvc_er_block unauthenticated-openvpn-temporary-profile; return 1; }
        mvc_er_wireguard_residue_absent || { mvc_er_block unauthenticated-wireguard-temporary-residue; return 1; }
        MVC_ER_SESSION_MODE=baseline
        MVC_ER_MARKER_KIND=none
        MVC_ER_TRANSACTION_STATE=none
        MVC_ER_D4_STATUS=not-applicable
        MVC_ER_REASON=eligible-already-clean-baseline
        return 0
    fi

    if mvc_er_parse_session_marker; then
        rc=0
    else
        rc=$?
    fi
    if (( rc == 2 )) && [[ ${MVC_ER_PARSE_DETAIL:-} == partial-start-not-supported ]]; then
        mvc_er_block partial-start-finalization-not-supported
        return 1
    fi
    (( rc == 0 )) || { mvc_er_block retained-session-marker-authentication-failed; return 1; }

    mvc_er_openvpn_clone_inventory || { mvc_er_block openvpn-temporary-profile-identity-ambiguous; return 1; }
    mvc_er_wireguard_residue_absent || { mvc_er_block wireguard-temporary-residue-remains; return 1; }

    MVC_ER_REASON=eligible-authenticated-retained-session
    return 0
}

mvc_er_print_finalization_result() {
    (( $# == 1 )) || return 1
    local rc=$1
    if (( rc == 0 )); then
        printf 'PASS: emergency recovery-finalization eligibility proven read-only\n'
        printf 'DETAIL: session_mode=%s marker=%s state=%s\n' \
          "$MVC_ER_SESSION_MODE" "$MVC_ER_MARKER_KIND" "$MVC_ER_TRANSACTION_STATE"
        printf 'DETAIL: d4_evidence=%s openvpn_clone=%s\n' \
          "$MVC_ER_D4_STATUS" "$MVC_ER_OVPN_CLONE_STATUS"
        printf 'RESULT: READ-ONLY EMERGENCY FINALIZATION ELIGIBLE — NO CHANGES\n'
    else
        printf 'BLOCKED: emergency recovery-finalization eligibility not proven: %s\n' "$MVC_ER_REASON" >&2
        printf 'RESULT: READ-ONLY EMERGENCY FINALIZATION BLOCKED — NO CHANGES\n' >&2
    fi
}


mvc_er_marker_file() {
    (( $# == 0 )) || return 1
    local runtime
    runtime=$(mvc_er_public_root) || return 1
    case ${MVC_ER_MARKER_KIND:-} in
        active) printf '%s\n' "$runtime/active" ;;
        transaction) printf '%s\n' "$runtime/transaction" ;;
        *) return 1 ;;
    esac
}

mvc_er_fixed_root_paths() {
    (( $# == 0 )) || return 1
    printf '%s\n' \
      "$(mvc_er_controller_root)" \
      "$(mvc_er_activation_root)" \
      "$(mvc_er_output_root)" \
      "$(mvc_er_disconnect_root)" \
      "$(mvc_er_completion_root)" \
      "$(mvc_er_wireguard_root)" \
      "$(mvc_er_public_root)"
}

mvc_er_tree_safe() {
    (( $# == 1 )) || return 1
    local root=$1 root_dev path rel meta dev
    [[ -d $root && ! -L $root ]] || return 1
    [[ $(stat -c '%u:%a' -- "$root" 2>/dev/null) == 0:700 ]] || return 1
    root_dev=$(stat -c '%d' -- "$root") || return 1
    while IFS= read -r -d '' path; do
        rel=${path#"$root"/}
        [[ $rel != "$path" && $rel =~ ^[A-Za-z0-9._/-]+$ &&
           $rel != .. && $rel != ../* && $rel != */../* && $rel != */.. ]] || return 1
        dev=$(stat -c '%d' -- "$path" 2>/dev/null) || return 1
        [[ $dev == "$root_dev" ]] || return 1
        if [[ -d $path && ! -L $path ]]; then
            [[ $(stat -c '%u:%a' -- "$path" 2>/dev/null) == 0:700 ]] || return 1
        elif [[ -f $path && ! -L $path ]]; then
            meta=$(stat -c '%u:%a:%h' -- "$path" 2>/dev/null) || return 1
            [[ $meta == 0:400:1 || $meta == 0:600:1 ]] || return 1
        else
            return 1
        fi
    done < <(find "$root" -xdev -mindepth 1 -print0 | sort -z)
}

mvc_er_tree_manifest() {
    (( $# == 2 )) || return 1
    local root=$1 prefix=$2 path rel mode hash
    mvc_er_tree_safe "$root" || return 1
    mode=$(stat -c '%a' -- "$root") || return 1
    printf 'D|%s|%s\n' "$prefix" "$mode"
    while IFS= read -r -d '' path; do
        rel=${path#"$root"/}
        mode=$(stat -c '%a' -- "$path") || return 1
        if [[ -d $path && ! -L $path ]]; then
            printf 'D|%s/%s|%s\n' "$prefix" "$rel" "$mode"
        elif [[ -f $path && ! -L $path ]]; then
            hash=$(mvc_er_hash_file "$path") || return 1
            printf 'F|%s/%s|%s|%s\n' "$prefix" "$rel" "$mode" "$hash"
        else
            return 1
        fi
    done < <(find "$root" -xdev -mindepth 1 -print0 | sort -z)
}

mvc_er_live_snapshot_manifest() {
    (( $# == 0 )) || return 1
    local path name
    while IFS= read -r path; do
        name=${path##*/}
        if [[ -e $path || -L $path ]]; then
            mvc_er_tree_manifest "$path" "$name" || return 1
        else
            printf 'A|%s\n' "$name"
        fi
    done < <(mvc_er_fixed_root_paths)
}

mvc_er_archive_snapshot_manifest() {
    (( $# == 1 )) || return 1
    local snapshot=$1 path live name
    mvc_er_secure_dir "$snapshot" 700 || return 1
    while IFS= read -r live; do
        name=${live##*/}
        path=$snapshot/$name
        if [[ -e $path || -L $path ]]; then
            mvc_er_tree_manifest "$path" "$name" || return 1
        else
            printf 'A|%s\n' "$name"
        fi
    done < <(mvc_er_fixed_root_paths)
}

mvc_er_all_live_trees_safe() {
    (( $# == 0 )) || return 1
    local path
    while IFS= read -r path; do
        if [[ -e $path || -L $path ]]; then
            mvc_er_tree_safe "$path" || return 1
        fi
    done < <(mvc_er_fixed_root_paths)
}

mvc_er_archive_root_secure() {
    (( $# == 0 )) || return 1
    local root
    root=$(mvc_er_archive_root) || return 1
    if [[ ! -e $root && ! -L $root ]]; then
        (umask 077; mkdir -m 700 -- "$root") || return 1
    fi
    mvc_er_secure_dir "$root" 700
}

mvc_er_sameboot_values() {
    (( $# == 4 )) || return 1
    local boot=$1 userns=$2 netns=$3 mntns=$4
    [[ $boot == "$(cat /proc/sys/kernel/random/boot_id)" &&
       $userns == "$(readlink /proc/self/ns/user)" &&
       $netns == "$(readlink /proc/self/ns/net)" &&
       $mntns == "$(readlink /proc/self/ns/mnt)" ]]
}

mvc_er_archive_evidence_valid() {
    (( $# == 1 || $# == 2 )) || return 1
    local archive=$1 expected_marker=${2:-} evidence manifest marker snapshot_manifest_sha marker_sha archive_row
    local boot userns netns mntns marker_kind session_mode transaction_state clone wgtemp d4
    local -a rows=()
    mvc_er_secure_dir "$archive" 700 || return 1
    evidence=$archive/recovery-evidence
    manifest=$archive/snapshot-manifest
    mvc_er_secure_file "$evidence" 400 || return 1
    mvc_er_secure_file "$manifest" 400 || return 1
    mvc_er_secure_dir "$archive/snapshot" 700 || return 1
    mapfile -t rows < "$evidence" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    [[ ${rows[0]} == mvc-emergency-recovery-evidence-v1 &&
       ${rows[1]} == state=evidence-archived-before-finalization &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == marker_sha=* && ${rows[7]} == marker_kind=* && ${rows[8]} == session_mode=* &&
       ${rows[9]} == transaction_state=* && ${rows[10]} == ovpn_clone_uuid=* &&
       ${rows[11]} == wg_temp_uuid=* && ${rows[12]} == d4_status=* &&
       ${rows[13]} == snapshot_manifest_sha=* && ${rows[14]} == archive=* &&
       ${rows[15]} == evidence_schema=complete ]] || return 1

    boot=${rows[2]#boot=}; userns=${rows[3]#userns=}; netns=${rows[4]#netns=}; mntns=${rows[5]#mntns=}
    mvc_er_sameboot_values "$boot" "$userns" "$netns" "$mntns" || return 1
    marker_sha=${rows[6]#marker_sha=}
    [[ $marker_sha =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ -z $expected_marker || $marker_sha == "$expected_marker" ]] || return 1
    [[ ${archive##*/} == "$marker_sha" ]] || return 1
    archive_row=${rows[14]#archive=}
    [[ $archive_row == "$archive" ]] || return 1

    marker_kind=${rows[7]#marker_kind=}
    session_mode=${rows[8]#session_mode=}
    transaction_state=${rows[9]#transaction_state=}
    clone=${rows[10]#ovpn_clone_uuid=}
    wgtemp=${rows[11]#wg_temp_uuid=}
    d4=${rows[12]#d4_status=}
    case $marker_kind in active|transaction) ;; *) return 1 ;; esac
    case $session_mode in combined|openvpn-only|wireguard-protected|wireguard-split) ;; *) return 1 ;; esac
    case $d4 in historical-only|live-authenticated-evidence|not-applicable) ;; *) return 1 ;; esac
    case $session_mode in
        combined)
            mvc_er_valid_uuid "$clone" && mvc_er_valid_uuid "$wgtemp" || return 1
            ;;
        openvpn-only)
            mvc_er_valid_uuid "$clone" && [[ $wgtemp == - && $d4 == not-applicable ]] || return 1
            ;;
        wireguard-protected|wireguard-split)
            [[ $clone == - ]] && mvc_er_valid_uuid "$wgtemp" && [[ $d4 == live-authenticated-evidence ]] || return 1
            ;;
    esac

    snapshot_manifest_sha=${rows[13]#snapshot_manifest_sha=}
    mvc_er_hash_matches "$manifest" "$snapshot_manifest_sha" || return 1
    cmp -s -- "$manifest" <(mvc_er_archive_snapshot_manifest "$archive/snapshot") || return 1

    case $marker_kind in
        active) marker=$archive/snapshot/mvc-public-session/active ;;
        transaction) marker=$archive/snapshot/mvc-public-session/transaction ;;
    esac
    mvc_er_secure_file "$marker" 400 || return 1
    mvc_er_hash_matches "$marker" "$marker_sha" || return 1

    MVC_ER_ARCHIVE=$archive
    MVC_ER_MARKER_SHA=$marker_sha
    MVC_ER_MARKER_KIND=$marker_kind
    MVC_ER_SESSION_MODE=$session_mode
    MVC_ER_TRANSACTION_STATE=$transaction_state
    MVC_ER_OVPN_CLONE_UUID=$clone
    MVC_ER_WG_TEMP_UUID=$wgtemp
    MVC_ER_D4_STATUS=$d4
    MVC_ER_EVIDENCE_SHA=$(mvc_er_hash_file "$evidence") || return 1
    return 0
}

mvc_er_prepare_archive() {
    (( $# == 0 )) || return 1
    local marker marker_sha root archive stage path name live_manifest manifest_sha
    marker=$(mvc_er_marker_file) || return 1
    mvc_er_secure_file "$marker" 400 || return 1
    marker_sha=$(mvc_er_hash_file "$marker") || return 1
    mvc_er_archive_root_secure || return 1
    root=$(mvc_er_archive_root) || return 1
    archive=$root/$marker_sha

    if [[ -e $archive || -L $archive ]]; then
        mvc_er_archive_evidence_valid "$archive" "$marker_sha" || return 1
        return 0
    fi

    mvc_er_all_live_trees_safe || return 1
    stage=$(umask 077; mktemp -d "$root/.staging.XXXXXXXX") || return 1
    mkdir -m 700 -- "$stage/snapshot" || { rm -rf -- "$stage"; return 1; }
    while IFS= read -r path; do
        if [[ -e $path || -L $path ]]; then
            name=${path##*/}
            cp -a -- "$path" "$stage/snapshot/$name" || { rm -rf -- "$stage"; return 1; }
        fi
    done < <(mvc_er_fixed_root_paths)

    live_manifest=$stage/.live-manifest
    mvc_er_live_snapshot_manifest > "$live_manifest" || { rm -rf -- "$stage"; return 1; }
    mvc_er_archive_snapshot_manifest "$stage/snapshot" > "$stage/snapshot-manifest" || { rm -rf -- "$stage"; return 1; }
    cmp -s -- "$live_manifest" "$stage/snapshot-manifest" || { rm -rf -- "$stage"; return 1; }
    rm -f -- "$live_manifest"
    chmod 400 -- "$stage/snapshot-manifest" || { rm -rf -- "$stage"; return 1; }
    manifest_sha=$(mvc_er_hash_file "$stage/snapshot-manifest") || { rm -rf -- "$stage"; return 1; }

    {
        printf '%s\n' mvc-emergency-recovery-evidence-v1
        printf '%s\n' state=evidence-archived-before-finalization
        printf 'boot=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
        printf 'userns=%s\n' "$(readlink /proc/self/ns/user)"
        printf 'netns=%s\n' "$(readlink /proc/self/ns/net)"
        printf 'mntns=%s\n' "$(readlink /proc/self/ns/mnt)"
        printf 'marker_sha=%s\n' "$marker_sha"
        printf 'marker_kind=%s\n' "$MVC_ER_MARKER_KIND"
        printf 'session_mode=%s\n' "$MVC_ER_SESSION_MODE"
        printf 'transaction_state=%s\n' "$MVC_ER_TRANSACTION_STATE"
        printf 'ovpn_clone_uuid=%s\n' "$MVC_ER_OVPN_CLONE_UUID"
        printf 'wg_temp_uuid=%s\n' "$MVC_ER_WG_TEMP_UUID"
        printf 'd4_status=%s\n' "$MVC_ER_D4_STATUS"
        printf 'snapshot_manifest_sha=%s\n' "$manifest_sha"
        printf 'archive=%s\n' "$archive"
        printf '%s\n' evidence_schema=complete
    } > "$stage/recovery-evidence" || { rm -rf -- "$stage"; return 1; }
    chmod 400 -- "$stage/recovery-evidence" || { rm -rf -- "$stage"; return 1; }

    mv -T -- "$stage" "$archive" || { rm -rf -- "$stage"; return 1; }
    mvc_er_archive_evidence_valid "$archive" "$marker_sha"
}

mvc_er_publish_record() {
    (( $# == 2 )) || return 1
    local path=$1 mode=$2 dir tmp
    dir=${path%/*}
    [[ -d $dir && ! -L $dir ]] || return 1
    [[ ! -e $path && ! -L $path ]] || return 1
    tmp=$(umask 077; mktemp "$dir/.record.XXXXXXXX") || return 1
    cat > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod "$mode" -- "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -T -- "$tmp" "$path" || { rm -f -- "$tmp"; return 1; }
}

mvc_er_clone_delete_intent_valid() {
    (( $# == 1 )) || return 1
    local archive=$1 evidence_sha clone_value
    local -a rows=()
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_secure_file "$archive/clone-delete-intent" 400 || return 1
    mapfile -t rows < "$archive/clone-delete-intent" || return 1
    (( ${#rows[@]} == 6 )) || return 1
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    clone_value=${rows[5]#clone=}
    [[ ${rows[0]} == mvc-emergency-clone-delete-v1 &&
       ${rows[1]} == state=attempted-once-outcome-uncertain &&
       ${rows[2]} == "boot=$(cat /proc/sys/kernel/random/boot_id)" &&
       ${rows[3]} == "evidence_sha=$evidence_sha" &&
       ${rows[4]} == "marker_sha=$MVC_ER_MARKER_SHA" &&
       ${rows[5]} == clone=* ]] || return 1
    [[ $clone_value == "$MVC_ER_OVPN_CLONE_UUID" ]] && mvc_er_valid_uuid "$clone_value"
}

mvc_er_publish_clone_delete_intent() {
    (( $# == 1 )) || return 1
    local archive=$1 evidence_sha
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_valid_uuid "$MVC_ER_OVPN_CLONE_UUID" || return 1
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    {
        printf '%s\n' mvc-emergency-clone-delete-v1
        printf '%s\n' state=attempted-once-outcome-uncertain
        printf 'boot=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
        printf 'evidence_sha=%s\n' "$evidence_sha"
        printf 'marker_sha=%s\n' "$MVC_ER_MARKER_SHA"
        printf 'clone=%s\n' "$MVC_ER_OVPN_CLONE_UUID"
    } | mvc_er_publish_record "$archive/clone-delete-intent" 400
    mvc_er_clone_delete_intent_valid "$archive"
}

mvc_er_delete_openvpn_clone_once() {
    (( $# == 1 )) || return 1
    local archive=$1 rc=0
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_openvpn_clone_inventory || return 1
    case $MVC_ER_OVPN_CLONE_STATUS in
        not-applicable|absent) return 0 ;;
        inactive-authenticated-residue) ;;
        *) return 1 ;;
    esac

    if [[ -f $archive/clone-delete-intent && ! -L $archive/clone-delete-intent ]]; then
        mvc_er_clone_delete_intent_valid "$archive" || return 1
        mvc_er_openvpn_clone_inventory || return 1
        [[ $MVC_ER_OVPN_CLONE_STATUS == absent ]] || {
            MVC_ER_REASON=openvpn-clone-delete-attempt-present-residue-remains-no-retry
            return 1
        }
        return 0
    fi

    mvc_er_publish_clone_delete_intent "$archive" || return 1
    LC_ALL=C nmcli --wait 35 --colors no --terse connection delete uuid "$MVC_ER_OVPN_CLONE_UUID" \
      </dev/null >/dev/null 2>&1 || rc=$?
    : "$rc"
    mvc_er_openvpn_clone_inventory || {
        MVC_ER_REASON=openvpn-clone-delete-poststate-unreadable
        return 1
    }
    [[ $MVC_ER_OVPN_CLONE_STATUS == absent ]] || {
        MVC_ER_REASON=openvpn-clone-delete-outcome-not-proven-no-retry
        return 1
    }
}

mvc_er_final_network_safe() {
    (( $# == 0 )) || return 1
    mvc_er_b4_all_absent || { MVC_ER_REASON=b4-reappeared-or-unreadable; return 1; }
    mvc_er_no_active_vpn_or_tunnel || { MVC_ER_REASON=active-or-foreign-vpn-tunnel-remains; return 1; }
    mvc_er_managed_routes_absent || { MVC_ER_REASON=mvc-proto-186-or-187-route-remains; return 1; }
    mvc_er_ipv6_no_default || { MVC_ER_REASON=ipv6-default-route-present-or-unreadable; return 1; }
    mvc_er_openvpn_clone_inventory || { MVC_ER_REASON=openvpn-temporary-profile-identity-ambiguous; return 1; }
    [[ $MVC_ER_OVPN_CLONE_STATUS == absent || $MVC_ER_OVPN_CLONE_STATUS == not-applicable ]] || {
        MVC_ER_REASON=openvpn-temporary-profile-remains
        return 1
    }
    mvc_er_wireguard_residue_absent || { MVC_ER_REASON=wireguard-temporary-residue-remains; return 1; }
}

mvc_er_network_finalized_valid() {
    (( $# == 1 )) || return 1
    local archive=$1 evidence_sha expected_delete=-
    local -a rows=()
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_secure_file "$archive/network-finalized" 400 || return 1
    mapfile -t rows < "$archive/network-finalized" || return 1
    (( ${#rows[@]} == 6 )) || return 1
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    if [[ -f $archive/clone-delete-intent && ! -L $archive/clone-delete-intent ]]; then
        mvc_er_clone_delete_intent_valid "$archive" || return 1
        expected_delete=$(mvc_er_hash_file "$archive/clone-delete-intent") || return 1
    fi
    [[ ${rows[0]} == mvc-emergency-network-finalized-v1 &&
       ${rows[1]} == state=managed-network-residue-absent &&
       ${rows[2]} == "boot=$(cat /proc/sys/kernel/random/boot_id)" &&
       ${rows[3]} == "evidence_sha=$evidence_sha" &&
       ${rows[4]} == "marker_sha=$MVC_ER_MARKER_SHA" &&
       ${rows[5]} == "clone_delete_sha=$expected_delete" ]]
}

mvc_er_publish_network_finalized() {
    (( $# == 1 )) || return 1
    local archive=$1 evidence_sha delete_sha=-
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_final_network_safe || return 1
    if [[ -f $archive/network-finalized && ! -L $archive/network-finalized ]]; then
        mvc_er_network_finalized_valid "$archive"
        return
    fi
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    if [[ -f $archive/clone-delete-intent && ! -L $archive/clone-delete-intent ]]; then
        mvc_er_clone_delete_intent_valid "$archive" || return 1
        delete_sha=$(mvc_er_hash_file "$archive/clone-delete-intent") || return 1
    fi
    {
        printf '%s\n' mvc-emergency-network-finalized-v1
        printf '%s\n' state=managed-network-residue-absent
        printf 'boot=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
        printf 'evidence_sha=%s\n' "$evidence_sha"
        printf 'marker_sha=%s\n' "$MVC_ER_MARKER_SHA"
        printf 'clone_delete_sha=%s\n' "$delete_sha"
    } | mvc_er_publish_record "$archive/network-finalized" 400
    mvc_er_network_finalized_valid "$archive"
}

mvc_er_retirement_plan_valid() {
    (( $# == 0 )) || return 1
    local public plan archive evidence_sha network_sha marker_sha marker names
    local -a rows=() entries=()
    public=$(mvc_er_public_root) || return 1
    plan=$(mvc_er_recovery_plan_path) || return 1
    mvc_er_secure_dir "$public" 700 || return 1
    mvc_er_secure_file "$plan" 400 || return 1
    mapfile -t rows < "$plan" || return 1
    (( ${#rows[@]} == 7 )) || return 1
    [[ ${rows[0]} == mvc-emergency-retirement-plan-v1 &&
       ${rows[1]} == state=filesystem-retirement-pending &&
       ${rows[2]} == "boot=$(cat /proc/sys/kernel/random/boot_id)" &&
       ${rows[3]} == archive=* && ${rows[4]} == evidence_sha=* &&
       ${rows[5]} == network_sha=* && ${rows[6]} == marker_sha=* ]] || return 1
    archive=${rows[3]#archive=}
    evidence_sha=${rows[4]#evidence_sha=}
    network_sha=${rows[5]#network_sha=}
    marker_sha=${rows[6]#marker_sha=}
    mvc_er_archive_evidence_valid "$archive" "$marker_sha" || return 1
    mvc_er_network_finalized_valid "$archive" || return 1
    mvc_er_hash_matches "$archive/recovery-evidence" "$evidence_sha" || return 1
    mvc_er_hash_matches "$archive/network-finalized" "$network_sha" || return 1

    case $MVC_ER_MARKER_KIND in
        active) marker=$public/active ;;
        transaction) marker=$public/transaction ;;
        *) return 1 ;;
    esac
    mvc_er_secure_file "$marker" 400 || return 1
    mvc_er_hash_matches "$marker" "$marker_sha" || return 1

    mapfile -d '' -t entries < <(find "$public" -mindepth 1 -maxdepth 1 -print0 | sort -z) || return 1
    if [[ $MVC_ER_MARKER_KIND == active ]]; then
        (( ${#entries[@]} == 2 )) || return 1
        names=$(printf '%s\n' "${entries[@]##*/}" | sort)
        [[ $names == $'active\nrecovery-plan' ]] || return 1
    elif [[ $MVC_ER_SESSION_MODE == wireguard-split ]]; then
        (( ${#entries[@]} == 3 )) || return 1
        names=$(printf '%s\n' "${entries[@]##*/}" | sort)
        [[ $names == $'recovery-plan\nsplit.lock\ntransaction' ]] || return 1
        mvc_er_secure_file "$public/split.lock" 600 || return 1
    else
        (( ${#entries[@]} == 2 )) || return 1
        names=$(printf '%s\n' "${entries[@]##*/}" | sort)
        [[ $names == $'recovery-plan\ntransaction' ]] || return 1
    fi
    MVC_ER_ARCHIVE=$archive
    return 0
}

mvc_er_publish_retirement_plan() {
    (( $# == 1 )) || return 1
    local archive=$1 plan evidence_sha network_sha
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_network_finalized_valid "$archive" || return 1
    plan=$(mvc_er_recovery_plan_path) || return 1
    if [[ -f $plan && ! -L $plan ]]; then
        mvc_er_retirement_plan_valid
        return
    fi
    [[ ! -e $plan && ! -L $plan ]] || return 1
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    network_sha=$(mvc_er_hash_file "$archive/network-finalized") || return 1
    {
        printf '%s\n' mvc-emergency-retirement-plan-v1
        printf '%s\n' state=filesystem-retirement-pending
        printf 'boot=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
        printf 'archive=%s\n' "$archive"
        printf 'evidence_sha=%s\n' "$evidence_sha"
        printf 'network_sha=%s\n' "$network_sha"
        printf 'marker_sha=%s\n' "$MVC_ER_MARKER_SHA"
    } | mvc_er_publish_record "$plan" 400
    mvc_er_retirement_plan_valid
}

mvc_er_acquire_finalization_locks() {
    (( $# == 0 )) || return 1
    local controller public lock fd
    MVC_ER_LOCKS_HELD=no
    MVC_ER_CONTROLLER_LOCK_FD=
    MVC_ER_SPLIT_LOCK_FD=
    controller=$(mvc_er_controller_root) || return 1
    public=$(mvc_er_public_root) || return 1
    if [[ -e $controller || -L $controller ]]; then
        mvc_er_secure_dir "$controller" 700 || return 1
        lock=$controller/controller.lock
        mvc_er_secure_file "$lock" 600 || return 1
        exec {fd}< "$lock" || return 1
        flock -n "$fd" || { exec {fd}>&-; return 1; }
        MVC_ER_CONTROLLER_LOCK_FD=$fd
    fi
    if [[ -f $public/split.lock && ! -L $public/split.lock ]]; then
        mvc_er_secure_file "$public/split.lock" 600 || return 1
        exec {fd}< "$public/split.lock" || return 1
        flock -n "$fd" || { exec {fd}>&-; return 1; }
        MVC_ER_SPLIT_LOCK_FD=$fd
    fi
    MVC_ER_LOCKS_HELD=yes
}

mvc_er_release_finalization_locks() {
    (( $# == 0 )) || return 1
    if [[ -n ${MVC_ER_SPLIT_LOCK_FD:-} ]]; then
        eval "exec ${MVC_ER_SPLIT_LOCK_FD}>&-"
    fi
    if [[ -n ${MVC_ER_CONTROLLER_LOCK_FD:-} ]]; then
        eval "exec ${MVC_ER_CONTROLLER_LOCK_FD}>&-"
    fi
    MVC_ER_SPLIT_LOCK_FD=
    MVC_ER_CONTROLLER_LOCK_FD=
    MVC_ER_LOCKS_HELD=no
}

mvc_er_publish_recovery_result() {
    (( $# == 1 )) || return 1
    local archive=$1 evidence_sha network_sha
    mvc_er_archive_evidence_valid "$archive" || return 1
    mvc_er_network_finalized_valid "$archive" || return 1
    if [[ -f $archive/recovery-result && ! -L $archive/recovery-result ]]; then
        mvc_er_secure_file "$archive/recovery-result" 400
        return
    fi
    evidence_sha=$(mvc_er_hash_file "$archive/recovery-evidence") || return 1
    network_sha=$(mvc_er_hash_file "$archive/network-finalized") || return 1
    {
        printf '%s\n' mvc-emergency-recovery-result-v1
        printf '%s\n' state=live-authority-retired
        printf 'boot=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
        printf 'evidence_sha=%s\n' "$evidence_sha"
        printf 'network_sha=%s\n' "$network_sha"
    } | mvc_er_publish_record "$archive/recovery-result" 400
}

mvc_er_retire_live_roots() {
    (( $# == 0 )) || return 1
    local public path
    mvc_er_retirement_plan_valid || { MVC_ER_REASON=recovery-retirement-plan-invalid; return 1; }
    mvc_er_final_network_safe || return 1
    public=$(mvc_er_public_root) || return 1

    for path in \
        "$(mvc_er_completion_root)" "$(mvc_er_disconnect_root)" "$(mvc_er_wireguard_root)" \
        "$(mvc_er_output_root)" "$(mvc_er_activation_root)" "$(mvc_er_controller_root)"; do
        if [[ -e $path || -L $path ]]; then
            mvc_er_tree_safe "$path" || { MVC_ER_REASON=unsafe-live-runtime-tree-before-retirement; return 1; }
            rm -rf -- "$path" || { MVC_ER_REASON=live-runtime-retirement-failed; return 1; }
            [[ ! -e $path && ! -L $path ]] || { MVC_ER_REASON=live-runtime-retirement-unproven; return 1; }
        fi
    done

    mvc_er_retirement_plan_valid || { MVC_ER_REASON=recovery-retirement-plan-invalid-after-partial-retirement; return 1; }
    mvc_er_tree_safe "$public" || { MVC_ER_REASON=unsafe-public-session-tree-before-retirement; return 1; }
    rm -rf -- "$public" || { MVC_ER_REASON=public-session-retirement-failed; return 1; }
    [[ ! -e $public && ! -L $public ]] || { MVC_ER_REASON=public-session-retirement-unproven; return 1; }

    mvc_er_fixed_roots_all_absent || { MVC_ER_REASON=live-mvc-root-remains-after-retirement; return 1; }
    mvc_er_final_network_safe || return 1
    mvc_er_publish_recovery_result "$MVC_ER_ARCHIVE" || {
        MVC_ER_REASON=recovery-result-record-failed-after-safe-retirement
        return 1
    }
    MVC_ER_REASON=recovery-finalized-sameboot-admission-available
    return 0
}

mvc_er_finalize_recovery() {
    (( $# == 0 )) || return 1
    local public plan rc mode_before marker_before archive
    mvc_er_reset_classifier
    mvc_er_root_scope || { MVC_ER_REASON=root-scope-not-proven; return 1; }
    mvc_er_b4_all_absent || { MVC_ER_REASON=b4-still-present-or-unreadable; return 1; }
    public=$(mvc_er_public_root) || { MVC_ER_REASON=public-session-root-unavailable; return 1; }
    plan=$(mvc_er_recovery_plan_path) || return 1

    if [[ -e $plan || -L $plan ]]; then
        mvc_er_acquire_finalization_locks || { MVC_ER_REASON=live-session-lock-busy-or-invalid; return 1; }
        if ! mvc_er_retirement_plan_valid; then
            mvc_er_release_finalization_locks || true
            MVC_ER_REASON=recovery-retirement-plan-invalid
            return 1
        fi
        if mvc_er_retire_live_roots; then
            rc=0
        else
            rc=$?
        fi
        mvc_er_release_finalization_locks || true
        return "$rc"
    fi

    if mvc_er_finalization_classify; then
        rc=0
    else
        rc=$?
    fi
    (( rc == 0 )) || return "$rc"
    if [[ $MVC_ER_SESSION_MODE == baseline ]]; then
        MVC_ER_REASON=recovery-already-clean-baseline
        return 0
    fi

    mode_before=$MVC_ER_SESSION_MODE
    marker_before=$MVC_ER_MARKER_KIND
    mvc_er_acquire_finalization_locks || { MVC_ER_REASON=live-session-lock-busy-or-invalid; return 1; }
    if mvc_er_finalization_classify; then
        rc=0
    else
        rc=$?
    fi
    if (( rc != 0 )) || [[ $MVC_ER_SESSION_MODE != "$mode_before" || $MVC_ER_MARKER_KIND != "$marker_before" ]]; then
        mvc_er_release_finalization_locks || true
        MVC_ER_REASON=finalization-state-changed-before-commit
        return 1
    fi

    if ! mvc_er_all_live_trees_safe; then
        mvc_er_release_finalization_locks || true
        MVC_ER_REASON=unsafe-live-runtime-tree
        return 1
    fi
    if ! mvc_er_prepare_archive; then
        mvc_er_release_finalization_locks || true
        MVC_ER_REASON=recovery-evidence-archive-failed
        return 1
    fi
    archive=$MVC_ER_ARCHIVE

    if ! mvc_er_delete_openvpn_clone_once "$archive"; then
        mvc_er_release_finalization_locks || true
        [[ ${MVC_ER_REASON:-unverified} != unverified ]] || MVC_ER_REASON=openvpn-clone-retirement-failed
        return 1
    fi
    if ! mvc_er_publish_network_finalized "$archive"; then
        mvc_er_release_finalization_locks || true
        [[ ${MVC_ER_REASON:-unverified} != unverified ]] || MVC_ER_REASON=post-mutation-final-safety-not-proven
        return 1
    fi
    if ! mvc_er_publish_retirement_plan "$archive"; then
        mvc_er_release_finalization_locks || true
        MVC_ER_REASON=recovery-retirement-plan-publish-failed
        return 1
    fi
    if mvc_er_retire_live_roots; then
        rc=0
    else
        rc=$?
    fi
    mvc_er_release_finalization_locks || true
    return "$rc"
}

mvc_er_print_mutating_finalization_result() {
    (( $# == 1 )) || return 1
    local rc=$1
    if (( rc == 0 )); then
        if [[ ${MVC_ER_REASON:-} == recovery-already-clean-baseline ]]; then
            printf '%s\n' 'PASS: MVC recovery state is already clean'
        else
            printf '%s\n' 'PASS: authenticated emergency recovery finalization completed'
            [[ -z ${MVC_ER_ARCHIVE:-} ]] || printf 'DETAIL: recovery evidence archived at %s\n' "$MVC_ER_ARCHIVE"
        fi
        printf '%s\n' \
          'RESULT: EMERGENCY RECOVERY COMPLETE — MVC OWNED STATE RETIRED' \
          'NOTE: a new same-boot MVC session may be attempted; normal connect admission still applies'
    else
        printf 'BLOCKED: emergency recovery finalization incomplete: %s\n' "${MVC_ER_REASON:-unverified}" >&2
        [[ -z ${MVC_ER_ARCHIVE:-} ]] || printf 'DETAIL: retained recovery evidence: %s\n' "$MVC_ER_ARCHIVE" >&2
        printf '%s\n' 'RESULT: EMERGENCY RECOVERY FINALIZATION INCOMPLETE — MVC REUSE REMAINS BLOCKED' >&2
    fi
}

mvc_er_require_finalization_dependencies() {
    local cmd
    for cmd in awk cat chmod cmp cp find flock ip jq mkdir mktemp mv nmcli nft pgrep readlink rm sha256sum sort stat wg; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'ERROR: required command missing for finalization inspection: %s\n' "$cmd" >&2
            return 1
        }
    done
}

mvc_er_main() {
    (( $# == 1 )) || mvc_er_usage
    local mode=$1 before again batch remaining rc
    case $mode in --inspect|--rollback|--finalization-inspect|--finalize) ;; *) mvc_er_usage ;; esac
    (( EUID == 0 )) || { echo 'ERROR: root required' >&2; return 1; }
    command -v nft >/dev/null && command -v jq >/dev/null || {
        echo 'ERROR: nft and jq required; see direct nft fallback in handoff' >&2
        return 1
    }

    if [[ $mode == --finalization-inspect ]]; then
        mvc_er_require_finalization_dependencies || return 1
        if mvc_er_finalization_classify; then
            rc=0
        else
            rc=$?
        fi
        mvc_er_print_finalization_result "$rc"
        return "$rc"
    fi

    if [[ $mode == --finalize ]]; then
        mvc_er_require_finalization_dependencies || return 1
        if mvc_er_finalize_recovery; then
            rc=0
        else
            rc=$?
        fi
        mvc_er_print_mutating_finalization_result "$rc"
        return "$rc"
    fi

    before=$(mvc_er_owned_tables) || { echo 'ERROR: cannot inventory nft tables' >&2; return 1; }
    if [[ -z $before ]]; then
        echo 'PASS: none of the three B4 quarantine tables is present'
        if [[ $mode == --inspect ]]; then
            echo 'RESULT: no nftables changes; other connectivity issues need separate diagnosis'
            return 0
        fi
        if ! mvc_er_require_finalization_dependencies; then
            printf '%s\n' \
              'RESULT: EMERGENCY DISARM COMPLETE — RECOVERY FINALIZATION INCOMPLETE' \
              'NOTE: B4 is already off, but finalization dependencies are unavailable; MVC reuse remains blocked' >&2
            return 1
        fi
        if mvc_er_finalize_recovery; then
            rc=0
        else
            rc=$?
        fi
        mvc_er_print_mutating_finalization_result "$rc"
        return "$rc"
    fi
    printf '%s\n' 'B4 quarantine tables currently present:' "$before"
    if [[ $mode == --inspect ]]; then
        echo 'RESULT: READ-ONLY OBSERVATION; NO RULES CHANGED'
        return 0
    fi

    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty &&
       -z ${SSH_CONNECTION:-} && -z ${SSH_TTY:-} ]] || {
        echo 'ERROR: --rollback requires a local interactive terminal' >&2
        return 1
    }
    printf '%s\n' \
      'WARNING: This deliberately DISABLES the B4 v2.4 quarantine, even if its journal is damaged.' \
      'It is NOT safe to use for an active protected VPN session.' \
      'After B4 is disarmed, the tool will attempt authenticated recovery finalization.' \
      'Type exactly: EMERGENCY RELEASE MVC' > /dev/tty
    printf '> ' > /dev/tty
    IFS= read -r confirmation < /dev/tty || return 1
    [[ $confirmation == 'EMERGENCY RELEASE MVC' ]] || {
        echo 'ERROR: confirmation refused' >&2
        return 1
    }

    again=$(mvc_er_owned_tables) || return 1
    [[ $before == "$again" ]] || {
        echo 'ERROR: quarantine table set changed; no nftables write attempted' >&2
        return 1
    }

    batch=$(mktemp /run/mvc-emergency-delete.XXXXXXXX.nft) || return 1
    trap 'rm -f -- "$batch"' RETURN
    chmod 600 -- "$batch"
    while IFS= read -r table; do
        case "$table" in
            inet:mvc_preclone_quarantine)
                echo 'delete table inet mvc_preclone_quarantine' >> "$batch" ;;
            bridge:mvc_preclone_bridge)
                echo 'delete table bridge mvc_preclone_bridge' >> "$batch" ;;
            netdev:mvc_preclone_underlay)
                echo 'delete table netdev mvc_preclone_underlay' >> "$batch" ;;
            *) echo 'ERROR: unexpected table identifier' >&2; return 1 ;;
        esac
    done <<< "$before"

    nft --check --file "$batch" || {
        echo 'ERROR: nft rejected emergency delete batch; no commit attempted' >&2
        return 1
    }
    if ! nft --file "$batch"; then
        echo 'ERROR: nft commit failed or is uncertain; check tables manually' >&2
        return 1
    fi
    remaining=$(mvc_er_owned_tables) || {
        echo 'UNVERIFIED: deletion submitted, but poststate cannot be read' >&2
        return 1
    }
    [[ -z $remaining ]] || {
        printf '%s\n' 'UNVERIFIED: some B4 quarantine tables remain:' "$remaining" >&2
        return 1
    }
    printf '%s\n' \
      'PASS: all three B4 quarantine tables are absent' \
      'RESULT: EMERGENCY DISARM COMPLETE — MVC kill switch OFF; other nftables tables untouched'

    if ! mvc_er_require_finalization_dependencies; then
        printf '%s\n' \
          'RESULT: EMERGENCY DISARM COMPLETE — RECOVERY FINALIZATION INCOMPLETE' \
          'NOTE: B4 is off, but lifecycle finalization could not run; retained MVC authority still blocks reuse' >&2
        return 1
    fi
    if mvc_er_finalize_recovery; then
        rc=0
    else
        rc=$?
    fi
    mvc_er_print_mutating_finalization_result "$rc"
    return "$rc"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    mvc_er_main "$@"
fi
