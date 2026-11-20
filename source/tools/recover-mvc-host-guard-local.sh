#!/usr/bin/env bash
# Manual emergency recovery for the MVC B4 maintenance quarantine.
#
# --rollback remains the independent B4 break-glass action: it can disarm the
# three MVC quarantine tables even when normal lifecycle journals are damaged.
#
# --finalization-inspect is deliberately READ-ONLY. It classifies whether the
# retained same-boot MVC state is sufficiently authenticated and sufficiently
# free of live managed network residue for a future recovery-finalization step.
# This checkpoint grants no lifecycle-retirement mutation authority.
set -euo pipefail
umask 077
export LC_ALL=C

mvc_er_usage() {
    printf '%s\n' 'Usage: recover-mvc-host-guard-local.sh --inspect|--rollback|--finalization-inspect' >&2
    exit 2
}

mvc_er_public_root() { printf '%s\n' /run/mvc-public-session; }
mvc_er_controller_root() { printf '%s\n' /run/mvc-controller; }
mvc_er_activation_root() { printf '%s\n' /run/mvc-activation; }
mvc_er_output_root() { printf '%s\n' /run/mvc-output-transition; }
mvc_er_disconnect_root() { printf '%s\n' /run/mvc-disconnect; }
mvc_er_completion_root() { printf '%s\n' /run/mvc-completion; }
mvc_er_wireguard_root() { printf '%s\n' /run/mvc-wireguard; }
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
            MVC_ER_PARSE_DETAIL=partial-start-not-supported-r1
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
    if (( rc == 2 )) && [[ ${MVC_ER_PARSE_DETAIL:-} == partial-start-not-supported-r1 ]]; then
        mvc_er_block partial-start-finalization-not-supported-in-r1
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

mvc_er_require_finalization_dependencies() {
    local cmd
    for cmd in awk cat find flock ip jq nmcli nft pgrep readlink sha256sum stat wg; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'ERROR: required command missing for finalization inspection: %s\n' "$cmd" >&2
            return 1
        }
    done
}

mvc_er_main() {
    (( $# == 1 )) || mvc_er_usage
    local mode=$1 before again batch remaining rc
    case $mode in --inspect|--rollback|--finalization-inspect) ;; *) mvc_er_usage ;; esac
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

    before=$(mvc_er_owned_tables) || { echo 'ERROR: cannot inventory nft tables' >&2; return 1; }
    if [[ -z $before ]]; then
        echo 'PASS: none of the three B4 quarantine tables is present'
        echo 'RESULT: no nftables changes; other connectivity issues need separate diagnosis'
        return 0
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
      'Type exactly: EMERGENCY RELEASE MVC' > /dev/tty
    printf '> ' > /dev/tty
    IFS= read -r confirmation < /dev/tty || return 1
    [[ $confirmation == 'EMERGENCY RELEASE MVC' ]] || {
        echo 'ERROR: confirmation refused' >&2
        return 1
    }

    # State must remain stable between the original observation and commitment.
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
    # A single atomic nft batch. No retry after a failed or ambiguous commit.
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
      'RESULT: EMERGENCY DISARM COMPLETE — MVC kill switch OFF; other nftables tables untouched' \
      'NOTE: recovery finalization is read-only in this development checkpoint; use --finalization-inspect to assess eligibility, and reboot before starting another MVC session'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    mvc_er_main "$@"
fi
