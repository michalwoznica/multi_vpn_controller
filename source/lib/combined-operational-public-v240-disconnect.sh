#!/usr/bin/env bash
# C23BE + C23BF Stage 6 — fresh-process public-v2.4 active/partial-session reattachment and reconciliation.
# Stage 6 adds completed-session public-marker retirement after authenticated C23T archival.
#
# Loaded only by the public candidate composition, after C23AU.  It does not
# enable the public dispatcher.  A durable public-session marker is only an
# index/binding: every fresh process reacquires the existing B2 lock, validates
# same-boot/namespace identity, recomputes immutable journal hashes, reconstructs
# nonsecret OpenVPN/WireGuard state from the authoritative journals/current
# saved WG profile, and re-observes the exact protected dual state before any
# teardown authority exists.

ubs24pubd_reset() {
    UBS24PUBD_ATTEMPTED=no
    UBS24PUBD_STAGE=idle
    UBS24PUBD_OPERATION=none
    UBS24PUBD_SESSION_MODE=none
    UBS24PUBD_APPROVAL=none
    UBS24PUBD_AUTHORITY=none
    UBS24PUBD_OVPN_SOURCE_UUID=
    UBS24PUBD_OVPN_CLONE_UUID=
    UBS24PUBD_WG_SOURCE_UUID=
    UBS24PUBD_WG_TEMP_UUID=
    UBS24PUBD_UNDERLAY=
    UBS24PUBD_MARKER_KIND=none
    UBS24PUBD_TRANSACTION_STATE=none
    UBS24PUBD_COMPLETED_MARKER_FILE=
}

ubs24pubd_active_path() {
    local runtime
    runtime=$(ubs24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/active"
}

ubs24pubd_hash_file() { ubs24pubc_hash_file "$@"; }


ubs24pubd_transaction_path() {
    local runtime
    runtime=$(ubs24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/transaction"
}

ubs24pubd_parse_transaction_marker() {
    (( $# == 0 )) || return 1
    local runtime file state boot userns netns mntns
    local -a rows=() entries=()
    runtime=$(ubs24pub_session_runtime_root) || return 1
    file=$runtime/transaction
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime") == '0:700:2' ]] || return 1
    [[ -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file") == '0:400:1' ]] || return 1
    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    [[ ${rows[0]} == ubs-v240-public-transaction-v1 && ${rows[1]} == state=* &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == ovpn_source_uuid=* && ${rows[7]} == ovpn_clone_uuid=* &&
       ${rows[8]} == wg_source_uuid=* && ${rows[9]} == wg_temp_uuid=* && ${rows[10]} == underlay=* &&
       ${rows[11]} == controller_prepare_sha=* && ${rows[12]} == controller_transition_sha=* &&
       ${rows[13]} == activation_sha=* && ${rows[14]} == output_sha=* && ${rows[15]} == d4_intent_sha=* ]] || return 1
    state=${rows[1]#state=}
    case $state in prepared-before-mutation|openvpn-protected|dual-active-observed|wireguard-protected|wireguard-split-prepared|wireguard-split) ;; *) return 1 ;; esac
    if [[ $state == wireguard-split-prepared || $state == wireguard-split ]]; then
        local entry base seen_tx=0 seen_lock=0
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
        [[ -f $file && ! -L $runtime/split.lock && -f $runtime/split.lock &&
           $(stat -c '%u:%a:%h' -- "$runtime/split.lock") == '0:600:1' ]] || return 1
    elif [[ $state == prepared-before-mutation ]]; then
        local entry base
        (( ${#entries[@]} >= 1 && ${#entries[@]} <= 15 )) || return 1
        for entry in "${entries[@]}"; do
            base=${entry##*/}
            case $base in
              transaction|preclone-intent|preclone-binding|preclone-delete-intent|preclone-release.nft|preclone-release-intent|preclone-retire-intent|early-plan|early-handback.nft|early-handback-intent|early-stop-intent|early-clone-delete-intent|early-guard-release.nft|early-guard-release-intent|early-retire-intent) ;;
              *) return 1 ;;
            esac
        done
        [[ -f $file ]] || return 1
    else
        (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$file" ]] || return 1
    fi
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" ]] || return 1

    UBS24PUBD_OVPN_SOURCE_UUID=${rows[6]#ovpn_source_uuid=}
    UBS24PUBD_OVPN_CLONE_UUID=${rows[7]#ovpn_clone_uuid=}
    UBS24PUBD_WG_SOURCE_UUID=${rows[8]#wg_source_uuid=}
    UBS24PUBD_WG_TEMP_UUID=${rows[9]#wg_temp_uuid=}
    UBS24PUBD_UNDERLAY=${rows[10]#underlay=}
    ubs24gb1_valid_ifname "$UBS24PUBD_UNDERLAY" || return 1

    if [[ $UBS24PUBD_OVPN_SOURCE_UUID == - && $UBS24PUBD_OVPN_CLONE_UUID == - ]]; then
        ubs24_valid_uuid "$UBS24PUBD_WG_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_WG_TEMP_UUID" || return 1
        case $state in
          prepared-before-mutation|wireguard-protected) UBS24PUBD_SESSION_MODE=wireguard-protected ;;
          wireguard-split-prepared|wireguard-split) UBS24PUBD_SESSION_MODE=wireguard-split ;;
          *) return 1 ;;
        esac
    else
        ubs24_valid_uuid "$UBS24PUBD_OVPN_SOURCE_UUID" || return 1
        if [[ $UBS24PUBD_WG_SOURCE_UUID == - && $UBS24PUBD_WG_TEMP_UUID == - ]]; then
            [[ $state != dual-active-observed && $state != wireguard-protected ]] || return 1
            UBS24PUBD_SESSION_MODE=openvpn-only
        else
            ubs24_valid_uuid "$UBS24PUBD_WG_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_WG_TEMP_UUID" || return 1
            [[ $state != wireguard-protected ]] || return 1
            UBS24PUBD_SESSION_MODE=combined
        fi
    fi

    if [[ $state == prepared-before-mutation || $state == wireguard-split-prepared ]]; then
        [[ $UBS24PUBD_OVPN_CLONE_UUID == - &&
           ${rows[11]} == controller_prepare_sha=- && ${rows[12]} == controller_transition_sha=- &&
           ${rows[13]} == activation_sha=- && ${rows[14]} == output_sha=- && ${rows[15]} == d4_intent_sha=- ]] || return 1
    elif [[ $state == wireguard-protected ]]; then
        [[ ${rows[11]#controller_prepare_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_controller_prepare_path)")" &&
           ${rows[12]} == controller_transition_sha=- && ${rows[13]} == activation_sha=- &&
           ${rows[14]} == output_sha=- &&
           ${rows[15]#d4_intent_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_d4_intent_path)")" ]] || return 1
    elif [[ $state == wireguard-split ]]; then
        [[ ${rows[11]} == controller_prepare_sha=- && ${rows[12]} == controller_transition_sha=- &&
           ${rows[13]} == activation_sha=- && ${rows[14]} == output_sha=- &&
           ${rows[15]#d4_intent_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_d4_intent_path)")" ]] || return 1
    else
        ubs24_valid_uuid "$UBS24PUBD_OVPN_CLONE_UUID" || return 1
        [[ ${rows[11]#controller_prepare_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_controller_prepare_path)")" &&
           ${rows[12]#controller_transition_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_controller_transition_path)")" &&
           ${rows[13]#activation_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_activation_path)")" &&
           ${rows[14]#output_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_output_path)")" ]] || return 1
        if [[ $state == openvpn-protected ]]; then
            [[ ${rows[15]} == d4_intent_sha=- ]] || return 1
        else
            [[ ${rows[15]#d4_intent_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_d4_intent_path)")" ]] || return 1
        fi
    fi
    UBS24PUBD_MARKER_KIND=transaction
    UBS24PUBD_TRANSACTION_STATE=$state
}

ubs24pubd_parse_session_marker() {
    (( $# == 0 )) || return 1
    UBS24PUBD_MARKER_KIND=none
    UBS24PUBD_TRANSACTION_STATE=none
    if ubs24pubd_parse_active_marker; then
        UBS24PUBD_MARKER_KIND=active
        return 0
    fi
    ubs24pubd_parse_transaction_marker
}

# Exact C23AU marker parser. Kept separate from the shape probe above to make
# line-count/key order reviewable and to avoid accepting duplicate keys.
ubs24pubd_parse_active_marker() {
    (( $# == 0 )) || return 1
    local runtime file
    runtime=$(ubs24pub_session_runtime_root) || return 1
    local -a rows=() entries=()
    local boot userns netns mntns hashes activation_sha output_sha d4_sha
    file=$runtime/active
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime") == '0:700:2' ]] || return 1
    [[ -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file") == '0:400:1' ]] || return 1
    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    [[ ${rows[0]} == ubs-v240-public-active-v1 && ${rows[1]} == state=dual-active-published &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == ovpn_source_uuid=* && ${rows[7]} == ovpn_clone_uuid=* &&
       ${rows[8]} == wg_source_uuid=* && ${rows[9]} == wg_temp_uuid=* && ${rows[10]} == underlay=* &&
       ${rows[11]} == controller_prepare_sha=* && ${rows[12]} == controller_transition_sha=* &&
       ${rows[13]} == activation_sha=* && ${rows[14]} == output_sha=* && ${rows[15]} == d4_intent_sha=* ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" ]] || return 1

    UBS24PUBD_OVPN_SOURCE_UUID=${rows[6]#ovpn_source_uuid=}
    UBS24PUBD_OVPN_CLONE_UUID=${rows[7]#ovpn_clone_uuid=}
    UBS24PUBD_WG_SOURCE_UUID=${rows[8]#wg_source_uuid=}
    UBS24PUBD_WG_TEMP_UUID=${rows[9]#wg_temp_uuid=}
    UBS24PUBD_UNDERLAY=${rows[10]#underlay=}
    ubs24_valid_uuid "$UBS24PUBD_OVPN_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_OVPN_CLONE_UUID" &&
      ubs24_valid_uuid "$UBS24PUBD_WG_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_WG_TEMP_UUID" &&
      ubs24gb1_valid_ifname "$UBS24PUBD_UNDERLAY" || return 1
    UBS24PUBD_SESSION_MODE=combined

    [[ ${rows[11]#controller_prepare_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_controller_prepare_path)")" &&
       ${rows[12]#controller_transition_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_controller_transition_path)")" &&
       ${rows[13]#activation_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_activation_path)")" &&
       ${rows[14]#output_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_output_path)")" &&
       ${rows[15]#d4_intent_sha=} == "$(ubs24pubd_hash_file "$(ubs24pubc_d4_intent_path)")" ]] || return 1
    UBS24PUBD_MARKER_KIND=active
}

# After C23T has completed and archived the session, the live D4 intent is gone
# by design. A final public marker may nevertheless remain if its filesystem-only
# retirement was interrupted. This parser grants no network authority: it binds
# the marker to the completed C23T archive and independently proves that all
# managed network/WireGuard residue is absent before allowing marker deletion.
ubs24pubd_completed_foreign_policy_witness() {
    (( $# == 1 )) || return 1
    local prestate=$1 scratch first second before after good=1
    [[ -f $prestate && ! -L $prestate ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-pubd-completed.XXXXXXXX) || return 1
    first=$scratch/first.json
    second=$scratch/second.json
    if ! ubs24gb1_capture_nft "$first" || ! ubs24gb1_capture_nft "$second" || ! cmp -s -- "$first" "$second" ||
       ! ubs24gc23t_owned_tables_absent "$first" || ! ubs24gc23t_owned_tables_absent "$second"; then
        good=0
    else
        before=$(ubs24gb2_foreign_projection "$prestate") || good=0
        after=$(ubs24gb2_foreign_projection "$first") || good=0
        [[ $before == "$after" ]] || good=0
    fi
    rm -f -- "$first" "$second" >/dev/null 2>&1 || good=0
    rmdir -- "$scratch" >/dev/null 2>&1 || good=0
    (( good == 1 ))
}

ubs24pubd_parse_completed_session_marker() {
    (( $# == 0 )) || return 1
    local runtime file kind state boot userns netns mntns root archive plan release delete
    local route186 route187 entry
    local -a rows=() entries=() plan_rows=()
    runtime=$(ubs24pub_session_runtime_root) || return 1
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' ]] || return 1
    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) || return 1
    entry=${entries[0]##*/}
    case $entry in
      active) kind=completed-active; file=$runtime/active ;;
      transaction) kind=completed-transaction; file=$runtime/transaction ;;
      *) return 1 ;;
    esac
    [[ -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 16 )) || return 1
    if [[ $entry == active ]]; then
        [[ ${rows[0]} == ubs-v240-public-active-v1 && ${rows[1]} == state=dual-active-published ]] || return 1
        state=dual-active-observed
    else
        [[ ${rows[0]} == ubs-v240-public-transaction-v1 && ${rows[1]} == state=* ]] || return 1
        state=${rows[1]#state=}
        case $state in openvpn-protected|dual-active-observed) ;; *) return 1 ;; esac
    fi
    [[ ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == ovpn_source_uuid=* && ${rows[7]} == ovpn_clone_uuid=* &&
       ${rows[8]} == wg_source_uuid=* && ${rows[9]} == wg_temp_uuid=* && ${rows[10]} == underlay=* &&
       ${rows[11]} == controller_prepare_sha=* && ${rows[12]} == controller_transition_sha=* &&
       ${rows[13]} == activation_sha=* && ${rows[14]} == output_sha=* && ${rows[15]} == d4_intent_sha=* ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" ]] || return 1

    UBS24PUBD_OVPN_SOURCE_UUID=${rows[6]#ovpn_source_uuid=}
    UBS24PUBD_OVPN_CLONE_UUID=${rows[7]#ovpn_clone_uuid=}
    UBS24PUBD_WG_SOURCE_UUID=${rows[8]#wg_source_uuid=}
    UBS24PUBD_WG_TEMP_UUID=${rows[9]#wg_temp_uuid=}
    UBS24PUBD_UNDERLAY=${rows[10]#underlay=}
    ubs24_valid_uuid "$UBS24PUBD_OVPN_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_OVPN_CLONE_UUID" &&
      ubs24gb1_valid_ifname "$UBS24PUBD_UNDERLAY" || return 1
    if [[ $UBS24PUBD_WG_SOURCE_UUID == - && $UBS24PUBD_WG_TEMP_UUID == - ]]; then
        [[ $state == openvpn-protected ]] || return 1
        UBS24PUBD_SESSION_MODE=openvpn-only
    else
        ubs24_valid_uuid "$UBS24PUBD_WG_SOURCE_UUID" && ubs24_valid_uuid "$UBS24PUBD_WG_TEMP_UUID" || return 1
        UBS24PUBD_SESSION_MODE=combined
    fi
    if [[ $state == openvpn-protected ]]; then
        [[ ${rows[15]} == d4_intent_sha=- ]] || return 1
    else
        [[ ${rows[15]#d4_intent_sha=} =~ ^[0-9a-f]{64}$ ]] || return 1
    fi

    root=$(ubs24gc23t_archive_root) || return 1
    archive=$root/$UBS24PUBD_OVPN_CLONE_UUID
    [[ -d $root && ! -L $root && -d $archive && ! -L $archive &&
       $(stat -c '%u:%a' -- "$root" 2>/dev/null) == '0:700' &&
       $(stat -c '%u:%a' -- "$archive" 2>/dev/null) == '0:700' ]] || return 1
    for entry in controller activation output-transition disconnect completion; do
        [[ -d $archive/$entry && ! -L $archive/$entry &&
           $(stat -c '%u:%a' -- "$archive/$entry" 2>/dev/null) == '0:700' ]] || return 1
    done
    [[ ${rows[11]#controller_prepare_sha=} == "$(ubs24pubd_hash_file "$archive/controller/prepare-intent")" &&
       ${rows[12]#controller_transition_sha=} == "$(ubs24pubd_hash_file "$archive/controller/transition-attempt")" &&
       ${rows[13]#activation_sha=} == "$(ubs24pubd_hash_file "$archive/activation/attempt")" &&
       ${rows[14]#output_sha=} == "$(ubs24pubd_hash_file "$archive/output-transition/attempt")" ]] || return 1

    plan=$archive/completion/archive-plan
    release=$archive/completion/release-intent
    delete=$archive/completion/clone-delete-intent
    [[ -f $plan && ! -L $plan && -f $release && ! -L $release && -f $delete && ! -L $delete ]] || return 1
    mapfile -t plan_rows < "$plan" || return 1
    (( ${#plan_rows[@]} == 8 )) || return 1
    [[ ${plan_rows[0]} == ubs-v240-c23t-archive-plan-v1 &&
       ${plan_rows[1]} == state=completed-session-archive-pending &&
       ${plan_rows[2]} == "boot=$boot" &&
       ${plan_rows[3]} == "release=$(ubs24pubd_hash_file "$release")" &&
       ${plan_rows[4]} == "delete=$(ubs24pubd_hash_file "$delete")" &&
       ${plan_rows[5]} == "source=$UBS24PUBD_OVPN_SOURCE_UUID" &&
       ${plan_rows[6]} == "clone=$UBS24PUBD_OVPN_CLONE_UUID" &&
       ${plan_rows[7]} == "archive=$archive" ]] || return 1

    for entry in /run/mvc-controller /run/mvc-activation /run/mvc-output-transition \
                 /run/mvc-disconnect /run/mvc-completion /run/mvc-wireguard; do
        [[ ! -e $entry && ! -L $entry ]] || return 1
    done
    ubs24gb4_no_active_vpn || return 1
    UBS24GC23T_SOURCE_UUID=$UBS24PUBD_OVPN_SOURCE_UUID
    UBS24GC23T_CLONE_UUID=$UBS24PUBD_OVPN_CLONE_UUID
    ubs24gc23t_clone_absent "$UBS24PUBD_OVPN_CLONE_UUID" || return 1
    ubs24pubd_completed_foreign_policy_witness "$archive/controller/prestate.json" || return 1

    UBS24GD4_TEMP_NAME=vpnks-wg
    UBS24GD4_TEMP_UUID=$UBS24PUBD_WG_TEMP_UUID
    ubs24pubr_nm_inventory && [[ $UBS24PUBR_NM_STATUS == absent ]] || return 1
    ubs24pubr_kernel_inventory && [[ $UBS24PUBR_KERNEL_STATUS == absent ]] || return 1
    [[ ! -e ${UBS24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} &&
       ! -L ${UBS24GD4_TEMP_FILE:-/run/NetworkManager/system-connections/vpnks-wg.nmconnection} ]] || return 1
    route186=$(ip -j -N -4 route show table all proto 186) || return 1
    route187=$(ip -j -N -4 route show table all proto 187) || return 1
    jq -e 'type=="array" and length==0' <<< "$route186" >/dev/null 2>&1 || return 1
    jq -e 'type=="array" and length==0' <<< "$route187" >/dev/null 2>&1 || return 1

    UBS24PUBD_MARKER_KIND=$kind
    UBS24PUBD_TRANSACTION_STATE=$state
    UBS24PUBD_COMPLETED_MARKER_FILE=$file
}

ubs24pubd_finalize_completed_marker() {
    (( $# == 0 )) || return 1
    local runtime file
    runtime=$(ubs24pub_session_runtime_root) || return 1
    file=${UBS24PUBD_COMPLETED_MARKER_FILE:-}
    [[ $file == "$runtime/active" || $file == "$runtime/transaction" ]] || return 1
    [[ -d $runtime && ! -L $runtime && -f $file && ! -L $file ]] || return 1
    rm -f -- "$file" >/dev/null 2>&1 || :
    [[ ! -e $file && ! -L $file ]] || return 1
    rmdir -- "$runtime" >/dev/null 2>&1 || :
    [[ ! -e $runtime && ! -L $runtime ]]
}

ubs24pubd_acquire_existing_lock() {
    (( $# == 0 )) || return 1
    [[ -z ${UBS24GB2_FD:-} ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_runtime_shape || return 1
    local dir fd
    dir=$(ubs24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller ]] || return 1
    exec {fd}< "$dir/controller.lock" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    UBS24GB2_FD=$fd
    ubs24gb2_lock_valid || { ubs24gb2_close; return 1; }
}

# Reconstruct D4's nonsecret bound fields from its immutable intent and current
# saved WG profile.  The marker is only cross-checked; it never supplies endpoint
# or AllowedIPs authority.
ubs24pubd_load_d4_intent() {
    (( $# == 0 )) || return 1
    local d4_runtime file
    d4_runtime=$(ubs24pub_wireguard_runtime_root) || return 1
    file=$d4_runtime/intent
    local -a rows=() allowed=()
    local boot userns netns mntns endpoint underlay_spec source_part gateway_part extra allowed_raw prefix
    [[ -d $d4_runtime && ! -L $d4_runtime &&
       $(stat -c '%u:%a:%h' "$d4_runtime") == '0:700:2' &&
       -f $file && ! -L $file && $(stat -c '%u:%a:%h' "$file") == '0:400:1' ]] || return 1
    mapfile -t rows < "$file" || return 1
    (( ${#rows[@]} == 14 )) || return 1
    [[ ${rows[0]} == ubs-v240-c23ai-wireguard-intent-v1 &&
       ${rows[1]} == state=prepared-no-wireguard-mutation-yet &&
       ${rows[2]} == boot=* && ${rows[3]} == userns=* && ${rows[4]} == netns=* && ${rows[5]} == mntns=* &&
       ${rows[6]} == source_uuid=* && ${rows[7]} == source_sha=* &&
       ${rows[8]} == temp_name=* && ${rows[9]} == temp_uuid=* &&
       ${rows[10]} == wg_source=* && ${rows[11]} == endpoint=* &&
       ${rows[12]} == underlay=* && ${rows[13]} == allowedips=* ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    [[ ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" ]] || return 1

    UBS24GD4_SOURCE_UUID=${rows[6]#source_uuid=}
    UBS24GD4_SOURCE_SHA=${rows[7]#source_sha=}
    UBS24GD4_TEMP_NAME=${rows[8]#temp_name=}
    UBS24GD4_TEMP_UUID=${rows[9]#temp_uuid=}
    UBS24GD4_WG_SOURCE=${rows[10]#wg_source=}
    endpoint=${rows[11]#endpoint=}
    underlay_spec=${rows[12]#underlay=}
    allowed_raw=${rows[13]#allowedips=}
    [[ $UBS24GD4_SOURCE_UUID == "$UBS24PUBD_WG_SOURCE_UUID" &&
       $UBS24GD4_TEMP_UUID == "$UBS24PUBD_WG_TEMP_UUID" &&
       $UBS24GD4_TEMP_NAME == vpnks-wg && $UBS24GD4_SOURCE_SHA =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ $endpoint == *:* && $endpoint != *:*:* ]] || return 1
    UBS24GD4_ENDPOINT_IP=${endpoint%:*}; UBS24GD4_ENDPOINT_PORT=${endpoint##*:}
    wg23_validate_ipv4 "$UBS24GD4_WG_SOURCE" && wg23_validate_ipv4 "$UBS24GD4_ENDPOINT_IP" &&
      [[ $UBS24GD4_ENDPOINT_PORT =~ ^[0-9]+$ ]] && (( UBS24GD4_ENDPOINT_PORT >= 1 && UBS24GD4_ENDPOINT_PORT <= 65535 )) || return 1
    IFS='|' read -r UBS24GD4_UNDERLAY source_part gateway_part extra <<< "$underlay_spec"
    [[ -z ${extra:-} && $source_part == source=* && $gateway_part == gateway=* ]] || return 1
    UBS24GD4_UNDERLAY_SOURCE=${source_part#source=}; UBS24GD4_UNDERLAY_GATEWAY=${gateway_part#gateway=}
    [[ $UBS24GD4_UNDERLAY == "$UBS24PUBD_UNDERLAY" ]] && ubs24gb1_valid_ifname "$UBS24GD4_UNDERLAY" &&
      wg23_validate_ipv4 "$UBS24GD4_UNDERLAY_SOURCE" || return 1
    [[ $UBS24GD4_UNDERLAY_GATEWAY == - ]] || wg23_validate_ipv4 "$UBS24GD4_UNDERLAY_GATEWAY" || return 1
    [[ -n $allowed_raw && $allowed_raw == *';' ]] || return 1
    IFS=';' read -r -a allowed <<< "$allowed_raw"
    (( ${#allowed[@]} >= 1 )) || return 1
    UBS24GD4_ALLOWED_IPS=()
    for prefix in "${allowed[@]}"; do
        [[ -n $prefix ]] || continue
        ubs24gd3_private_ipv4_prefix "$prefix" || return 1
        UBS24GD4_ALLOWED_IPS+=("$prefix")
    done
    (( ${#UBS24GD4_ALLOWED_IPS[@]} >= 1 )) || return 1

    # Re-read the current saved source profile and require byte/hash + semantic
    # equality with the immutable D4 intent. Deliberately do NOT re-resolve the
    # source hostname here: disconnect authority is bound to the endpoint pinned
    # in the immutable live intent, and DNS rotation must not redirect teardown.
    local source_type
    source_type=$(nmcli --wait 10 -g connection.type connection show uuid "$UBS24GD4_SOURCE_UUID" 2>/dev/null) || return 1
    [[ $source_type == wireguard ]] || return 1
    ubs24gd2_find_saved_keyfile "$UBS24GD4_SOURCE_UUID" || return 1
    ubs24gd2_validate_keyfile "$UBS24GD2_KEYFILE" "$UBS24GD4_SOURCE_UUID" "$UBS24GD4_UNDERLAY" || return 1
    UBS24GD4_SOURCE_FILE=$UBS24GD2_KEYFILE
    [[ $(ubs24gd4_hash_file "$UBS24GD4_SOURCE_FILE") == "$UBS24GD4_SOURCE_SHA" ]] || return 1
    ubs24gd3_keyfile_ipv4_source "$UBS24GD4_SOURCE_FILE" || return 1
    [[ $UBS24GD3_WG_SOURCE_IP == "$UBS24GD4_WG_SOURCE" && ${#UBS24GD2_ALLOWED_IPS[@]} == ${#UBS24GD4_ALLOWED_IPS[@]} ]] || return 1
    local i
    for ((i=0; i<${#UBS24GD4_ALLOWED_IPS[@]}; i++)); do
        [[ ${UBS24GD2_ALLOWED_IPS[i]} == "${UBS24GD4_ALLOWED_IPS[i]}" ]] || return 1
    done
    UBS24GD4_RUNTIME=$d4_runtime
    UBS24GD4_TEMP_FILE=/run/NetworkManager/system-connections/vpnks-wg.nmconnection
    UBS24GD4_HOLD_PROTO=187
    UBS24GD4_HOLD_METRIC=4241
}

# Reconstruct immutable OpenVPN session identity without requiring the VPN to
# still be active. v2.4.1 uses this narrower witness only after a published
# same-boot marker has authenticated the session, so an independently vanished
# OpenVPN tunnel can be classified as a failure rather than lost ownership.
ubs24pubd_rehydrate_openvpn_identity_locked() {
    (( $# == 0 )) || return 1
    ubs24gc3_transition_records_valid && ubs24gc7_read_intent && ubs24gc15_load_bound_intent &&
      ubs24gc15_candidate_digest_valid || return 1
    [[ $UBS24GC7_SOURCE_UUID == "$UBS24PUBD_OVPN_SOURCE_UUID" &&
       $UBS24GC7_CLONE_UUID == "$UBS24PUBD_OVPN_CLONE_UUID" &&
       $UBS24GC3_IFACE == "$UBS24PUBD_UNDERLAY" ]] || return 1
    UBS24GA3_PREPARED_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GA3_PREPARED_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_SOURCE_SHA256=$UBS24GC7_SOURCE_SHA
    UBS24GA3_DERIVATIVE_SHA256=$UBS24GC7_CLONE_SHA
    UBS24GA_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_STAGE=prepared-nonsecret-parity-only
    UBS24GA3_AUTHORITY=none
    UBS24GA2_STATE=quarantined-exact-nonsecret-settings-verified
    local UBS24S_LOCK_HELD=1
    ubs24gc5_prepared_profile_witness && ubs24op_session_nm_identity &&
      [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24GC7_NM_OWNER" ]] || return 1
}

ubs24pubd_rehydrate_openvpn_locked() {
    (( $# == 0 )) || return 1
    ubs24pubd_rehydrate_openvpn_identity_locked || return 1
    UBS24GC6_NM_SNAPSHOT=$(ubs24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || return 1
    UBS24GC6_ROUTE_SNAPSHOT=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    [[ -n $UBS24GC6_NM_SNAPSHOT && -n $UBS24GC6_ROUTE_SNAPSHOT ]] || return 1
}

# Exact post-publication OpenVPN-loss observation. The clone itself must still
# be the immutable owned temporary derivative, but it must not be active and no
# OpenVPN/tun carrier may remain. A combined session may still have only its
# exact authenticated WG connection active; every other managed VPN shape is
# refused. This function is read-only.
ubs24pubd_openvpn_absent_observed() {
    (( $# == 0 )) || return 1
    ubs24pub_disconnect_admission_witness || return 1
    [[ ${UBS24PUBD_STAGE:-} == observing-openvpn-dropout ]] || return 1
    local rows line uuid type name dev foreign=0 wg_seen=0
    UBS24GC23T_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GC23T_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GC23T_NM_OWNER=$UBS24GC7_NM_OWNER
    ubs24gc23t_clone_present "$UBS24GC7_CLONE_UUID" || return 1
    rows=$(nmcli --wait 10 --colors no -t -f UUID,TYPE,NAME,DEVICE connection show --active 2>/dev/null) || return 1
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        IFS=: read -r uuid type name dev <<< "$line"
        case $type in
          vpn|tun|tap|ppp) foreign=1 ;;
          wireguard)
            if [[ ${UBS24PUBD_SESSION_MODE:-none} == combined &&
                  $uuid == "$UBS24PUBD_WG_TEMP_UUID" && $name == vpnks-wg && $dev == vpnks-wg ]]; then
                wg_seen=$((wg_seen+1))
            else
                foreign=1
            fi
            ;;
        esac
    done <<< "$rows"
    (( foreign == 0 && wg_seen <= 1 )) || return 1
    ip link show dev tun-vpnks >/dev/null 2>&1 && return 1
    if pgrep -x openvpn >/dev/null 2>&1; then return 1; fi
    return 0
}

# Adopt an already-absent OpenVPN into the ordinary C19/C23T finalization
# pipeline. We first prove exact C11, journal a truthful alternative C19 intent,
# atomically restore exact C1, prove OpenVPN is still absent, and only then mark
# the session as C1-held/finalization-pending. No NetworkManager down is issued.
ubs24pubd_adopt_openvpn_absence_to_c1() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBD_STAGE:-} == adopting-openvpn-absence ]] || return 1
    ubs24pub_disconnect_admission_witness || return 1
    [[ ! -e /run/mvc-disconnect && ! -L /run/mvc-disconnect &&
       ! -e /run/mvc-completion && ! -L /run/mvc-completion &&
       $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local scratch batch a b success=1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v241-c24a-absent.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch && $(stat -c %a -- "$scratch") == 700 ]] || return 1
    batch=$scratch/handback.nft a=$scratch/first.json b=$scratch/second.json
    if ! (umask 077; set -C; : > "$batch") ||
       ! ubs24gc19_write_c1_handback "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$batch" ||
       ! nft --check --file "$batch" >/dev/null 2>&1; then success=0; fi
    if (( success == 1 )); then
        ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" &&
          ubs24gc19_kernel_witness c11 "$a" "$b" || success=0
    fi
    if (( success == 1 )); then
        ubs24gc19_publish_absent_intent "$batch" "$UBS24PUBD_MARKER_KIND" || success=0
    fi
    if (( success == 1 )); then
        UBS24GC19_ATTEMPTED=yes
        UBS24GC19_STAGE=handback-commit-attempted-uncertain-openvpn-already-absent
        nft --file "$batch" >/dev/null 2>&1 || success=0
    fi
    if (( success == 1 )); then
        ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" &&
          ubs24gc19_kernel_witness c1 "$a" "$b" && ubs24gc19_intent_valid || success=0
    fi
    if (( success == 1 )); then
        UBS24PUBD_STAGE=observing-openvpn-dropout
        ubs24pubd_openvpn_absent_observed || success=0
        UBS24PUBD_STAGE=adopting-openvpn-absence
    fi
    rm -f -- "$batch" "$a" "$b" || success=0
    rmdir -- "$scratch" || success=0
    if (( success == 1 )); then
        UBS24GC19_NM_STOP_EXIT_STATUS=not-needed-openvpn-already-absent
        UBS24GC19_POST_STOP_OBSERVATION=verified-openvpn-already-absent
        UBS24GC19_STAGE=openvpn-stopped-c1-guard-retained-no-release-authority
        UBS24GCO_STAGE=protected-stopped-c1-held-finalize-pending
        return 0
    fi
    return 1
}

ubs24pub_disconnect_admission_witness() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBD_OPERATION:-none} == disconnect &&
       ${UBS24PUBD_APPROVAL:-none} == approved-process-local &&
       ${UBS24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]] || return 1
    case ${UBS24PUBD_STAGE:-idle} in
      reobserving-dual-active|tearing-down-wireguard|reconciling-partial-wireguard|observing-published-wireguard-dropout|reconciling-published-wireguard-dropout|reobserving-openvpn-after-wireguard|reobserving-openvpn-only|stopping-openvpn|releasing-private-holds|completing-session|observing-openvpn-dropout|reconciling-openvpn-dropout-wireguard|adopting-openvpn-absence) ;;
      *) return 1 ;;
    esac
    ubs24gb2_root_scope && ubs24gb2_lock_valid
}

ubs24gco_public_disconnect_enabled() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_MODE:-disabled} == public-live-fresh-disconnect &&
       ${UBS24GCO_AUTHORITY:-none} == public-explicit-disconnect ]] || return 1
    ubs24pub_disconnect_admission_witness
}

# Final public-process binding after C23AU.
ubs24gco_enabled() {
    (( $# == 0 )) || return 1
    ubs24gco_offline_enabled || ubs24gco_private_live_enabled ||
      ubs24gco_public_live_enabled || ubs24gco_public_disconnect_enabled
}

ubs24gd4_authority_witness() {
    (( $# == 0 )) || return 1
    local admitted=no
    if [[ ${UBS24GCU_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCU_APPROVAL:-none} == approved-process-local &&
          ${UBS24GCU_OPERATION:-none} == session &&
          ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
          ${UBS24GCO_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
          ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]]; then
        ubs24gcu_live_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24GCO_MODE:-disabled} == public-live-explicit-command &&
            ${UBS24GCO_AUTHORITY:-none} == public-explicit-connect &&
            ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
            ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]]; then
        ubs24pub_connect_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24PUBC_MODE:-none} == wireguard-protected &&
            ${UBS24PUBC_OPERATION:-none} == connect &&
            ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
            ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect &&
            ${UBS24PUBC_STAGE:-} == starting-wireguard ]]; then
        ubs24pub_connect_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24PUBC_MODE:-none} == wireguard-split &&
            ${UBS24PUBC_OPERATION:-none} == connect &&
            ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
            ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect &&
            ${UBS24PUBC_STAGE:-} == starting-wireguard-split ]]; then
        ubs24pub_connect_admission_witness && ubs24gws_lock_valid || return 1
        admitted=split
    elif [[ ${UBS24PUBD_SESSION_MODE:-none} == wireguard-split &&
            ${UBS24PUBD_OPERATION:-none} == disconnect &&
            ${UBS24PUBD_APPROVAL:-none} == approved-process-local &&
            ${UBS24PUBD_AUTHORITY:-none} == public-explicit-disconnect &&
            ( ${UBS24PUBD_STAGE:-} == reobserving-wireguard-split || ${UBS24PUBD_STAGE:-} == stopping-wireguard-split || ${UBS24PUBD_STAGE:-} == resuming-wireguard-split-runtime-retirement ) ]]; then
        ubs24gws_lock_valid || return 1
        admitted=split
    elif [[ ${UBS24GCO_MODE:-disabled} == public-live-fresh-disconnect &&
            ${UBS24GCO_AUTHORITY:-none} == public-explicit-disconnect &&
            ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
            ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]]; then
        ubs24pub_disconnect_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24GCO_MODE:-disabled} == public-live-fresh-disconnect &&
            ${UBS24GCO_AUTHORITY:-none} == public-explicit-disconnect &&
            ${UBS24GCO_STAGE:-} == protected-openvpn-absent-reconciliation &&
            ${UBS24PUBD_STAGE:-} == reconciling-openvpn-dropout-wireguard ]]; then
        ubs24pub_disconnect_admission_witness || return 1
        admitted=yes
    fi
    [[ $admitted == yes || $admitted == split ]] || return 1
    if [[ $admitted == split ]]; then
        ubs24gb2_root_scope && ubs24gws_lock_valid
    else
        ubs24gb2_root_scope && ubs24gb2_lock_valid
    fi
}

# Public equivalent of the private-only post-OpenVPN D4 cleanup witness.
ubs24gd4_post_openvpn_cleanup_witness() {
    (( $# == 0 )) || return 1
    if [[ ${UBS24GCU_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCU_APPROVAL:-none} == approved-process-local &&
          ${UBS24GCU_OPERATION:-none} == session &&
          ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
          ${UBS24GCO_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
          ${UBS24GCU_STAGE:-} == stopped-c1-held &&
          ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority ]]; then
        ubs24gb2_root_scope && ubs24gb2_lock_valid && ubs24gb4_no_active_vpn
        return
    fi
    if [[ ${UBS24GCO_MODE:-disabled} == public-live-fresh-disconnect &&
          ${UBS24GCO_AUTHORITY:-none} == public-explicit-disconnect &&
          ${UBS24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
          ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority &&
          ${UBS24PUBD_STAGE:-} == releasing-private-holds ]]; then
        ubs24pub_disconnect_admission_witness && ubs24gb4_no_active_vpn
        return
    fi
    [[ ${UBS24GCO_MODE:-disabled} == public-live-explicit-command &&
       ${UBS24GCO_AUTHORITY:-none} == public-explicit-connect &&
       ${UBS24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
       ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority &&
       ${UBS24PUBC_STAGE:-} == cleanup-releasing-private-holds ]] || return 1
    ubs24pub_connect_admission_witness && ubs24gb4_no_active_vpn
}

ubs24pubd_reobserve_openvpn_after_wg() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GD4_STAGE:-} == wireguard-residue-removed-openvpn-protected-private-hold ]] || return 1
    # Reconcile the exact C13/C11 journal and current OpenVPN state after D4 has
    # restored the pure OpenVPN guard. Proto-187 holds are routing state only.
    ubs24gc15_reconcile_locked || return 1
    [[ ${UBS24GC15_STAGE:-} == c13-intent-present-tunnel-output-policy-reobserved-dns-unverified ]] || return 1
    UBS24GC7_STAGE=active-nm-and-ipv4-observed-bootstrap-only
    UBS24GC7_AUTHORITY=none
    UBS24GC9_STAGE=active-nm-ipv4-observed-endpoint-only-guard
    UBS24GC9_AUTHORITY=none
    UBS24GC13_STAGE=atomic-ipv4-tunnel-output-observed-dns-unverified
    UBS24GC13_AUTHORITY=none
    UBS24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
    UBS24GC17_AUTHORITY=none
    # Refresh C6 snapshots from the now-pure OpenVPN state, then use C16's
    # existing bounded DNS observer. It rechecks C13 exact policy itself.
    UBS24GC6_NM_SNAPSHOT=$(ubs24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || return 1
    UBS24GC6_ROUTE_SNAPSHOT=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    ubs24gc16_observe_locked || return 1
    [[ ${UBS24GC16_AUTHORITY:-} == none &&
       ( ${UBS24GC16_STAGE:-} == direct-glibc-vpn-dns-observed-no-traffic-authority ||
         ${UBS24GC16_STAGE:-} == conditional-arch-nss-vpn-dns-observed-no-traffic-authority ) ]]
}

ubs24pubd_reobserve_openvpn_only() {
    (( $# == 0 )) || return 1
    ubs24gc15_reconcile_locked || return 1
    [[ ${UBS24GC15_STAGE:-} == c13-intent-present-tunnel-output-policy-reobserved-dns-unverified ]] || return 1
    UBS24GC7_STAGE=active-nm-and-ipv4-observed-bootstrap-only
    UBS24GC7_AUTHORITY=none
    UBS24GC9_STAGE=active-nm-ipv4-observed-endpoint-only-guard
    UBS24GC9_AUTHORITY=none
    UBS24GC13_STAGE=atomic-ipv4-tunnel-output-observed-dns-unverified
    UBS24GC13_AUTHORITY=none
    UBS24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
    UBS24GC17_AUTHORITY=none
    UBS24GC6_NM_SNAPSHOT=$(ubs24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || return 1
    UBS24GC6_ROUTE_SNAPSHOT=$(ubs24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    ubs24gc16_observe_locked || return 1
    [[ ${UBS24GC16_AUTHORITY:-} == none &&
       ( ${UBS24GC16_STAGE:-} == direct-glibc-vpn-dns-observed-no-traffic-authority ||
         ${UBS24GC16_STAGE:-} == conditional-arch-nss-vpn-dns-observed-no-traffic-authority ) ]]
}

ubs24pubd_finalize_transaction() {
    (( $# == 0 )) || return 1
    local runtime
    runtime=$(ubs24pub_session_runtime_root) || return 1
    [[ ${UBS24GCO_STAGE:-} == completed-session-archived-sameboot-ready &&
       -d $runtime && ! -L $runtime && -f $runtime/transaction && ! -L $runtime/transaction ]] || return 1
    rm -f -- "$runtime/transaction" >/dev/null 2>&1 || :
    [[ ! -e $runtime/transaction && ! -L $runtime/transaction ]] || return 1
    rmdir -- "$runtime" >/dev/null 2>&1 || :
    [[ ! -e $runtime && ! -L $runtime ]]
}

ubs24pubd_finalize_prepared_transaction_if_clean() {
    (( $# == 0 )) || return 1
    local runtime p
    runtime=$(ubs24pub_session_runtime_root) || return 1
    [[ ${UBS24PUBD_TRANSACTION_STATE:-} == prepared-before-mutation &&
       -d $runtime && ! -L $runtime && -f $runtime/transaction && ! -L $runtime/transaction ]] || return 1
    for p in /run/mvc-controller /run/mvc-activation /run/mvc-output-transition \
             /run/mvc-disconnect /run/mvc-completion /run/mvc-wireguard; do
        [[ ! -e $p && ! -L $p ]] || return 1
    done
    rm -f -- "$runtime/transaction" || return 1
    rmdir -- "$runtime" || return 1
}

ubs24pubd_finalize_marker() {
    (( $# == 0 )) || return 1
    local runtime
    runtime=$(ubs24pub_session_runtime_root) || return 1
    [[ ${UBS24GCO_STAGE:-} == completed-session-archived-sameboot-ready &&
       ${UBS24GD4_STAGE:-} == wireguard-teardown-complete-openvpn-stopped-no-private-hold &&
       -d $runtime && ! -L $runtime && -f $runtime/active && ! -L $runtime/active ]] || return 1
    rm -f -- "$runtime/active" >/dev/null 2>&1 || :
    [[ ! -e $runtime/active && ! -L $runtime/active ]] || return 1
    rmdir -- "$runtime" >/dev/null 2>&1 || :
    [[ ! -e $runtime && ! -L $runtime ]]
}

ubs24pubd_consume_authority() {
    UBS24PUBD_APPROVAL=consumed
    UBS24PUBD_AUTHORITY=none
    [[ ${UBS24GCO_MODE:-} == public-live-fresh-disconnect ]] && UBS24GCO_AUTHORITY=none
}

ubs24pubd_disconnect_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBD_ATTEMPTED:-no} == no ]] || return 1
    UBS24PUBD_ATTEMPTED=yes
    UBS24PUBD_OPERATION=disconnect
    UBS24PUBD_STAGE=authenticating-durable-session
    if ! ubs24pubd_parse_session_marker; then
        if ubs24pubd_parse_completed_session_marker; then
            UBS24PUBD_STAGE=retiring-completed-public-marker
            if ubs24pubd_finalize_completed_marker; then
                UBS24PUBD_STAGE=public-completed-session-marker-retired-sameboot-ready
                return 0
            fi
            UBS24PUBD_STAGE=completed-public-marker-retirement-refused
            return 1
        fi
        if ubs24pub_baseline_clean_readonly; then
            UBS24PUBD_STAGE=already-clean-baseline
            return 0
        fi
        UBS24PUBD_STAGE=durable-session-authentication-refused
        return 1
    fi

    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
          ${UBS24PUBD_TRANSACTION_STATE:-none} == prepared-before-mutation ]]; then
        if [[ ${UBS24PUBD_SESSION_MODE:-none} == wireguard-protected ]]; then
            if ubs24pubd_finalize_prepared_transaction_if_clean; then
                UBS24PUBD_STAGE=public-wireguard-protected-prepared-clean-no-mutation
                return 0
            fi
            # Stage 2 deliberately keeps ambiguous/partial standalone-WG start
            # recovery in the packaged recovery tools. The prepared marker is
            # still useful ownership evidence, but this public disconnect does
            # not infer destructive authority from it.
            UBS24PUBD_STAGE=wireguard-protected-partial-start-recovery-required
            return 1
        fi
        if [[ -f $(ubs24pube_preclone_retire_intent_path) && ! -L $(ubs24pube_preclone_retire_intent_path) ]]; then
            UBS24PUBD_APPROVAL=approved-process-local
            UBS24PUBD_AUTHORITY=public-explicit-disconnect
            UBS24PUBD_STAGE=resuming-pre-c7-runtime-retirement
            if ubs24pube_preclone_retire_archive_continue; then
                UBS24PUBD_STAGE=public-pre-c7-openvpn-start-clean-baseline-restored
                UBS24PUBD_APPROVAL=consumed
                UBS24PUBD_AUTHORITY=none
                return 0
            fi
            UBS24PUBD_STAGE=pre-c7-runtime-retirement-refused
            UBS24PUBD_APPROVAL=consumed
            UBS24PUBD_AUTHORITY=none
            return 1
        fi
        if [[ -f $(ubs24pube_retire_intent_path) && ! -L $(ubs24pube_retire_intent_path) ]]; then
            UBS24PUBD_APPROVAL=approved-process-local
            UBS24PUBD_AUTHORITY=public-explicit-disconnect
            UBS24PUBD_STAGE=resuming-incomplete-openvpn-runtime-retirement
            if ubs24pube_retire_archive_continue; then
                UBS24PUBD_STAGE=public-incomplete-openvpn-start-clean-baseline-restored
                UBS24PUBD_APPROVAL=consumed
                UBS24PUBD_AUTHORITY=none
                return 0
            fi
            UBS24PUBD_STAGE=incomplete-openvpn-runtime-retirement-refused
            UBS24PUBD_APPROVAL=consumed
            UBS24PUBD_AUTHORITY=none
            return 1
        fi
        if ubs24pubd_finalize_prepared_transaction_if_clean; then
            UBS24PUBD_STAGE=public-partial-session-clean-no-mutation
            return 0
        fi
        if ! ubs24pubd_acquire_existing_lock; then
            UBS24PUBD_STAGE=prepared-transaction-live-state-lock-refused
            return 1
        fi
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        if ubs24pube_preclone_intent_present && ! ubs24pube_c7_intent_present; then
            UBS24PUBD_STAGE=reconciling-pre-c7-openvpn-start
            if ubs24pube_reconcile_pre_c7_locked; then
                UBS24PUBD_STAGE=public-pre-c7-openvpn-start-clean-baseline-restored
                UBS24PUBD_APPROVAL=consumed
                UBS24PUBD_AUTHORITY=none
                return 0
            fi
            UBS24PUBD_STAGE=pre-c7-openvpn-start-reconciliation-refused
        else
            UBS24PUBD_STAGE=reconciling-incomplete-openvpn-start
            if ubs24pube_reconcile_incomplete_start_locked; then
                UBS24PUBD_STAGE=public-incomplete-openvpn-start-clean-baseline-restored
                UBS24PUBD_APPROVAL=consumed
                UBS24PUBD_AUTHORITY=none
                return 0
            fi
            UBS24PUBD_STAGE=incomplete-openvpn-start-reconciliation-refused
        fi
        UBS24PUBD_APPROVAL=consumed
        UBS24PUBD_AUTHORITY=none
        ubs24gb2_close >/dev/null 2>&1 || true
        return 1
    fi

    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
          ${UBS24PUBD_TRANSACTION_STATE:-none} == wireguard-split-prepared &&
          ${UBS24PUBD_SESSION_MODE:-none} == wireguard-split ]]; then
        if ! ubs24gws_lock_reopen; then
            UBS24PUBD_STAGE=wireguard-split-prepared-lock-refused
            return 1
        fi
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        UBS24PUBD_STAGE=reobserving-wireguard-split-prepared
        if ubs24gws_prepared_clean_observed; then
            if ! ubs24gws_retire_prepared_once; then
                UBS24PUBD_STAGE=wireguard-split-prepared-retirement-refused
                ubs24pubd_consume_authority
                ubs24gws_lock_close
                return 1
            fi
            UBS24PUBD_STAGE=public-wireguard-split-prepared-clean-no-mutation
            ubs24pubd_consume_authority
            return 0
        fi
        if [[ -e $(ubs24pub_wireguard_runtime_root) || -L $(ubs24pub_wireguard_runtime_root) ]] &&
           ubs24pubd_load_d4_intent && ubs24gws_network_clean_retirement_pending_observed; then
            UBS24PUBD_STAGE=resuming-wireguard-split-runtime-retirement
            if ubs24gws_retire_runtime_once; then
                UBS24PUBD_STAGE=public-wireguard-split-session-complete-sameboot-ready
                ubs24pubd_consume_authority
                return 0
            fi
            UBS24PUBD_STAGE=wireguard-split-runtime-retirement-resume-refused
            ubs24pubd_consume_authority
            ubs24gws_lock_close
            return 1
        fi
        UBS24PUBD_STAGE=wireguard-split-partial-start-recovery-required
        ubs24pubd_consume_authority
        ubs24gws_lock_close
        return 1
    fi

    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
          ${UBS24PUBD_TRANSACTION_STATE:-none} == wireguard-split &&
          ${UBS24PUBD_SESSION_MODE:-none} == wireguard-split ]]; then
        if ! ubs24gws_lock_reopen; then
            UBS24PUBD_STAGE=wireguard-split-lock-refused
            return 1
        fi
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        UBS24PUBD_STAGE=reconstructing-wireguard-split
        if ! ubs24pubd_load_d4_intent; then
            UBS24PUBD_STAGE=wireguard-split-reconstruction-refused
            ubs24pubd_consume_authority
            ubs24gws_lock_close
            return 1
        fi
        UBS24GD4_ATTEMPTED=yes
        UBS24GWS_ATTEMPTED=yes
        UBS24PUBD_STAGE=reobserving-wireguard-split
        if ubs24gws_active_observed; then
            UBS24GWS_STAGE=wireguard-only-split-running
            UBS24PUBD_STAGE=stopping-wireguard-split
            if ! ubs24gws_stop_once; then
                UBS24PUBD_STAGE="wireguard-split-stop-failed-${UBS24GWS_STAGE:-unknown}"
                ubs24pubd_consume_authority
                ubs24gws_lock_close
                return 1
            fi
        elif ubs24gws_network_clean_retirement_pending_observed; then
            UBS24GWS_STAGE=wireguard-residue-removed-runtime-retirement-pending
            UBS24PUBD_STAGE=resuming-wireguard-split-runtime-retirement
            if ! ubs24gws_retire_runtime_once; then
                UBS24PUBD_STAGE=wireguard-split-runtime-retirement-resume-refused
                ubs24pubd_consume_authority
                ubs24gws_lock_close
                return 1
            fi
        else
            UBS24PUBD_STAGE=wireguard-split-reobservation-refused
            ubs24pubd_consume_authority
            ubs24gws_lock_close
            return 1
        fi
        UBS24PUBD_STAGE=public-wireguard-split-session-complete-sameboot-ready
        ubs24pubd_consume_authority
        return 0
    fi

    if ! ubs24pubd_acquire_existing_lock; then
        UBS24PUBD_STAGE=durable-session-lock-refused
        return 1
    fi

    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
          ${UBS24PUBD_TRANSACTION_STATE:-none} == wireguard-protected &&
          ${UBS24PUBD_SESSION_MODE:-none} == wireguard-protected ]]; then
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        UBS24PUBD_STAGE=reconstructing-wireguard-protected
        if ! ubs24pubd_load_d4_intent; then
            UBS24PUBD_STAGE=wireguard-protected-reconstruction-refused
            ubs24pubd_consume_authority
            ubs24gb2_close
            return 1
        fi
        UBS24GD4_ATTEMPTED=yes
        UBS24GWG_ATTEMPTED=yes
        UBS24PUBD_STAGE=reobserving-wireguard-protected
        if ubs24gwg_active_observed; then
            UBS24GWG_STAGE=wireguard-only-protected-running
            UBS24PUBD_STAGE=stopping-wireguard-protected
            if ! ubs24gwg_stop_once; then
                UBS24PUBD_STAGE="wireguard-protected-stop-failed-${UBS24GWG_STAGE:-unknown}"
                ubs24pubd_consume_authority
                return 1
            fi
        elif ubs24gwg_network_clean_retirement_pending_observed; then
            # C23BK: a prior disconnect may already have removed WG, its
            # endpoint route/profile and the standalone guard, then failed only
            # while retiring authenticated same-boot runtime state. Resume only
            # from that exact network-clean observation; never infer cleanup
            # authority from missing WG alone.
            UBS24GWG_STAGE=guard-released-runtime-retirement-pending
            UBS24PUBD_STAGE=resuming-wireguard-protected-runtime-retirement
            if ! ubs24gwg_retire_runtime_once; then
                UBS24PUBD_STAGE=wireguard-protected-runtime-retirement-resume-refused
                ubs24pubd_consume_authority
                return 1
            fi
        else
            UBS24PUBD_STAGE=wireguard-protected-reobservation-refused
            ubs24pubd_consume_authority
            ubs24gb2_close
            return 1
        fi
        UBS24PUBD_STAGE=public-wireguard-protected-session-complete-sameboot-ready
        ubs24pubd_consume_authority
        return 0
    fi

    local openvpn_dropout=no
    if ! ubs24pubd_rehydrate_openvpn_locked; then
        # v2.4.1 C24A: full live rehydration can fail legitimately after an
        # underlay outage has independently removed OpenVPN. Never infer that
        # from absence alone: reconstruct immutable identity first, establish
        # explicit public-disconnect authority, then require the exact read-only
        # OpenVPN-absent observation before any mutation is admitted.
        if ! ubs24pubd_rehydrate_openvpn_identity_locked; then
            UBS24PUBD_STAGE=active-session-reconstruction-refused
            ubs24gb2_close
            return 1
        fi
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        UBS24GCO_MODE=public-live-fresh-disconnect
        UBS24GCO_AUTHORITY=public-explicit-disconnect
        UBS24GCO_ATTEMPTED=yes
        UBS24GCO_STAGE=protected-openvpn-absent-reconciliation
        UBS24PUBD_STAGE=observing-openvpn-dropout
        if ! ubs24pubd_openvpn_absent_observed; then
            UBS24PUBD_STAGE=active-session-reconstruction-refused
            ubs24pubd_consume_authority
            ubs24gb2_close
            return 1
        fi
        openvpn_dropout=yes
    else
        UBS24PUBD_APPROVAL=approved-process-local
        UBS24PUBD_AUTHORITY=public-explicit-disconnect
        UBS24GCO_MODE=public-live-fresh-disconnect
        UBS24GCO_AUTHORITY=public-explicit-disconnect
        UBS24GCO_ATTEMPTED=yes
        UBS24GCO_STAGE=protected-openvpn-observed
        UBS24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
        UBS24GC17_AUTHORITY=none
    fi

    if [[ $openvpn_dropout == yes ]]; then
        # Only already-published/protected OpenVPN-bearing states are eligible.
        # Prepared states and standalone WireGuard modes were handled earlier.
        if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction ]]; then
            case ${UBS24PUBD_TRANSACTION_STATE:-none} in
              openvpn-protected|dual-active-observed) ;;
              *)
                UBS24PUBD_STAGE=unsupported-openvpn-dropout-transaction-state
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
                ;;
            esac
        else
            [[ ${UBS24PUBD_MARKER_KIND:-none} == active && ${UBS24PUBD_SESSION_MODE:-none} == combined ]] || {
                UBS24PUBD_STAGE=unsupported-openvpn-dropout-marker
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
            }
        fi

        # If this session ever acquired D4/WG state, reconcile that exact
        # authenticated survivor to C11 + private holds before adopting the
        # already-absent OpenVPN into C1. This covers the 2026-11-06 incident,
        # including the observed case where proto-186 was already absent.
        if [[ ${UBS24PUBD_MARKER_KIND:-none} == active ||
              ${UBS24PUBD_TRANSACTION_STATE:-none} == dual-active-observed ||
              -e $(ubs24pub_wireguard_runtime_root) || -L $(ubs24pub_wireguard_runtime_root) ]]; then
            UBS24PUBD_STAGE=reconciling-openvpn-dropout-wireguard
            if ! ubs24pubd_load_d4_intent || ! ubs24pubr_reconcile_d4_to_c11_hold_openvpn_absent; then
                UBS24PUBD_STAGE=openvpn-dropout-wireguard-reconciliation-refused
                ubs24pubd_consume_authority
                return 1
            fi
        fi

        UBS24PUBD_STAGE=adopting-openvpn-absence
        if ! ubs24pubd_adopt_openvpn_absence_to_c1; then
            UBS24PUBD_STAGE=openvpn-dropout-c1-adoption-refused
            ubs24pubd_consume_authority
            return 1
        fi

        if [[ ${UBS24GD4_STAGE:-} == wireguard-residue-removed-openvpn-absent-c11-private-hold ]]; then
            UBS24PUBD_STAGE=releasing-private-holds
            if ! ubs24gd4_release_private_hold_after_openvpn_stop; then
                UBS24PUBD_STAGE="private-hold-release-failed-${UBS24GD4_STAGE:-unknown}"
                ubs24pubd_consume_authority
                return 1
            fi
        fi

        UBS24PUBD_STAGE=completing-session
        if ! ubs24gco_complete_once; then
            UBS24PUBD_STAGE="session-completion-failed-${UBS24GC23T_STAGE:-unknown}"
            ubs24pubd_consume_authority
            return 1
        fi
        if [[ ${UBS24PUBD_MARKER_KIND:-none} == active ]]; then
            if ! ubs24pubd_finalize_marker; then
                UBS24PUBD_STAGE=public-session-marker-finalize-failed
                ubs24pubd_consume_authority
                return 1
            fi
        else
            if ! ubs24pubd_finalize_transaction; then
                UBS24PUBD_STAGE=public-transaction-marker-finalize-failed
                ubs24pubd_consume_authority
                return 1
            fi
        fi
        if [[ ${UBS24PUBD_SESSION_MODE:-none} == combined ]]; then
            UBS24PUBD_STAGE=public-dual-session-complete-sameboot-ready
        else
            UBS24PUBD_STAGE=public-openvpn-session-complete-sameboot-ready
        fi
        ubs24pubd_consume_authority
        return 0
    fi

    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
          ${UBS24PUBD_TRANSACTION_STATE:-none} == openvpn-protected ]]; then
        if [[ -e $(ubs24pub_wireguard_runtime_root) || -L $(ubs24pub_wireguard_runtime_root) ]]; then
            [[ -d $(ubs24pub_wireguard_runtime_root) && ! -L $(ubs24pub_wireguard_runtime_root) ]] || {
                UBS24PUBD_STAGE=partial-wireguard-runtime-shape-refused
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
            }
            UBS24PUBD_STAGE=reconciling-partial-wireguard
            if ! ubs24pubd_load_d4_intent || ! ubs24pubr_reconcile_partial_d4_to_openvpn_hold; then
                UBS24PUBD_STAGE=partial-wireguard-reconciliation-refused
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
            fi
            UBS24PUBD_STAGE=reobserving-openvpn-after-wireguard
            if ! ubs24pubd_reobserve_openvpn_after_wg; then
                UBS24PUBD_STAGE=openvpn-post-partial-wireguard-reobservation-refused
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
            fi
        else
            UBS24PUBD_STAGE=reobserving-openvpn-only
            if ! ubs24pubd_reobserve_openvpn_only; then
                UBS24PUBD_STAGE=openvpn-only-reobservation-refused
                ubs24pubd_consume_authority
                ubs24gb2_close
                return 1
            fi
        fi
        UBS24PUBD_STAGE=stopping-openvpn
        if ! ubs24gco_stop_once; then
            UBS24PUBD_STAGE="openvpn-stop-failed-${UBS24GC19_STAGE:-unknown}"
            ubs24pubd_consume_authority
            return 1
        fi
        if [[ ${UBS24GD4_STAGE:-} == wireguard-residue-removed-openvpn-protected-private-hold ]]; then
            UBS24PUBD_STAGE=releasing-private-holds
            if ! ubs24gd4_release_private_hold_after_openvpn_stop; then
                UBS24PUBD_STAGE="private-hold-release-failed-${UBS24GD4_STAGE:-unknown}"
                ubs24pubd_consume_authority
                return 1
            fi
        fi
        UBS24PUBD_STAGE=completing-session
        if ! ubs24gco_complete_once; then
            UBS24PUBD_STAGE="session-completion-failed-${UBS24GC23T_STAGE:-unknown}"
            ubs24pubd_consume_authority
            return 1
        fi
        if ! ubs24pubd_finalize_transaction; then
            UBS24PUBD_STAGE=public-transaction-marker-finalize-failed
            ubs24pubd_consume_authority
            return 1
        fi
        if [[ ${UBS24PUBD_SESSION_MODE:-none} == openvpn-only ]]; then
            UBS24PUBD_STAGE=public-openvpn-session-complete-sameboot-ready
        else
            UBS24PUBD_STAGE=public-openvpn-partial-session-complete-sameboot-ready
        fi
        ubs24pubd_consume_authority
        return 0
    fi

    # Active marker and dual-active-observed transaction use the same proven
    # dual teardown. The latter covers failure after D4 succeeded but before
    # final active-marker publication.
    if [[ ${UBS24PUBD_MARKER_KIND:-none} == transaction ]]; then
        [[ ${UBS24PUBD_TRANSACTION_STATE:-none} == dual-active-observed ]] || {
            UBS24PUBD_STAGE=unsupported-transaction-state
            ubs24pubd_consume_authority
            ubs24gb2_close
            return 1
        }
    fi
    if ! ubs24pubd_load_d4_intent; then
        UBS24PUBD_STAGE=active-session-wireguard-reconstruction-refused
        ubs24pubd_consume_authority
        ubs24gb2_close
        return 1
    fi
    UBS24GD4_ATTEMPTED=yes
    UBS24GD4_STAGE=parallel-wireguard-openvpn-protected-running
    UBS24PUBD_STAGE=reobserving-dual-active
    if ubs24gd4_dual_active_observed && ubs24gd4_private_hold_routes_state absent; then
        UBS24PUBD_STAGE=tearing-down-wireguard
        if ! ubs24gd4_stop_once || [[ ${UBS24GD4_STAGE:-} != wireguard-residue-removed-openvpn-protected-private-hold ]]; then
            UBS24PUBD_STAGE="wireguard-stop-failed-${UBS24GD4_STAGE:-unknown}"
            ubs24pubd_consume_authority
            return 1
        fi
    else
        # v2.4.1 C24A Stage 2: the inverse published dropout.  OpenVPN was
        # already rehydrated and observed healthy above, so admit only the exact
        # case where the authenticated WG side is now down/absent under the
        # unchanged parallel guard.  Any other dual-shape mismatch remains a
        # refusal rather than being generalized into cleanup authority.
        UBS24PUBD_STAGE=observing-published-wireguard-dropout
        if ! ubs24pubr_published_wg_absent_observed; then
            UBS24PUBD_STAGE=dual-active-reobservation-refused
            ubs24pubd_consume_authority
            ubs24gb2_close
            return 1
        fi
        UBS24PUBD_STAGE=reconciling-published-wireguard-dropout
        if ! ubs24pubr_reconcile_published_wg_absent_to_openvpn_hold; then
            UBS24PUBD_STAGE=published-wireguard-dropout-reconciliation-refused
            ubs24pubd_consume_authority
            return 1
        fi
    fi

    UBS24PUBD_STAGE=reobserving-openvpn-after-wireguard
    if ! ubs24pubd_reobserve_openvpn_after_wg; then
        UBS24PUBD_STAGE=openvpn-post-wireguard-reobservation-refused
        ubs24pubd_consume_authority
        return 1
    fi

    UBS24PUBD_STAGE=stopping-openvpn
    if ! ubs24gco_stop_once; then
        UBS24PUBD_STAGE="openvpn-stop-failed-${UBS24GC19_STAGE:-unknown}"
        ubs24pubd_consume_authority
        return 1
    fi

    UBS24PUBD_STAGE=releasing-private-holds
    if ! ubs24gd4_release_private_hold_after_openvpn_stop; then
        UBS24PUBD_STAGE="private-hold-release-failed-${UBS24GD4_STAGE:-unknown}"
        ubs24pubd_consume_authority
        return 1
    fi

    UBS24PUBD_STAGE=completing-session
    if ! ubs24gco_complete_once; then
        UBS24PUBD_STAGE="session-completion-failed-${UBS24GC23T_STAGE:-unknown}"
        ubs24pubd_consume_authority
        return 1
    fi
    if [[ ${UBS24PUBD_MARKER_KIND:-none} == active ]]; then
        if ! ubs24pubd_finalize_marker; then
            UBS24PUBD_STAGE=public-session-marker-finalize-failed
            ubs24pubd_consume_authority
            return 1
        fi
    else
        if ! ubs24pubd_finalize_transaction; then
            UBS24PUBD_STAGE=public-transaction-marker-finalize-failed
            ubs24pubd_consume_authority
            return 1
        fi
    fi
    UBS24PUBD_STAGE=public-dual-session-complete-sameboot-ready
    ubs24pubd_consume_authority
    return 0
}

ubs24pubd_authorize_dispatch_live() { return 1; }
ubs24pubd_authorize_automatic_retry() { return 1; }

ubs24pubd_reset
