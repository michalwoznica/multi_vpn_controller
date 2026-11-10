#!/usr/bin/env bash
# C23BE + C23BF Stage 6 — public-v2.4 CONNECT coordinator with durable partial-session reconciliation.
# Stage 6 hardens late transaction/active publication ambiguity without changing the frozen core.
#
# Loaded by the narrow public production composition. The dispatcher admits
# only explicitly implemented public coordinators; standalone WG split remains gated.
#
# C23AR's private files are not modified. This module adds a public-only
# authority mode by overriding the final composition admission selector and D4
# authority witness *after* the physically proven definitions are loaded.

mvc24pubc_reset() {
    UBS24PUBC_ATTEMPTED=no
    UBS24PUBC_STAGE=idle
    UBS24PUBC_OPERATION=none
    UBS24PUBC_MODE=none
    UBS24PUBC_APPROVAL=none
    UBS24PUBC_AUTHORITY=none
    UBS24PUBC_WG_NAME=
    UBS24PUBC_OVPN_NAME=
    UBS24PUBC_WG_UUID=
    UBS24PUBC_OVPN_UUID=
    UBS24PUBC_UNDERLAY=
    UBS24PUBC_NM_OWNER=
    UBS24PUBC_SOURCE_FILE=
    UBS24PUBC_SOURCE_SHA=
    UBS24PUBC_WG_SOURCE=
    UBS24PUBC_TEMP_UUID=
    UBS24PUBC_TRANSACTION_STATE=none
    UBS24PUBC_ACTIVE_MARKER_PUBLISHED_THIS_PROCESS=no
    UBS24PUBC_PRECLONE_NAME=
}

mvc24pubc_runtime_absent() {
    (( $# == 0 )) || return 1
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    [[ $runtime == /* && ! -e $runtime && ! -L $runtime ]]
}

mvc24pubc_fixed_live_roots_absent() {
    (( $# == 0 )) || return 1
    local p
    for p in /run/mvc-controller /run/mvc-activation \
             /run/mvc-output-transition /run/mvc-disconnect \
             /run/mvc-completion /run/mvc-wireguard; do
        [[ ! -e $p && ! -L $p ]] || return 1
    done
    mvc24pubc_runtime_absent
}

mvc24pubc_hash_file() {
    (( $# == 1 )) || return 1
    local file=$1 hash tail
    [[ -f $file && ! -L $file ]] || return 1
    read -r hash tail < <(sha256sum -- "$file") || return 1
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

mvc24pubc_preflight_readonly() {
    (( $# == 2 )) || return 1
    local wg_name=$1 ovpn_name=$2 prefix source_sha temp_uuid
    UBS24PUBC_MODE=combined
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    UBS24PUBC_STAGE=preflight-fixed-live-roots
    mvc24pubc_fixed_live_roots_absent || return 1

    UBS24PUBC_STAGE=preflight-profile-identities
    mvc24pub_bind_combined_names "$wg_name" "$ovpn_name" || return 1

    UBS24PUBC_STAGE=preflight-openvpn
    mvc24gc4_preflight "$UBS24PUB_OVPN_UUID" || return 1
    [[ ${UBS24GC4_PREFLIGHT_STAGE:-} == ready && -n ${UBS24GC4_IFACE:-} && -n ${UBS24GC4_NM_OWNER:-} ]] || return 1

    UBS24PUBC_STAGE=preflight-wireguard
    mvc24gd2_assess_saved_profile "$UBS24PUB_WG_UUID" "$UBS24GC4_IFACE" || return 1
    (( ${UBS24GD2_PEER_COUNT:-0} == 1 && ${#UBS24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    mvc24gd3_keyfile_ipv4_source "$UBS24GD2_KEYFILE" || return 1
    for prefix in "${UBS24GD2_ALLOWED_IPS[@]}"; do
        mvc24gd3_private_ipv4_prefix "$prefix" || return 1
    done

    UBS24PUBC_STAGE=preflight-controller-route-owners
    [[ -z $(ip -4 route show table all proto 186) &&
       -z $(ip -4 route show table all proto 187) ]] || return 1

    source_sha=$(mvc24gd4_hash_file "$UBS24GD2_KEYFILE") || return 1
    temp_uuid=$(cat /proc/sys/kernel/random/uuid) || return 1
    mvc24_valid_uuid "$temp_uuid" || return 1

    UBS24PUBC_WG_NAME=$wg_name
    UBS24PUBC_OVPN_NAME=$ovpn_name
    UBS24PUBC_WG_UUID=$UBS24PUB_WG_UUID
    UBS24PUBC_OVPN_UUID=$UBS24PUB_OVPN_UUID
    UBS24PUBC_UNDERLAY=$UBS24GC4_IFACE
    UBS24PUBC_NM_OWNER=$UBS24GC4_NM_OWNER
    UBS24PUBC_SOURCE_FILE=$UBS24GD2_KEYFILE
    UBS24PUBC_SOURCE_SHA=$source_sha
    UBS24PUBC_WG_SOURCE=$UBS24GD3_WG_SOURCE_IP
    UBS24PUBC_TEMP_UUID=$temp_uuid

    mvc24gd4_prepare_from_preflight \
      "$UBS24PUBC_WG_UUID" "$UBS24PUBC_SOURCE_FILE" "$UBS24PUBC_SOURCE_SHA" \
      "$UBS24PUBC_WG_SOURCE" "$UBS24PUBC_UNDERLAY" "$UBS24GD2_UNDERLAY_SOURCE" \
      "$UBS24GD2_UNDERLAY_GATEWAY" "$UBS24PUBC_TEMP_UUID" || return 1

    # Recheck that no live root appeared during the read-only preflight.
    mvc24pubc_fixed_live_roots_absent || return 1
    UBS24PUBC_STAGE=fresh-public-dual-connect-readonly-eligible
}

mvc24pubc_preflight_openvpn_readonly() {
    (( $# == 1 )) || return 1
    local ovpn_name=$1
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    UBS24PUBC_MODE=openvpn-only
    UBS24PUBC_STAGE=preflight-fixed-live-roots
    mvc24pubc_fixed_live_roots_absent || return 1

    UBS24PUBC_STAGE=preflight-openvpn-profile-identity
    mvc24pub_bind_openvpn_name "$ovpn_name" || return 1

    UBS24PUBC_STAGE=preflight-openvpn
    mvc24gc4_preflight "$UBS24PUB_OVPN_UUID" || return 1
    [[ ${UBS24GC4_PREFLIGHT_STAGE:-} == ready && -n ${UBS24GC4_IFACE:-} && -n ${UBS24GC4_NM_OWNER:-} ]] || return 1

    UBS24PUBC_STAGE=preflight-controller-route-owners
    [[ -z $(ip -4 route show table all proto 186) &&
       -z $(ip -4 route show table all proto 187) ]] || return 1

    UBS24PUBC_WG_NAME=-
    UBS24PUBC_OVPN_NAME=$ovpn_name
    UBS24PUBC_WG_UUID=-
    UBS24PUBC_OVPN_UUID=$UBS24PUB_OVPN_UUID
    UBS24PUBC_UNDERLAY=$UBS24GC4_IFACE
    UBS24PUBC_NM_OWNER=$UBS24GC4_NM_OWNER
    UBS24PUBC_SOURCE_FILE=
    UBS24PUBC_SOURCE_SHA=
    UBS24PUBC_WG_SOURCE=
    UBS24PUBC_TEMP_UUID=-

    mvc24pubc_fixed_live_roots_absent || return 1
    UBS24PUBC_STAGE=fresh-public-openvpn-connect-readonly-eligible
}

# Explicit-command process-local admission. This is not user input by itself:
# only mvc24pubc_connect_once sets these values, after the exact read-only
# preflight. The public dispatcher is still disabled in C23AU.
mvc24pub_connect_admission_witness() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBC_OPERATION:-none} == connect &&
       ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
       ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect &&
       -n ${UBS24PUBC_UNDERLAY:-} ]] || return 1
    case ${UBS24PUBC_MODE:-none} in
        combined)
            mvc24_valid_uuid "${UBS24PUBC_OVPN_UUID:-}" && mvc24_valid_uuid "${UBS24PUBC_WG_UUID:-}" &&
              mvc24_valid_uuid "${UBS24PUBC_TEMP_UUID:-}" && [[ -n ${UBS24PUBC_NM_OWNER:-} ]] || return 1
            case ${UBS24PUBC_STAGE:-idle} in
                authorizing-public-connect|starting-openvpn|starting-wireguard|publishing-active-session|cleanup-stopping-openvpn|cleanup-completing-openvpn|cleanup-stopping-wireguard|cleanup-reconciling-partial-wireguard|cleanup-reobserving-openvpn|cleanup-releasing-private-holds) ;;
                *) return 1 ;;
            esac
            [[ ${UBS24GC4_PREFLIGHT_STAGE:-} == ready &&
               ${UBS24GC4_IFACE:-} == "$UBS24PUBC_UNDERLAY" &&
               ${UBS24GC4_NM_OWNER:-} == "$UBS24PUBC_NM_OWNER" ]] || return 1
            ;;
        openvpn-only)
            mvc24_valid_uuid "${UBS24PUBC_OVPN_UUID:-}" && [[ -n ${UBS24PUBC_NM_OWNER:-} &&
              ${UBS24PUBC_WG_UUID:-} == - && ${UBS24PUBC_TEMP_UUID:-} == - ]] || return 1
            case ${UBS24PUBC_STAGE:-idle} in
                authorizing-public-connect|starting-openvpn|cleanup-stopping-openvpn|cleanup-completing-openvpn) ;;
                *) return 1 ;;
            esac
            [[ ${UBS24GC4_PREFLIGHT_STAGE:-} == ready &&
               ${UBS24GC4_IFACE:-} == "$UBS24PUBC_UNDERLAY" &&
               ${UBS24GC4_NM_OWNER:-} == "$UBS24PUBC_NM_OWNER" ]] || return 1
            ;;
        wireguard-protected)
            [[ ${UBS24PUBC_OVPN_UUID:-} == - && ${UBS24PUBC_NM_OWNER:-} == - ]] || return 1
            mvc24_valid_uuid "${UBS24PUBC_WG_UUID:-}" && mvc24_valid_uuid "${UBS24PUBC_TEMP_UUID:-}" || return 1
            case ${UBS24PUBC_STAGE:-idle} in
                authorizing-public-connect|starting-wireguard|cleanup-stopping-wireguard|cleanup-releasing-guard) ;;
                *) return 1 ;;
            esac
            ;;
        wireguard-split)
            [[ ${UBS24PUBC_OVPN_UUID:-} == - && ${UBS24PUBC_NM_OWNER:-} == - ]] || return 1
            mvc24_valid_uuid "${UBS24PUBC_WG_UUID:-}" && mvc24_valid_uuid "${UBS24PUBC_TEMP_UUID:-}" || return 1
            case ${UBS24PUBC_STAGE:-idle} in
                authorizing-public-connect|starting-wireguard-split|cleanup-stopping-wireguard-split) ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
    mvc24gb4_scope
}

mvc24gco_enable_public_live() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == no &&
       ${UBS24GCO_STAGE:-idle} == idle &&
       ${UBS24GCO_AUTHORITY:-none} == none ]] || return 1
    mvc24pub_connect_admission_witness || return 1
    UBS24GCO_MODE=public-live-explicit-command
    UBS24GCO_AUTHORITY=public-explicit-connect
}

mvc24gco_public_live_enabled() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_MODE:-disabled} == public-live-explicit-command &&
       ${UBS24GCO_AUTHORITY:-none} == public-explicit-connect ]] || return 1
    mvc24pub_connect_admission_witness
}

# Final public-process binding. The private C23AR wrapper never sources this
# module, so its exact physically proven binding remains untouched.
mvc24gco_enabled() {
    (( $# == 0 )) || return 1
    mvc24gco_offline_enabled || mvc24gco_private_live_enabled || mvc24gco_public_live_enabled
}

# Preserve the private D4 authority branch exactly, and add only the public
# explicit-connect branch for the public candidate composition.
mvc24gd4_authority_witness() {
    (( $# == 0 )) || return 1
    local admitted=no
    if [[ ${UBS24GCU_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCU_APPROVAL:-none} == approved-process-local &&
          ${UBS24GCU_OPERATION:-none} == session &&
          ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
          ${UBS24GCO_AUTHORITY:-none} == private-local-console &&
          ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
          ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]]; then
        mvc24gcu_live_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24PUBC_MODE:-none} == combined &&
            ${UBS24GCO_MODE:-disabled} == public-live-explicit-command &&
            ${UBS24GCO_AUTHORITY:-none} == public-explicit-connect &&
            ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
            ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]]; then
        mvc24pub_connect_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24PUBC_MODE:-none} == wireguard-protected &&
            ${UBS24PUBC_STAGE:-} == starting-wireguard ]]; then
        mvc24pub_connect_admission_witness || return 1
        admitted=yes
    elif [[ ${UBS24PUBC_MODE:-none} == wireguard-split &&
            ${UBS24PUBC_STAGE:-} == starting-wireguard-split ]]; then
        mvc24pub_connect_admission_witness && mvc24gws_lock_valid || return 1
        admitted=split
    fi
    [[ $admitted == yes || $admitted == split ]] || return 1
    if [[ $admitted == split ]]; then
        mvc24gb2_root_scope && mvc24gws_lock_valid
    else
        mvc24gb2_root_scope && mvc24gb2_lock_valid
    fi
}


mvc24pubc_preclone_intent_path() {
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/preclone-intent"
}

mvc24pubc_preclone_binding_path() {
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/preclone-binding"
}

mvc24pubc_publish_preclone_intent() {
    (( $# == 2 )) || return 1
    local source_uuid=$1 clone_name=$2 runtime path tmp boot userns netns mntns tx prepare commit source_sha
    runtime=$(mvc24pub_session_runtime_root) || return 1
    path=$(mvc24pubc_preclone_intent_path) || return 1
    [[ ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect &&
       ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
       ${UBS24PUBC_OPERATION:-none} == connect &&
       ${UBS24PUBC_TRANSACTION_STATE:-none} == prepared-before-mutation &&
       ${UBS24PUBC_STAGE:-} == starting-openvpn &&
       $source_uuid == "${UBS24PUBC_OVPN_UUID:-}" &&
       $clone_name =~ ^mvc-prepared-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$ ]] || return 1
    [[ -d $runtime && ! -L $runtime && ! -e $path && ! -L $path ]] || return 1
    mvc24gb2_lock_valid && mvc24gc2_guard_witness || return 1
    mvc24ga3_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24PUBC_NM_OWNER" ]] || return 1
    [[ -n ${UBS24GA3_SOURCE_FILE:-} && -f $UBS24GA3_SOURCE_FILE && ! -L $UBS24GA3_SOURCE_FILE ]] || return 1
    source_sha=$(mvc24op_settings_fingerprint "$UBS24GA3_SOURCE_FILE") || return 1
    [[ $source_sha =~ ^[0-9a-f]{64}$ ]] || return 1
    tx=$(mvc24pubc_hash_file "$runtime/transaction") || return 1
    prepare=$(mvc24pubc_hash_file /run/mvc-controller/prepare-intent) || return 1
    commit=$(mvc24pubc_hash_file /run/mvc-controller/commit-attempt) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tmp=$runtime/.preclone-intent.tmp
    : > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    printf '%s\n' \
      ubs-v240-public-preclone-intent-v1 \
      state=name-absent-bound-before-nm-clone-write \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "transaction=$tx" "controller_prepare=$prepare" "controller_commit=$commit" \
      "source_uuid=$source_uuid" "source_sha=$source_sha" "clone_name=$clone_name" \
      "underlay=$UBS24PUBC_UNDERLAY" "nm_owner=$UBS24PUBC_NM_OWNER" > "$tmp" || return 1
    if ! mv -T -- "$tmp" "$path"; then
        rm -f -- "$tmp" >/dev/null 2>&1 || :
        return 1
    fi
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path" 2>/dev/null) == '0:400:1' ]] || return 1
    UBS24PUBC_PRECLONE_NAME=$clone_name
}

mvc24pubc_publish_preclone_binding() {
    (( $# == 3 )) || return 1
    local source_uuid=$1 clone_name=$2 clone_uuid=$3 runtime intent path tmp boot pre
    runtime=$(mvc24pub_session_runtime_root) || return 1
    intent=$(mvc24pubc_preclone_intent_path) || return 1
    path=$(mvc24pubc_preclone_binding_path) || return 1
    [[ $source_uuid == "${UBS24PUBC_OVPN_UUID:-}" && $clone_name == "${UBS24PUBC_PRECLONE_NAME:-}" &&
       $clone_uuid != "$source_uuid" ]] && mvc24ga_uuid_valid "$clone_uuid" || return 1
    [[ -f $intent && ! -L $intent && ! -e $path && ! -L $path ]] || return 1
    mvc24gb2_lock_valid && mvc24gc2_guard_witness || return 1
    mvc24ga3_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24PUBC_NM_OWNER" ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    pre=$(mvc24pubc_hash_file "$intent") || return 1
    tmp=$runtime/.preclone-binding.tmp
    : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-preclone-binding-v1 state=raw-clone-uuid-observed-before-hardening \
      "boot=$boot" "preclone=$pre" "source_uuid=$source_uuid" "clone_name=$clone_name" \
      "clone_uuid=$clone_uuid" "nm_owner=$UBS24PUBC_NM_OWNER" > "$tmp" || return 1
    if ! mv -T -- "$tmp" "$path"; then rm -f -- "$tmp" >/dev/null 2>&1 || :; return 1; fi
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:400:1' ]]
}

# Public-only implementation of A1's optional pre-mutation hook. Private C23AR
# never sources this module and therefore retains the adapter's no-op hook.
mvc24ga_preclone_intent_hook() { mvc24pubc_publish_preclone_intent "$@"; }
mvc24ga_postclone_identity_hook() { mvc24pubc_publish_preclone_binding "$@"; }

mvc24pubc_retire_preclone_intent_after_c7() {
    (( $# == 0 )) || return 1
    local path
    path=$(mvc24pubc_preclone_intent_path) || return 1
    [[ -f $path && ! -L $path && ${UBS24PUBC_TRANSACTION_STATE:-none} == prepared-before-mutation ]] || return 1
    mvc24gb2_lock_valid && mvc24gc3_transition_records_valid && mvc24gc7_read_intent || return 1
    [[ $UBS24GC7_SOURCE_UUID == "$UBS24PUBC_OVPN_UUID" ]] && mvc24ga_uuid_valid "$UBS24GC7_CLONE_UUID" || return 1
    local binding
    binding=$(mvc24pubc_preclone_binding_path) || return 1
    if [[ -e $binding || -L $binding ]]; then
        [[ -f $binding && ! -L $binding ]] || return 1
        rm -f -- "$binding" || return 1
    fi
    rm -f -- "$path" || return 1
    [[ ! -e $path && ! -L $path && ! -e $binding && ! -L $binding ]]
}

mvc24pubc_transaction_path() {
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/transaction"
}

mvc24pubc_transaction_write() {
    (( $# == 1 )) || return 1
    local state=$1 runtime file tmp boot userns netns mntns clone='-' prepare_sha='-' transition_sha='-' activation_sha='-' output_sha='-' d4_sha='-'
    runtime=$(mvc24pub_session_runtime_root) || return 1
    file=$runtime/transaction
    case $state in
      prepared-before-mutation|wireguard-split-prepared)
        [[ ! -e $runtime && ! -L $runtime ]] || return 1
        umask 077
        mkdir --mode=700 -- "$runtime" || return 1
        ;;
      openvpn-protected|dual-active-observed)
        [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' &&
           -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
        clone=${UBS24GC7_CLONE_UUID:-}
        mvc24_valid_uuid "$clone" || return 1
        prepare_sha=$(mvc24pubc_hash_file "$(mvc24pubc_controller_prepare_path)") || return 1
        transition_sha=$(mvc24pubc_hash_file "$(mvc24pubc_controller_transition_path)") || return 1
        activation_sha=$(mvc24pubc_hash_file "$(mvc24pubc_activation_path)") || return 1
        output_sha=$(mvc24pubc_hash_file "$(mvc24pubc_output_path)") || return 1
        if [[ $state == dual-active-observed ]]; then
            d4_sha=$(mvc24pubc_hash_file "$(mvc24pubc_d4_intent_path)") || return 1
        fi
        ;;
      wireguard-protected)
        [[ ${UBS24PUBC_MODE:-none} == wireguard-protected &&
           -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' &&
           -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
        prepare_sha=$(mvc24pubc_hash_file "$(mvc24pubc_controller_prepare_path)") || return 1
        d4_sha=$(mvc24pubc_hash_file "$(mvc24pubc_d4_intent_path)") || return 1
        ;;
      wireguard-split)
        [[ ${UBS24PUBC_MODE:-none} == wireguard-split &&
           -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' &&
           -f $file && ! -L $file && $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
        mvc24gws_lock_valid || return 1
        d4_sha=$(mvc24pubc_hash_file "$(mvc24pubc_d4_intent_path)") || return 1
        ;;
      *) return 1 ;;
    esac
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    mvc24gb1_valid_ifname "$UBS24PUBC_UNDERLAY" || return 1
    case ${UBS24PUBC_MODE:-none} in
      combined)
        mvc24_valid_uuid "$UBS24PUBC_OVPN_UUID" && mvc24_valid_uuid "$UBS24PUBC_WG_UUID" &&
          mvc24_valid_uuid "$UBS24PUBC_TEMP_UUID" || return 1
        [[ $state != wireguard-protected ]] || return 1
        ;;
      openvpn-only)
        mvc24_valid_uuid "$UBS24PUBC_OVPN_UUID" || return 1
        [[ $state != dual-active-observed && $state != wireguard-protected &&
           $UBS24PUBC_WG_UUID == - && $UBS24PUBC_TEMP_UUID == - ]] || return 1
        ;;
      wireguard-protected)
        [[ $UBS24PUBC_OVPN_UUID == - && $UBS24PUBC_NM_OWNER == - &&
           $state != openvpn-protected && $state != dual-active-observed &&
           $state != wireguard-split-prepared && $state != wireguard-split ]] || return 1
        mvc24_valid_uuid "$UBS24PUBC_WG_UUID" && mvc24_valid_uuid "$UBS24PUBC_TEMP_UUID" || return 1
        ;;
      wireguard-split)
        [[ $UBS24PUBC_OVPN_UUID == - && $UBS24PUBC_NM_OWNER == - &&
           ( $state == wireguard-split-prepared || $state == wireguard-split ) ]] || return 1
        mvc24_valid_uuid "$UBS24PUBC_WG_UUID" && mvc24_valid_uuid "$UBS24PUBC_TEMP_UUID" || return 1
        ;;
      *) return 1 ;;
    esac
    tmp=$runtime/.transaction.tmp
    : > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    printf '%s\n' \
      'ubs-v240-public-transaction-v1' \
      "state=$state" \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "ovpn_source_uuid=$UBS24PUBC_OVPN_UUID" "ovpn_clone_uuid=$clone" \
      "wg_source_uuid=$UBS24PUBC_WG_UUID" "wg_temp_uuid=$UBS24PUBC_TEMP_UUID" \
      "underlay=$UBS24PUBC_UNDERLAY" \
      "controller_prepare_sha=$prepare_sha" "controller_transition_sha=$transition_sha" \
      "activation_sha=$activation_sha" "output_sha=$output_sha" "d4_intent_sha=$d4_sha" \
      > "$tmp" || return 1
    if ! mv -T -- "$tmp" "$file"; then
        rm -f -- "$tmp" >/dev/null 2>&1 || :
        [[ ! -e $tmp && ! -L $tmp ]] || return 1
        return 1
    fi
    [[ $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
    UBS24PUBC_TRANSACTION_STATE=$state
}

mvc24pubc_transaction_remove_if_unmutated() {
    (( $# == 0 )) || return 1
    local runtime file
    runtime=$(mvc24pub_session_runtime_root) || return 1
    file=$runtime/transaction
    [[ ${UBS24PUBC_TRANSACTION_STATE:-none} == prepared-before-mutation &&
       -d $runtime && ! -L $runtime && -f $file && ! -L $file ]] || return 1
    rm -f -- "$file" || return 1
    rmdir -- "$runtime" || return 1
    UBS24PUBC_TRANSACTION_STATE=none
}

mvc24pubc_transaction_finalize_after_completion() {
    (( $# == 0 )) || return 1
    local runtime file active entry base
    local -a entries=()
    runtime=$(mvc24pub_session_runtime_root) || return 1
    file=$runtime/transaction
    active=$runtime/active
    [[ -d $runtime && ! -L $runtime && -f $file && ! -L $file &&
       $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' &&
       $(stat -c '%u:%a:%h' -- "$file" 2>/dev/null) == '0:400:1' ]] || return 1
    mapfile -d '' -t entries < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} >= 1 && ${#entries[@]} <= 2 )) || return 1
    for entry in "${entries[@]}"; do
        base=${entry##*/}
        case $base in
          transaction) ;;
          active)
            [[ ${UBS24PUBC_ACTIVE_MARKER_PUBLISHED_THIS_PROCESS:-no} == yes &&
               -f $active && ! -L $active &&
               $(stat -c '%u:%a:%h' -- "$active" 2>/dev/null) == '0:400:1' &&
               $(sed -n '1p' -- "$active") == ubs-v240-public-active-v1 &&
               $(sed -n '2p' -- "$active") == state=dual-active-published ]] || return 1
            ;;
          *) return 1 ;;
        esac
    done
    if [[ -e $active || -L $active ]]; then
        rm -f -- "$active" >/dev/null 2>&1 || :
        [[ ! -e $active && ! -L $active ]] || return 1
    fi
    rm -f -- "$file" >/dev/null 2>&1 || :
    [[ ! -e $file && ! -L $file ]] || return 1
    rmdir -- "$runtime" >/dev/null 2>&1 || :
    [[ ! -e $runtime && ! -L $runtime ]] || return 1
    UBS24PUBC_TRANSACTION_STATE=none
}

mvc24pubc_controller_prepare_path() { printf '%s\n' /run/mvc-controller/prepare-intent; }
mvc24pubc_controller_transition_path() { printf '%s\n' /run/mvc-controller/transition-attempt; }
mvc24pubc_activation_path() { printf '%s\n' /run/mvc-activation/attempt; }
mvc24pubc_output_path() { printf '%s\n' /run/mvc-output-transition/attempt; }
mvc24pubc_d4_intent_path() { printf '%s\n' /run/mvc-wireguard/intent; }

mvc24pubc_publish_active_session() {
    (( $# == 0 )) || return 1
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    local boot userns netns mntns tmp prepare_sha transition_sha activation_sha output_sha d4_sha
    [[ $runtime == /* && -d $runtime && ! -L $runtime &&
       $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' &&
       -f $runtime/transaction && ! -L $runtime/transaction ]] || return 1
    [[ ${UBS24PUBC_STAGE:-} == publishing-active-session &&
       ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
       ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority &&
       ${UBS24GD4_STAGE:-} == parallel-wireguard-openvpn-protected-running ]] || return 1
    mvc24pub_connect_admission_witness || return 1
    mvc24gd4_dual_active_observed || return 1
    mvc24_valid_uuid "${UBS24GC7_CLONE_UUID:-}" &&
      mvc24_valid_uuid "$UBS24PUBC_OVPN_UUID" && mvc24_valid_uuid "$UBS24PUBC_WG_UUID" &&
      mvc24_valid_uuid "${UBS24GD4_TEMP_UUID:-}" || return 1

    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    prepare_sha=$(mvc24pubc_hash_file "$(mvc24pubc_controller_prepare_path)") || return 1
    transition_sha=$(mvc24pubc_hash_file "$(mvc24pubc_controller_transition_path)") || return 1
    activation_sha=$(mvc24pubc_hash_file "$(mvc24pubc_activation_path)") || return 1
    output_sha=$(mvc24pubc_hash_file "$(mvc24pubc_output_path)") || return 1
    d4_sha=$(mvc24pubc_hash_file "$(mvc24pubc_d4_intent_path)") || return 1

    umask 077
    tmp=$runtime/.active.tmp
    : > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    printf '%s\n' \
      'ubs-v240-public-active-v1' \
      'state=dual-active-published' \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "ovpn_source_uuid=$UBS24PUBC_OVPN_UUID" "ovpn_clone_uuid=$UBS24GC7_CLONE_UUID" \
      "wg_source_uuid=$UBS24PUBC_WG_UUID" "wg_temp_uuid=$UBS24GD4_TEMP_UUID" \
      "underlay=$UBS24PUBC_UNDERLAY" \
      "controller_prepare_sha=$prepare_sha" "controller_transition_sha=$transition_sha" \
      "activation_sha=$activation_sha" "output_sha=$output_sha" "d4_intent_sha=$d4_sha" \
      > "$tmp" || return 1
    if ! mv -T -- "$tmp" "$runtime/active"; then
        # As with transaction upgrades, remove only the unpublished scratch
        # pathname. If the rename actually landed despite a nonzero reply, mark
        # that exact file as same-process-owned so failure cleanup may retire it.
        rm -f -- "$tmp" >/dev/null 2>&1 || :
        [[ ! -e $tmp && ! -L $tmp ]] || return 1
        if [[ -f $runtime/active && ! -L $runtime/active &&
              $(stat -c '%u:%a:%h' -- "$runtime/active" 2>/dev/null) == '0:400:1' &&
              $(sed -n '1p' -- "$runtime/active") == ubs-v240-public-active-v1 &&
              $(sed -n '2p' -- "$runtime/active") == state=dual-active-published ]]; then
            UBS24PUBC_ACTIVE_MARKER_PUBLISHED_THIS_PROCESS=yes
        fi
        return 1
    fi
    [[ $(stat -c '%u:%a:%h' -- "$runtime/active" 2>/dev/null) == '0:400:1' ]] || return 1
    UBS24PUBC_ACTIVE_MARKER_PUBLISHED_THIS_PROCESS=yes
    rm -f -- "$runtime/transaction" >/dev/null 2>&1 || :
    [[ ! -e $runtime/transaction && ! -L $runtime/transaction ]] || return 1
    UBS24PUBC_TRANSACTION_STATE=none
    UBS24PUBC_STAGE=dual-active-session-published
}

mvc24pubc_consume_authority() {
    UBS24PUBC_APPROVAL=consumed
    UBS24PUBC_AUTHORITY=none
    # This process has no further mutation work. Clearing the public GCO token
    # ensures an accidental later call cannot reuse connect authority.
    if [[ ${UBS24GCO_MODE:-} == public-live-explicit-command ]]; then
        UBS24GCO_AUTHORITY=none
    fi
}

mvc24pubc_cleanup_openvpn_only_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBC_TRANSACTION_STATE:-none} == openvpn-protected &&
       ! -e /run/mvc-wireguard && ! -L /run/mvc-wireguard &&
       ${UBS24GCO_STAGE:-} == protected-openvpn-observed ]] || return 1
    UBS24PUBC_STAGE=cleanup-stopping-openvpn
    mvc24gco_stop_once || return 1
    UBS24PUBC_STAGE=cleanup-completing-openvpn
    mvc24gco_complete_once || return 1
    mvc24pubc_transaction_finalize_after_completion || return 1
    UBS24PUBC_STAGE=connect-failed-clean-baseline-restored
}

mvc24pubc_cleanup_dual_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBC_TRANSACTION_STATE:-none} == dual-active-observed &&
       ${UBS24GD4_STAGE:-} == parallel-wireguard-openvpn-protected-running &&
       ${UBS24GCO_STAGE:-} == protected-openvpn-observed ]] || return 1
    UBS24PUBC_STAGE=cleanup-stopping-wireguard
    mvc24gd4_stop_once || return 1
    [[ ${UBS24GD4_STAGE:-} == wireguard-residue-removed-openvpn-protected-private-hold ]] || return 1
    UBS24PUBC_STAGE=cleanup-reobserving-openvpn
    mvc24pubd_reobserve_openvpn_after_wg || return 1
    UBS24PUBC_STAGE=cleanup-stopping-openvpn
    mvc24gco_stop_once || return 1
    UBS24PUBC_STAGE=cleanup-releasing-private-holds
    mvc24gd4_release_private_hold_after_openvpn_stop || return 1
    UBS24PUBC_STAGE=cleanup-completing-openvpn
    mvc24gco_complete_once || return 1
    mvc24pubc_transaction_finalize_after_completion || return 1
    UBS24PUBC_STAGE=connect-failed-clean-baseline-restored
}

mvc24pubc_cleanup_partial_d4_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24PUBC_TRANSACTION_STATE:-none} == openvpn-protected &&
       -e $(mvc24pub_wireguard_runtime_root) && ! -L $(mvc24pub_wireguard_runtime_root) ]] || return 1
    UBS24PUBC_STAGE=cleanup-reconciling-partial-wireguard
    # Reuse the fresh-process parser to reconstruct and cross-check the exact
    # immutable D4 intent against the identities already selected by CONNECT.
    UBS24PUBD_WG_SOURCE_UUID=$UBS24PUBC_WG_UUID
    UBS24PUBD_WG_TEMP_UUID=$UBS24PUBC_TEMP_UUID
    UBS24PUBD_UNDERLAY=$UBS24PUBC_UNDERLAY
    mvc24pubd_load_d4_intent || return 1
    mvc24pubr_reconcile_partial_d4_to_openvpn_hold || return 1
    UBS24PUBC_STAGE=cleanup-reobserving-openvpn
    mvc24pubd_reobserve_openvpn_after_wg || return 1
    UBS24PUBC_STAGE=cleanup-stopping-openvpn
    mvc24gco_stop_once || return 1
    UBS24PUBC_STAGE=cleanup-releasing-private-holds
    mvc24gd4_release_private_hold_after_openvpn_stop || return 1
    UBS24PUBC_STAGE=cleanup-completing-openvpn
    mvc24gco_complete_once || return 1
    mvc24pubc_transaction_finalize_after_completion || return 1
    UBS24PUBC_STAGE=connect-failed-clean-baseline-restored
}




mvc24pubc_connect_openvpn_once() {
    (( $# == 1 )) || return 1
    local ovpn_name=$1 original_failure
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    if ! mvc24pubc_preflight_openvpn_readonly "$ovpn_name"; then
        UBS24PUBC_ATTEMPTED=yes
        return 1
    fi
    UBS24PUBC_ATTEMPTED=yes
    UBS24PUBC_OPERATION=connect
    UBS24PUBC_APPROVAL=approved-process-local
    UBS24PUBC_AUTHORITY=public-explicit-connect

    UBS24PUBC_STAGE=publishing-pre-mutation-transaction
    if ! mvc24pubc_transaction_write prepared-before-mutation; then
        UBS24PUBC_STAGE=pre-mutation-transaction-publication-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=authorizing-public-connect
    if ! mvc24gco_enable_public_live; then
        UBS24PUBC_STAGE=public-openvpn-authority-refused
        mvc24pubc_transaction_remove_if_unmutated || UBS24PUBC_STAGE=authority-refused-transaction-cleanup-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=starting-openvpn
    if ! mvc24gco_start_once "$UBS24PUBC_OVPN_UUID" "$UBS24PUBC_UNDERLAY"; then
        original_failure="openvpn-start-failed-${UBS24GC17_STAGE:-unknown}"
        if mvc24pube_c7_intent_present && mvc24pube_reconcile_incomplete_start_locked; then
            UBS24PUBC_STAGE="${original_failure}-auto-cleaned-baseline"
            mvc24pubc_consume_authority
            return 1
        fi
        if mvc24pube_preclone_intent_present && mvc24pube_reconcile_pre_c7_locked; then
            UBS24PUBC_STAGE="${original_failure}-pre-c7-auto-cleaned-baseline"
            mvc24pubc_consume_authority
            return 1
        fi
        UBS24PUBC_STAGE="${original_failure}-cleanup-refused-use-disconnect-or-recovery"
        mvc24pubc_consume_authority
        return 1
    fi

    if ! mvc24pubc_retire_preclone_intent_after_c7; then
        UBS24PUBC_STAGE=openvpn-preclone-intent-retirement-failed
        if declare -F mvc24pube_reconcile_incomplete_start_locked >/dev/null && mvc24pube_reconcile_incomplete_start_locked; then
            UBS24PUBC_STAGE=openvpn-preclone-intent-retirement-failed-auto-cleaned-baseline
        fi
        mvc24pubc_consume_authority
        return 1
    fi
    if ! mvc24pubc_transaction_write openvpn-protected; then
        UBS24PUBC_STAGE=openvpn-protected-transaction-update-failed
        UBS24PUBC_TRANSACTION_STATE=openvpn-protected
        if mvc24pubc_cleanup_openvpn_only_once; then
            mvc24pubc_consume_authority
            return 1
        fi
        UBS24PUBC_STAGE=openvpn-protected-transaction-update-failed-cleanup-refused
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=openvpn-only-session-published-connect-complete
    mvc24pubc_consume_authority
    return 0
}

mvc24pubc_connect_wireguard_protected_once() {
    (( $# == 1 )) || return 1
    local wg_name=$1 original_failure
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    if ! mvc24gwg_preflight_readonly "$wg_name"; then
        UBS24PUBC_ATTEMPTED=yes
        return 1
    fi
    UBS24PUBC_ATTEMPTED=yes
    UBS24PUBC_OPERATION=connect
    UBS24PUBC_APPROVAL=approved-process-local
    UBS24PUBC_AUTHORITY=public-explicit-connect

    UBS24PUBC_STAGE=publishing-pre-mutation-transaction
    if ! mvc24pubc_transaction_write prepared-before-mutation; then
        UBS24PUBC_STAGE=pre-mutation-transaction-publication-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=authorizing-public-connect
    UBS24GWG_STAGE=authorizing-public-connect
    if ! mvc24pub_connect_admission_witness; then
        UBS24PUBC_STAGE=public-wireguard-protected-authority-refused
        mvc24pubc_transaction_remove_if_unmutated || UBS24PUBC_STAGE=authority-refused-transaction-cleanup-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=starting-wireguard
    if ! mvc24gwg_start_once; then
        original_failure="wireguard-protected-start-failed-${UBS24GWG_STAGE:-unknown}"
        UBS24PUBC_STAGE="${original_failure}-guard-may-remain-use-recovery"
        mvc24pubc_consume_authority
        return 1
    fi

    if ! mvc24pubc_transaction_write wireguard-protected; then
        UBS24PUBC_STAGE=wireguard-protected-transaction-update-failed
        # The active state is exact and same-process authenticated. Tear it
        # down rather than strand a protected session behind the older marker.
        UBS24PUBC_STAGE=cleanup-stopping-wireguard
        if mvc24gwg_stop_once; then
            UBS24PUBC_STAGE=wireguard-protected-transaction-update-failed-auto-cleaned-baseline
        else
            UBS24PUBC_STAGE="wireguard-protected-transaction-update-failed-cleanup-refused-${UBS24GWG_STAGE:-unknown}"
        fi
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=wireguard-only-protected-session-published-connect-complete
    mvc24pubc_consume_authority
    return 0
}

mvc24pubc_connect_once() {
    (( $# == 2 )) || return 1
    local wg_name=$1 ovpn_name=$2 original_failure
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    if ! mvc24pubc_preflight_readonly "$wg_name" "$ovpn_name"; then
        UBS24PUBC_ATTEMPTED=yes
        return 1
    fi
    UBS24PUBC_ATTEMPTED=yes
    UBS24PUBC_OPERATION=connect
    UBS24PUBC_APPROVAL=approved-process-local
    UBS24PUBC_AUTHORITY=public-explicit-connect

    # Publish same-boot ownership before the first host mutation. At this state
    # all mutation-derived hashes are deliberately '-'.
    UBS24PUBC_STAGE=publishing-pre-mutation-transaction
    if ! mvc24pubc_transaction_write prepared-before-mutation; then
        UBS24PUBC_STAGE=pre-mutation-transaction-publication-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=authorizing-public-connect
    if ! mvc24gco_enable_public_live; then
        UBS24PUBC_STAGE=public-openvpn-authority-refused
        mvc24pubc_transaction_remove_if_unmutated || UBS24PUBC_STAGE=authority-refused-transaction-cleanup-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=starting-openvpn
    if ! mvc24gco_start_once "$UBS24PUBC_OVPN_UUID" "$UBS24PUBC_UNDERLAY"; then
        original_failure="openvpn-start-failed-${UBS24GC17_STAGE:-unknown}"
        # Once C7 exists, the exact temporary clone and C1/C13 ownership are
        # durably bound. Reconcile that authenticated partial start now.
        if mvc24pube_c7_intent_present && mvc24pube_reconcile_incomplete_start_locked; then
            UBS24PUBC_STAGE="${original_failure}-auto-cleaned-baseline"
            mvc24pubc_consume_authority
            return 1
        fi
        # Stage 7: A1 now publishes an unguessable clone-name intent before the
        # first NM clone write. If C7 does not exist but that intent does, the
        # pre-C7 reconciler can authenticate an inactive temporary clone (or its
        # absence), remove only that owned clone, release B2/C1 and retire state.
        if mvc24pube_preclone_intent_present && mvc24pube_reconcile_pre_c7_locked; then
            UBS24PUBC_STAGE="${original_failure}-pre-c7-auto-cleaned-baseline"
            mvc24pubc_consume_authority
            return 1
        fi
        UBS24PUBC_STAGE="${original_failure}-cleanup-refused-use-disconnect-or-recovery"
        mvc24pubc_consume_authority
        return 1
    fi
    # C7 now durably owns the exact clone UUID. Retire the earlier name-only
    # intent before upgrading the public transaction; a crash after this point
    # is handled by the existing C23BE prepared+C7 reconciliation path.
    if ! mvc24pubc_retire_preclone_intent_after_c7; then
        UBS24PUBC_STAGE=openvpn-preclone-intent-retirement-failed
        if declare -F mvc24pube_reconcile_incomplete_start_locked >/dev/null && mvc24pube_reconcile_incomplete_start_locked; then
            UBS24PUBC_STAGE=openvpn-preclone-intent-retirement-failed-auto-cleaned-baseline
        fi
        mvc24pubc_consume_authority
        return 1
    fi
    if ! mvc24pubc_transaction_write openvpn-protected; then
        UBS24PUBC_STAGE=openvpn-protected-transaction-update-failed
        # The protected OpenVPN state is authenticated in this process. Clean it
        # before returning rather than stranding the caller behind C11.
        UBS24PUBC_TRANSACTION_STATE=openvpn-protected
        if mvc24pubc_cleanup_openvpn_only_once; then
            mvc24pubc_consume_authority
            return 1
        fi
        UBS24PUBC_STAGE=openvpn-protected-transaction-update-failed-cleanup-refused
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=starting-wireguard
    if ! mvc24gd4_start_once; then
        original_failure="wireguard-start-failed-${UBS24GD4_STAGE:-unknown}"
        # If D4 failed before publishing its immutable intent, it made no
        # authenticated WG mutation. This is exactly the C23AY failure class.
        if [[ ! -e $(mvc24pub_wireguard_runtime_root) && ! -L $(mvc24pub_wireguard_runtime_root) ]]; then
            if mvc24pubc_cleanup_openvpn_only_once; then
                UBS24PUBC_STAGE="${original_failure}-auto-cleaned-baseline"
                mvc24pubc_consume_authority
                return 1
            fi
            UBS24PUBC_STAGE="${original_failure}-openvpn-cleanup-refused"
        else
            if mvc24pubc_cleanup_partial_d4_once; then
                UBS24PUBC_STAGE="${original_failure}-auto-cleaned-partial-d4-baseline"
                mvc24pubc_consume_authority
                return 1
            fi
            UBS24PUBC_STAGE="${original_failure}-partial-d4-cleanup-refused-use-disconnect"
        fi
        mvc24pubc_consume_authority
        return 1
    fi
    [[ ${UBS24GD4_STAGE:-} == parallel-wireguard-openvpn-protected-running ]] || {
        UBS24PUBC_STAGE=wireguard-active-contract-failed
        mvc24pubc_consume_authority
        return 1
    }
    if ! mvc24pubc_transaction_write dual-active-observed; then
        UBS24PUBC_STAGE=dual-active-transaction-update-failed
        mvc24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=publishing-active-session
    if ! mvc24pubc_publish_active_session; then
        original_failure=active-session-publication-failed
        if mvc24pubc_cleanup_dual_once; then
            UBS24PUBC_STAGE="${original_failure}-auto-cleaned-baseline"
            mvc24pubc_consume_authority
            return 1
        fi
        UBS24PUBC_STAGE="${original_failure}-dual-session-retained-for-disconnect"
        mvc24pubc_consume_authority
        return 1
    fi
    UBS24PUBC_STAGE=dual-active-session-published-connect-complete
    mvc24pubc_consume_authority
    return 0
}

mvc24pubc_authorize_dispatch_live() { return 1; }
mvc24pubc_authorize_disconnect() { return 1; }
mvc24pubc_authorize_automatic_retry() { return 1; }

mvc24pubc_reset
