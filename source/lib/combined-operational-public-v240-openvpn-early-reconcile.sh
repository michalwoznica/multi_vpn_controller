#!/usr/bin/env bash
# C23BE + C23BF Stage 7 — authenticated reconciliation of an incomplete public
# OpenVPN start. C7-and-later recovery remains the C23BE path. Stage 7 adds a
# separate pre-C7 path whose authority comes only from a random, prechecked-
# absent clone-name intent and (when observed) a UUID binding published before
# A2 hardening can rename the temporary profile. Every cleanup mutation is
# preceded by a durable root-owned intent and driven from current observation.

ubs24pube_reset() {
    UBS24PUBE_STAGE=idle
    UBS24PUBE_GUARD_INITIAL=unknown
    UBS24PUBE_C13_PRESENT=no
    UBS24PUBE_SOURCE_UUID=
    UBS24PUBE_CLONE_UUID=
    UBS24PUBE_UNDERLAY=
    UBS24PUBE_NM_OWNER=
    UBS24PUBE_PRECLONE_NAME=
    UBS24PUBE_PRECLONE_UUID=
    UBS24PUBE_PRECLONE_TOKEN=
    UBS24PUBE_PRECLONE_GUARD=unknown
    UBS24PUBE_PRECLONE_PRESENCE=unknown
}

ubs24pube_runtime() { ubs24pub_session_runtime_root; }
ubs24pube_plan_path() { printf '%s/early-plan\n' "$(ubs24pube_runtime)"; }
ubs24pube_handback_batch_path() { printf '%s/early-handback.nft\n' "$(ubs24pube_runtime)"; }
ubs24pube_handback_intent_path() { printf '%s/early-handback-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_stop_intent_path() { printf '%s/early-stop-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_clone_delete_intent_path() { printf '%s/early-clone-delete-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_release_batch_path() { printf '%s/early-guard-release.nft\n' "$(ubs24pube_runtime)"; }
ubs24pube_release_intent_path() { printf '%s/early-guard-release-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_retire_intent_path() { printf '%s/early-retire-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_archive_root() { printf '%s\n' /run/mvc-completed-early; }
ubs24pube_preclone_archive_root() { printf '%s\n' /run/mvc-completed-preclone; }
ubs24pube_preclone_intent_path() { printf '%s/preclone-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_preclone_binding_path() { printf '%s/preclone-binding\n' "$(ubs24pube_runtime)"; }
ubs24pube_preclone_delete_intent_path() { printf '%s/preclone-delete-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_preclone_release_batch_path() { printf '%s/preclone-release.nft\n' "$(ubs24pube_runtime)"; }
ubs24pube_preclone_release_intent_path() { printf '%s/preclone-release-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_preclone_retire_intent_path() { printf '%s/preclone-retire-intent\n' "$(ubs24pube_runtime)"; }
ubs24pube_controller_runtime() { printf '%s\n' /run/mvc-controller; }
ubs24pube_activation_runtime() { printf '%s\n' /run/mvc-activation; }
ubs24pube_output_runtime() { printf '%s\n' /run/mvc-output-transition; }

ubs24pube_sha() { ubs24pubc_hash_file "$1"; }
ubs24pube_c7_intent_present() {
    (( $# == 0 )) || return 1
    [[ -f /run/mvc-activation/attempt && ! -L /run/mvc-activation/attempt &&
       $(stat -c '%u:%a:%h' -- /run/mvc-activation/attempt 2>/dev/null) == '0:400:1' ]]
}

ubs24pube_preclone_intent_present() {
    (( $# == 0 )) || return 1
    local path
    path=$(ubs24pube_preclone_intent_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path" 2>/dev/null) == '0:400:1' ]]
}

ubs24pube_context_witness() {
    (( $# == 0 )) || return 1
    if [[ ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect &&
          ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
          ${UBS24PUBC_OPERATION:-none} == connect &&
          ${UBS24PUBC_TRANSACTION_STATE:-none} == prepared-before-mutation ]]; then
        UBS24PUBE_SOURCE_UUID=${UBS24PUBC_OVPN_UUID:-}
        UBS24PUBE_UNDERLAY=${UBS24PUBC_UNDERLAY:-}
    elif [[ ${UBS24PUBD_AUTHORITY:-none} == public-explicit-disconnect &&
            ${UBS24PUBD_APPROVAL:-none} == approved-process-local &&
            ${UBS24PUBD_OPERATION:-none} == disconnect &&
            ${UBS24PUBD_MARKER_KIND:-none} == transaction &&
            ${UBS24PUBD_TRANSACTION_STATE:-none} == prepared-before-mutation ]]; then
        UBS24PUBE_SOURCE_UUID=${UBS24PUBD_OVPN_SOURCE_UUID:-}
        UBS24PUBE_UNDERLAY=${UBS24PUBD_UNDERLAY:-}
    else
        return 1
    fi
    ubs24ga_uuid_valid "$UBS24PUBE_SOURCE_UUID" &&
      ubs24gb1_valid_ifname "$UBS24PUBE_UNDERLAY" &&
      ubs24gb2_root_scope && ubs24gb2_lock_valid
}

ubs24pube_public_runtime_shape() {
    (( $# == 0 )) || return 1
    local runtime p base
    runtime=$(ubs24pube_runtime) || return 1
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime" 2>/dev/null) == '0:700:2' ]] || return 1
    while IFS= read -r -d '' p; do
        base=${p##*/}
        case $base in
            transaction|preclone-intent|preclone-binding|preclone-delete-intent|preclone-release.nft|preclone-release-intent|preclone-retire-intent|early-plan|early-handback.nft|early-handback-intent|early-stop-intent|early-clone-delete-intent|early-guard-release.nft|early-guard-release-intent|early-retire-intent) ;;
            *) return 1 ;;
        esac
        [[ -f $p && ! -L $p && $(stat -c '%u:%a:%h' -- "$p" 2>/dev/null) == '0:400:1' ]] || return 1
    done < <(find "$runtime" -mindepth 1 -maxdepth 1 -print0)
}

ubs24pube_rehydrate_c7_locked() {
    (( $# == 0 )) || return 1
    ubs24pube_context_witness || return 1
    ubs24gc3_transition_records_valid && ubs24gc7_read_intent || return 1
    [[ $UBS24GC7_SOURCE_UUID == "$UBS24PUBE_SOURCE_UUID" &&
       $UBS24GC3_IFACE == "$UBS24PUBE_UNDERLAY" ]] || return 1
    UBS24PUBE_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24PUBE_NM_OWNER=$UBS24GC7_NM_OWNER
    ubs24ga_uuid_valid "$UBS24PUBE_CLONE_UUID" && ubs24gc7_nm_owner_valid "$UBS24PUBE_NM_OWNER" || return 1

    UBS24GA3_PREPARED_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GA3_PREPARED_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_SOURCE_SHA256=$UBS24GC7_SOURCE_SHA
    UBS24GA3_DERIVATIVE_SHA256=$UBS24GC7_CLONE_SHA
    UBS24GA_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_STAGE=prepared-nonsecret-parity-only
    UBS24GA3_AUTHORITY=none
    UBS24GA2_STATE=quarantined-exact-nonsecret-settings-verified
    local UBS24S_LOCK_HELD=1
    ubs24op_session_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24PUBE_NM_OWNER" ]] || return 1

    # The clone may already have disappeared after an interrupted NM attempt.
    # If it still exists, require the full immutable non-secret fingerprint.
    UBS24GC23T_SOURCE_UUID=$UBS24PUBE_SOURCE_UUID
    if ubs24gc23t_clone_present "$UBS24PUBE_CLONE_UUID"; then
        ubs24gc5_prepared_profile_witness || return 1
    elif ! ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID"; then
        return 1
    fi
}

ubs24pube_capture_guard_state() {
    (( $# == 0 )) || return 1
    UBS24PUBE_C13_PRESENT=no
    if [[ -e /run/mvc-output-transition || -L /run/mvc-output-transition ]]; then
        [[ -d /run/mvc-output-transition && ! -L /run/mvc-output-transition ]] || return 1
        ubs24gc15_load_bound_intent || return 1
        UBS24PUBE_C13_PRESENT=yes
        local scratch a b c1=0 c11=0
        scratch=$(umask 077; mktemp -d /run/mvc-pube-guard.XXXXXXXX) || return 1
        a=$scratch/a.json; b=$scratch/b.json
        if ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" && cmp -s -- "$a" "$b"; then
            ubs24gc19_kernel_witness c1 "$a" "$b" && c1=1
            ubs24gc19_kernel_witness c11 "$a" "$b" && c11=1
        fi
        rm -f -- "$a" "$b" || { rmdir -- "$scratch" 2>/dev/null || true; return 1; }
        rmdir -- "$scratch" || return 1
        (( c1 + c11 == 1 )) || return 1
        if (( c11 == 1 )); then UBS24PUBE_GUARD_INITIAL=c11; else UBS24PUBE_GUARD_INITIAL=c1; fi
    else
        ubs24gc5_guard_witness || return 1
        UBS24PUBE_GUARD_INITIAL=c1
    fi
}

# C23BF Stage 7: authenticate and reconcile the pre-C7 clone window. The
# preclone intent is published by the public A1 hook after a cryptographically
# random name was proven absent and immediately before the first NM clone write.
ubs24pube_preclone_intent_valid() {
    (( $# == 0 )) || return 1
    local runtime path boot userns netns mntns tx prepare commit source_sha tmp current_sha
    local -a rows=()
    ubs24pube_context_witness || return 1
    runtime=$(ubs24pube_runtime) || return 1; path=$(ubs24pube_preclone_intent_path) || return 1
    ubs24pube_public_runtime_shape || return 1
    [[ -f $path && ! -L $path ]] || return 1
    mapfile -t rows < "$path" || return 1
    (( ${#rows[@]} == 14 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx=$(ubs24pube_sha "$runtime/transaction") || return 1
    prepare=$(ubs24pube_sha /run/mvc-controller/prepare-intent) || return 1
    commit=$(ubs24pube_sha /run/mvc-controller/commit-attempt) || return 1
    [[ ${rows[0]} == ubs-v240-public-preclone-intent-v1 &&
       ${rows[1]} == state=name-absent-bound-before-nm-clone-write &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" &&
       ${rows[6]} == "transaction=$tx" && ${rows[7]} == "controller_prepare=$prepare" &&
       ${rows[8]} == "controller_commit=$commit" && ${rows[9]} == source_uuid=* &&
       ${rows[10]} == source_sha=* && ${rows[11]} == clone_name=* &&
       ${rows[12]} == underlay=* && ${rows[13]} == nm_owner=* ]] || return 1
    UBS24PUBE_SOURCE_UUID=${rows[9]#source_uuid=}
    source_sha=${rows[10]#source_sha=}
    UBS24PUBE_PRECLONE_NAME=${rows[11]#clone_name=}
    UBS24PUBE_UNDERLAY=${rows[12]#underlay=}
    UBS24PUBE_NM_OWNER=${rows[13]#nm_owner=}
    [[ $source_sha =~ ^[0-9a-f]{64}$ &&
       $UBS24PUBE_PRECLONE_NAME =~ ^mvc-prepared-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$ ]] || return 1
    UBS24PUBE_PRECLONE_TOKEN=${BASH_REMATCH[1]}
    ubs24ga_uuid_valid "$UBS24PUBE_SOURCE_UUID" && ubs24ga_uuid_valid "$UBS24PUBE_PRECLONE_TOKEN" &&
      ubs24gb1_valid_ifname "$UBS24PUBE_UNDERLAY" && ubs24gc7_nm_owner_valid "$UBS24PUBE_NM_OWNER" || return 1
    if [[ ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        [[ $UBS24PUBE_SOURCE_UUID == "${UBS24PUBC_OVPN_UUID:-}" && $UBS24PUBE_UNDERLAY == "${UBS24PUBC_UNDERLAY:-}" ]] || return 1
    else
        [[ $UBS24PUBE_SOURCE_UUID == "${UBS24PUBD_OVPN_SOURCE_UUID:-}" && $UBS24PUBE_UNDERLAY == "${UBS24PUBD_UNDERLAY:-}" ]] || return 1
    fi
    local UBS24S_LOCK_HELD=1
    ubs24op_session_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24PUBE_NM_OWNER" ]] || return 1
    tmp=$(umask 077; mktemp /run/mvc-pube-source.XXXXXXXX) || return 1
    chmod 600 -- "$tmp" || { rm -f -- "$tmp"; return 1; }
    if ! ubs24ga3_capture_source "$UBS24PUBE_SOURCE_UUID" "$tmp"; then rm -f -- "$tmp"; return 1; fi
    current_sha=$(ubs24op_settings_fingerprint "$tmp") || { rm -f -- "$tmp"; return 1; }
    rm -f -- "$tmp" || return 1
    [[ $current_sha == "$source_sha" ]]
}

ubs24pube_preclone_binding_valid() {
    (( $# == 0 )) || return 1
    local path boot pre; local -a rows=()
    path=$(ubs24pube_preclone_binding_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:400:1' ]] || return 1
    mapfile -t rows < "$path" || return 1; (( ${#rows[@]} == 8 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)") || return 1
    [[ ${rows[0]} == ubs-v240-public-preclone-binding-v1 && ${rows[1]} == state=raw-clone-uuid-observed-before-hardening &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "preclone=$pre" && ${rows[4]} == "source_uuid=$UBS24PUBE_SOURCE_UUID" &&
       ${rows[5]} == "clone_name=$UBS24PUBE_PRECLONE_NAME" && ${rows[6]} == clone_uuid=* && ${rows[7]} == "nm_owner=$UBS24PUBE_NM_OWNER" ]] || return 1
    UBS24PUBE_PRECLONE_UUID=${rows[6]#clone_uuid=}
    ubs24ga_uuid_valid "$UBS24PUBE_PRECLONE_UUID" && [[ $UBS24PUBE_PRECLONE_UUID != "$UBS24PUBE_SOURCE_UUID" ]]
}

ubs24pube_preclone_guard_state_locked() {
    (( $# == 0 )) || return 1
    local dir entries scratch a b before after state=unknown
    ubs24pube_preclone_intent_valid || return 1
    [[ ! -e /run/mvc-activation && ! -L /run/mvc-activation &&
       ! -e /run/mvc-output-transition && ! -L /run/mvc-output-transition &&
       ! -e /run/mvc-wireguard && ! -L /run/mvc-wireguard ]] || return 1
    ubs24gb4_no_active_vpn || return 1
    dir=$(ubs24gb2_runtime) || return 1
    ubs24gb2_records_valid || return 1
    entries=$(find "$dir" -mindepth 1 -maxdepth 1 -print | wc -l) || return 1
    (( entries == 8 || entries == 10 )) || return 1
    if (( entries == 10 )); then ubs24gc3_transition_payload_valid "$dir" || return 1; fi
    scratch=$(umask 077; mktemp -d /run/mvc-pube-preclone-guard.XXXXXXXX) || return 1
    a=$scratch/a.json; b=$scratch/b.json
    if ! ubs24gb1_capture_nft "$a" || ! ubs24gb1_capture_nft "$b" || ! cmp -s -- "$a" "$b"; then rm -rf -- "$scratch"; return 1; fi
    before=$(ubs24gb2_foreign_projection "$dir/prestate.json") || { rm -rf -- "$scratch"; return 1; }
    after=$(ubs24gb2_foreign_projection "$a") || { rm -rf -- "$scratch"; return 1; }
    [[ $before == "$after" ]] || { rm -rf -- "$scratch"; return 1; }
    if ubs24gb2_poststate_valid "$a" "$UBS24PUBE_UNDERLAY" && ubs24gb2_poststate_valid "$b" "$UBS24PUBE_UNDERLAY"; then
        state=b2
    elif (( entries == 10 )) && ubs24gc1_postshape_observation "$a" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" &&
         ubs24gc1_postshape_observation "$b" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT"; then
        state=c1
    else
        rm -rf -- "$scratch"; return 1
    fi
    rm -rf -- "$scratch" || return 1
    UBS24PUBE_PRECLONE_GUARD=$state
}

ubs24pube_preclone_topology_witness_dir() {
    (( $# == 1 )) || return 1
    local dir=$1 scratch links r4 r6 ok=1
    [[ -d $dir && ! -L $dir ]] || return 1
    scratch=$(umask 077; mktemp -d /run/mvc-pube-preclone-topo.XXXXXXXX) || return 1
    links=$scratch/links.json; r4=$scratch/routes4.json; r6=$scratch/routes6.json
    ubs24gb1_capture_links "$links" && ubs24gb1_capture_routes4 "$r4" && ubs24gb1_capture_routes6 "$r6" &&
      cmp -s -- "$links" "$dir/links.json" && cmp -s -- "$r4" "$dir/routes4.json" && cmp -s -- "$r6" "$dir/routes6.json" || ok=0
    rm -rf -- "$scratch" || ok=0
    (( ok == 1 ))
}

ubs24pube_preclone_name_lookup() {
    (( $# == 0 )) || return 1
    local uuid='' obj unsaved type tmp inv count names line name_count=0
    # Once A1 observed a UUID, use that immutable binding because A2 may rename
    # connection.id to vpnks-ovpn. Before that binding exists, only the random
    # prechecked-absent raw name can identify an ambiguous clone command.
    if [[ -e $(ubs24pube_preclone_binding_path) || -L $(ubs24pube_preclone_binding_path) ]]; then
        ubs24pube_preclone_binding_valid || return 1
        uuid=$UBS24PUBE_PRECLONE_UUID
        UBS24GC23T_SOURCE_UUID=$UBS24PUBE_SOURCE_UUID
        inv=$(umask 077; mktemp /run/mvc-pube-inv.XXXXXXXX) || return 1; chmod 600 -- "$inv" || { rm -f -- "$inv"; return 1; }
        if ! ubs24gc23t_uuid_inventory "$inv"; then rm -f -- "$inv"; return 1; fi
        count=$(ubs24gc23t_clone_inventory_count "$inv" "$uuid") || { rm -f -- "$inv"; return 1; }
        rm -f -- "$inv" || return 1
        (( count <= 1 )) || return 1
        if (( count == 0 )); then UBS24PUBE_PRECLONE_PRESENCE=absent; printf '%s\n' absent; return 0; fi
    else
        names=$(LC_ALL=C nmcli --wait 10 --terse --fields NAME connection show </dev/null) || return 1
        while IFS= read -r line || [[ -n $line ]]; do [[ $line == "$UBS24PUBE_PRECLONE_NAME" ]] && name_count=$((name_count+1)); done <<< "$names"
        (( name_count <= 1 )) || return 1
        if (( name_count == 0 )); then UBS24PUBE_PRECLONE_UUID=; UBS24PUBE_PRECLONE_PRESENCE=absent; printf '%s\n' absent; return 0; fi
        uuid=$(LC_ALL=C nmcli --wait 10 -g connection.uuid connection show "$UBS24PUBE_PRECLONE_NAME" </dev/null 2>/dev/null) || return 1
        [[ $uuid != *$'\n'* && $uuid != "$UBS24PUBE_SOURCE_UUID" ]] && ubs24ga_uuid_valid "$uuid" || return 1
        UBS24PUBE_PRECLONE_UUID=$uuid
    fi
    type=$(LC_ALL=C nmcli --wait 10 -g connection.type connection show uuid "$uuid" </dev/null 2>/dev/null) || return 1
    [[ $type == vpn ]] || return 1
    obj=$(ubs24g_call_readonly org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/Settings org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || return 1
    [[ $obj =~ ^o\ \"(/org/freedesktop/NetworkManager/Settings/[0-9]+)\"$ ]] || return 1
    obj=${BASH_REMATCH[1]}
    unsaved=$(ubs24g_get_property org.freedesktop.NetworkManager "$obj" org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || return 1
    [[ $unsaved == 'b true' ]] || return 1
    tmp=$(umask 077; mktemp /run/mvc-pube-clone.XXXXXXXX) || return 1; chmod 600 -- "$tmp" || { rm -f -- "$tmp"; return 1; }
    if ! ubs24gs_capture_settings "$obj" "$tmp"; then rm -f -- "$tmp"; return 1; fi
    jq -e --arg uuid "$uuid" --arg raw "$UBS24PUBE_PRECLONE_NAME" '
      .type=="a{sa{sv}}" and (.data|type=="array" and length==1) and
      .data[0].connection.uuid=={type:"s",data:$uuid} and .data[0].connection.type=={type:"s",data:"vpn"} and
      ((.data[0].connection.id.data==$raw) or (.data[0].connection.id.data=="vpnks-ovpn")) and
      .data[0].vpn["service-type"]=={type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
      (.data[0].vpn|has("secrets")|not)' "$tmp" >/dev/null 2>&1 || { rm -f -- "$tmp"; return 1; }
    rm -f -- "$tmp" || return 1
    UBS24PUBE_PRECLONE_UUID=$uuid
    UBS24PUBE_PRECLONE_PRESENCE=present
    printf '%s\n' present
}
ubs24pube_preclone_delete_intent_valid() {
    (( $# == 0 )) || return 1
    local path boot pre; local -a rows=()
    path=$(ubs24pube_preclone_delete_intent_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:400:1' ]] || return 1
    mapfile -t rows < "$path" || return 1; (( ${#rows[@]} == 8 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)") || return 1
    [[ ${rows[0]} == ubs-v240-public-preclone-delete-v1 && ${rows[1]} == state=delete-attempt-authorized-once &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "preclone=$pre" && ${rows[4]} == "source=$UBS24PUBE_SOURCE_UUID" &&
       ${rows[5]} == "clone_name=$UBS24PUBE_PRECLONE_NAME" && ${rows[6]} == clone_uuid=* && ${rows[7]} == "nm_owner=$UBS24PUBE_NM_OWNER" ]] || return 1
    UBS24PUBE_PRECLONE_UUID=${rows[6]#clone_uuid=}; ubs24ga_uuid_valid "$UBS24PUBE_PRECLONE_UUID"
}

ubs24pube_preclone_publish_delete_intent() {
    (( $# == 0 )) || return 1
    local path tmp boot pre
    path=$(ubs24pube_preclone_delete_intent_path) || return 1
    [[ -n ${UBS24PUBE_PRECLONE_UUID:-} && ! -e $path && ! -L $path ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)") || return 1
    tmp="$(ubs24pube_runtime)/.preclone-delete.tmp"; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-preclone-delete-v1 state=delete-attempt-authorized-once "boot=$boot" "preclone=$pre" \
      "source=$UBS24PUBE_SOURCE_UUID" "clone_name=$UBS24PUBE_PRECLONE_NAME" "clone_uuid=$UBS24PUBE_PRECLONE_UUID" "nm_owner=$UBS24PUBE_NM_OWNER" > "$tmp" || return 1
    mv -T -- "$tmp" "$path" || return 1; ubs24pube_preclone_delete_intent_valid
}

ubs24pube_preclone_delete_owned_clone() {
    (( $# == 0 )) || return 1
    local state
    ubs24pube_preclone_name_lookup >/dev/null || return 1
    state=$UBS24PUBE_PRECLONE_PRESENCE
    if [[ $state == absent ]]; then return 0; fi
    [[ $state == present && -n ${UBS24PUBE_PRECLONE_UUID:-} ]] || return 1
    if [[ -e $(ubs24pube_preclone_delete_intent_path) || -L $(ubs24pube_preclone_delete_intent_path) ]]; then
        ubs24pube_preclone_delete_intent_valid || return 1
        # At-most-once delete: if a prior process published intent and the clone
        # is still present, do not guess whether NM received the delete request.
        return 1
    fi
    ubs24pube_preclone_publish_delete_intent || return 1
    LC_ALL=C nmcli --wait 35 --colors no --terse connection delete uuid "$UBS24PUBE_PRECLONE_UUID" </dev/null >/dev/null 2>&1 || true
    [[ $(ubs24pube_preclone_name_lookup) == absent ]]
}

ubs24pube_preclone_release_intent_valid() {
    (( $# == 0 )) || return 1
    local batch intent boot pre batch_sha; local -a rows=()
    batch=$(ubs24pube_preclone_release_batch_path); intent=$(ubs24pube_preclone_release_intent_path) || return 1
    [[ -f $batch && ! -L $batch && -f $intent && ! -L $intent ]] || return 1
    ubs24gc23t_release_batch_valid "$batch" || return 1
    mapfile -t rows < "$intent" || return 1; (( ${#rows[@]} == 8 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)"); batch_sha=$(ubs24pube_sha "$batch") || return 1
    [[ ${rows[0]} == ubs-v240-public-preclone-release-v1 && ${rows[1]} == state=owned-b4-delete-observation-driven &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "preclone=$pre" && ${rows[4]} == "batch=$batch_sha" &&
       ${rows[5]} == "source=$UBS24PUBE_SOURCE_UUID" && ${rows[6]} == "clone_name=$UBS24PUBE_PRECLONE_NAME" &&
       ( ${rows[7]} == guard=b2 || ${rows[7]} == guard=c1 ) ]]
}

ubs24pube_preclone_publish_release_intent() {
    (( $# == 0 )) || return 1
    local batch intent tmp boot pre batch_sha
    batch=$(ubs24pube_preclone_release_batch_path); intent=$(ubs24pube_preclone_release_intent_path) || return 1
    [[ ! -e $intent && ! -L $intent ]] || return 1
    ubs24gb4_no_active_vpn && [[ $(ubs24pube_preclone_name_lookup) == absent ]] || return 1
    ubs24pube_preclone_guard_state_locked || return 1
    # The release batch is published before its authorizing intent. If a process
    # dies in that narrow publication gap, accept only the exact deterministic
    # C23T release batch and finish publishing the intent; never regenerate over
    # an unknown existing file.
    if [[ -e $batch || -L $batch ]]; then
        [[ -f $batch && ! -L $batch && $(stat -c '%u:%a:%h' -- "$batch") == '0:400:1' ]] || return 1
        ubs24gc23t_release_batch_valid "$batch" || return 1
    else
        tmp="$(ubs24pube_runtime)/.preclone-release.tmp"; : > "$tmp" || return 1; chmod 600 -- "$tmp" || return 1
        ubs24gc23t_release_batch_write "$tmp" || return 1; nft --check --file "$tmp" >/dev/null 2>&1 || return 1
        chmod 400 -- "$tmp" || return 1; mv -T -- "$tmp" "$batch" || return 1
    fi
    boot=$(cat /proc/sys/kernel/random/boot_id); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)"); batch_sha=$(ubs24pube_sha "$batch") || return 1
    tmp="$(ubs24pube_runtime)/.preclone-release-intent.tmp"; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-preclone-release-v1 state=owned-b4-delete-observation-driven "boot=$boot" "preclone=$pre" "batch=$batch_sha" \
      "source=$UBS24PUBE_SOURCE_UUID" "clone_name=$UBS24PUBE_PRECLONE_NAME" "guard=$UBS24PUBE_PRECLONE_GUARD" > "$tmp" || return 1
    mv -T -- "$tmp" "$intent" || return 1; ubs24pube_preclone_release_intent_valid
}

ubs24pube_preclone_release_guard() {
    (( $# == 0 )) || return 1
    local intent batch
    intent=$(ubs24pube_preclone_release_intent_path); batch=$(ubs24pube_preclone_release_batch_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_preclone_publish_release_intent || return 1; fi
    ubs24pube_preclone_release_intent_valid || return 1
    if ! ubs24pube_owned_tables_absent_now; then
        ubs24gb4_no_active_vpn && [[ $(ubs24pube_preclone_name_lookup) == absent ]] || return 1
        ubs24pube_preclone_guard_state_locked || return 1
        nft --file "$batch" >/dev/null 2>&1 || return 1
    fi
    ubs24gc23t_release_post_witness && ubs24pube_preclone_topology_witness_dir /run/mvc-controller
}

ubs24pube_preclone_retire_intent_valid() {
    (( $# == 0 )) || return 1
    local runtime path boot userns netns mntns tx pre release token entries transition; local -a rows=()
    runtime=$(ubs24pube_runtime); path=$(ubs24pube_preclone_retire_intent_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:400:1' ]] || return 1
    mapfile -t rows < "$path" || return 1; (( ${#rows[@]} == 15 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); userns=$(readlink /proc/self/ns/user); netns=$(readlink /proc/self/ns/net); mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx=$(ubs24pube_sha "$runtime/transaction"); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)"); release=$(ubs24pube_sha "$(ubs24pube_preclone_release_intent_path)") || return 1
    [[ ${rows[0]} == ubs-v240-public-preclone-retire-v1 && ${rows[1]} == state=network-clean-runtime-retirement-pending &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" && ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" &&
       ${rows[6]} == "transaction=$tx" && ${rows[7]} == "preclone=$pre" && ${rows[8]} == "release=$release" &&
       ${rows[9]} == source=* && ${rows[10]} == clone_name=* && ${rows[11]} == token=* && ${rows[12]} == controller_entries=* &&
       ${rows[13]} == transition=* && ${rows[14]} == nm_owner=* ]] || return 1
    UBS24PUBE_SOURCE_UUID=${rows[9]#source=}; UBS24PUBE_PRECLONE_NAME=${rows[10]#clone_name=}; token=${rows[11]#token=}; entries=${rows[12]#controller_entries=}; transition=${rows[13]#transition=}; UBS24PUBE_NM_OWNER=${rows[14]#nm_owner=}
    [[ $UBS24PUBE_PRECLONE_NAME == "mvc-prepared-$token" && ( $entries == 8 || $entries == 10 ) ]] || return 1
    ubs24ga_uuid_valid "$UBS24PUBE_SOURCE_UUID" && ubs24ga_uuid_valid "$token" && ubs24gc7_nm_owner_valid "$UBS24PUBE_NM_OWNER" || return 1
    UBS24PUBE_PRECLONE_TOKEN=$token; UBS24PUBE_PRECLONE_CONTROLLER_ENTRIES=$entries; UBS24PUBE_PRECLONE_TRANSITION_SHA=$transition
    [[ $entries == 8 && $transition == - || $entries == 10 && $transition =~ ^[0-9a-f]{64}$ ]]
}

ubs24pube_preclone_publish_retire_intent() {
    (( $# == 0 )) || return 1
    local runtime path tmp boot userns netns mntns tx pre release entries transition='-'
    runtime=$(ubs24pube_runtime); path=$(ubs24pube_preclone_retire_intent_path) || return 1
    [[ ! -e $path && ! -L $path ]] || return 1
    ubs24gb4_no_active_vpn && [[ $(ubs24pube_preclone_name_lookup) == absent ]] && ubs24pube_owned_tables_absent_now &&
      ubs24gc23t_release_post_witness && ubs24pube_preclone_topology_witness_dir /run/mvc-controller || return 1
    entries=$(find /run/mvc-controller -mindepth 1 -maxdepth 1 -print | wc -l) || return 1
    if (( entries == 10 )); then transition=$(ubs24pube_sha /run/mvc-controller/transition-attempt) || return 1; elif (( entries != 8 )); then return 1; fi
    boot=$(cat /proc/sys/kernel/random/boot_id); userns=$(readlink /proc/self/ns/user); netns=$(readlink /proc/self/ns/net); mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx=$(ubs24pube_sha "$runtime/transaction"); pre=$(ubs24pube_sha "$(ubs24pube_preclone_intent_path)"); release=$(ubs24pube_sha "$(ubs24pube_preclone_release_intent_path)") || return 1
    tmp=$runtime/.preclone-retire.tmp; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-preclone-retire-v1 state=network-clean-runtime-retirement-pending \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" "transaction=$tx" "preclone=$pre" "release=$release" \
      "source=$UBS24PUBE_SOURCE_UUID" "clone_name=$UBS24PUBE_PRECLONE_NAME" "token=$UBS24PUBE_PRECLONE_TOKEN" "controller_entries=$entries" "transition=$transition" \
      "nm_owner=$UBS24PUBE_NM_OWNER" > "$tmp" || return 1
    mv -T -- "$tmp" "$path" || return 1; ubs24pube_preclone_retire_intent_valid
}

ubs24pube_preclone_controller_dir_valid() {
    (( $# == 1 )) || return 1
    local dir=$1 entries=$UBS24PUBE_PRECLONE_CONTROLLER_ENTRIES file mode
    [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir") == '0:700:2' ]] || return 1
    [[ $(find "$dir" -mindepth 1 -maxdepth 1 -print | wc -l) == "$entries" ]] || return 1
    for file in controller.lock prestate.json batch.nft links.json routes4.json routes6.json prepare-intent commit-attempt; do
        [[ -f $dir/$file && ! -L $dir/$file ]] || return 1; mode=400; [[ $file == controller.lock ]] && mode=600
        [[ $(stat -c '%u:%a:%h' -- "$dir/$file") == "0:$mode:1" ]] || return 1
    done
    if [[ $entries == 10 ]]; then
        for file in transition.nft transition-attempt; do [[ -f $dir/$file && ! -L $dir/$file && $(stat -c '%u:%a:%h' -- "$dir/$file") == '0:400:1' ]] || return 1; done
        [[ $(ubs24pube_sha "$dir/transition-attempt") == "$UBS24PUBE_PRECLONE_TRANSITION_SHA" ]] || return 1
    fi
}

ubs24pube_preclone_retire_archive_continue() {
    (( $# == 0 )) || return 1
    local runtime root archive controller
    runtime=$(ubs24pube_runtime) || return 1
    ubs24pube_preclone_retire_intent_valid || return 1
    ubs24gb4_no_active_vpn && ubs24pube_owned_tables_absent_now || return 1
    [[ ! -e /run/mvc-activation && ! -L /run/mvc-activation && ! -e /run/mvc-output-transition && ! -L /run/mvc-output-transition &&
       ! -e /run/mvc-disconnect && ! -L /run/mvc-disconnect && ! -e /run/mvc-completion && ! -L /run/mvc-completion &&
       ! -e /run/mvc-wireguard && ! -L /run/mvc-wireguard ]] || return 1
    [[ $(ubs24pube_preclone_name_lookup) == absent ]] || return 1
    root=$(ubs24pube_preclone_archive_root); archive=$root/$UBS24PUBE_PRECLONE_TOKEN; controller=/run/mvc-controller || return 1
    if [[ ! -e $root && ! -L $root ]]; then (umask 077; mkdir -m 700 -- "$root") || return 1; fi
    [[ -d $root && ! -L $root && $(stat -c '%u:%a' -- "$root") == '0:700' ]] || return 1
    if [[ ! -e $archive && ! -L $archive ]]; then (umask 077; mkdir -m 700 -- "$archive") || return 1; fi
    [[ -d $archive && ! -L $archive && $(stat -c '%u:%a' -- "$archive") == '0:700' ]] || return 1
    if [[ -e $controller || -L $controller ]]; then
        [[ ! -e $archive/controller && ! -L $archive/controller ]] || return 1
        ubs24pube_preclone_controller_dir_valid "$controller" && ubs24pube_preclone_topology_witness_dir "$controller" || return 1
        mv -T -- "$controller" "$archive/controller" || return 1
    else
        ubs24pube_preclone_controller_dir_valid "$archive/controller" && ubs24pube_preclone_topology_witness_dir "$archive/controller" || return 1
    fi
    [[ -d $runtime && ! -L $runtime && ! -e $archive/public-session && ! -L $archive/public-session ]] || return 1
    mv -T -- "$runtime" "$archive/public-session" || return 1
    [[ -d $archive/public-session && ! -L $archive/public-session && ! -e $runtime && ! -L $runtime && ! -e $controller && ! -L $controller ]]
}

ubs24pube_reconcile_pre_c7_locked() {
    (( $# == 0 )) || return 1
    UBS24PUBE_STAGE=authenticating-pre-c7-clone-intent
    ubs24pube_preclone_intent_valid && ! ubs24pube_c7_intent_present || return 1

    local release_intent retire_intent
    release_intent=$(ubs24pube_preclone_release_intent_path) || return 1
    retire_intent=$(ubs24pube_preclone_retire_intent_path) || return 1

    # Before release intent exists, exact B2/C1 observation is still required.
    # Once release intent is durable, its batch may already have taken effect;
    # resume from current observation rather than demanding the historical guard.
    if [[ ! -e $release_intent && ! -L $release_intent ]]; then
        UBS24PUBE_STAGE=observing-pre-c7-guard-and-clone
        ubs24pube_preclone_guard_state_locked || return 1
        UBS24PUBE_STAGE=deleting-pre-c7-owned-clone-if-present
        ubs24pube_preclone_delete_owned_clone || return 1
    else
        UBS24PUBE_STAGE=resuming-pre-c7-release-after-durable-intent
        ubs24pube_preclone_release_intent_valid || return 1
        [[ $(ubs24pube_preclone_name_lookup) == absent ]] || return 1
    fi

    UBS24PUBE_STAGE=releasing-pre-c7-owned-guard
    ubs24pube_preclone_release_guard || return 1
    UBS24PUBE_STAGE=retiring-pre-c7-runtime
    if [[ ! -e $retire_intent && ! -L $retire_intent ]]; then ubs24pube_preclone_publish_retire_intent || return 1; fi
    ubs24pube_preclone_retire_intent_valid || return 1
    ubs24gb2_close || return 1
    ubs24pube_preclone_retire_archive_continue || return 1
    UBS24PUBE_STAGE=pre-c7-clean-baseline-restored
}

ubs24pube_plan_valid() {
    (( $# == 0 )) || return 1
    local runtime plan boot userns netns mntns tx c1 c7 c13 expected_c13
    local -a rows=()
    runtime=$(ubs24pube_runtime) || return 1; plan=$(ubs24pube_plan_path) || return 1
    ubs24pube_public_runtime_shape || return 1
    [[ -f $plan && ! -L $plan ]] || return 1
    mapfile -t rows < "$plan" || return 1
    (( ${#rows[@]} == 14 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx=$(ubs24pube_sha "$runtime/transaction") || return 1
    c1=$(ubs24pube_sha /run/mvc-controller/transition-attempt) || return 1
    c7=$(ubs24pube_sha /run/mvc-activation/attempt) || return 1
    expected_c13='-'
    if [[ -e /run/mvc-output-transition || -L /run/mvc-output-transition ]]; then
        [[ -d /run/mvc-output-transition && ! -L /run/mvc-output-transition &&
           -f /run/mvc-output-transition/attempt && ! -L /run/mvc-output-transition/attempt &&
           $(stat -c '%u:%a:%h' -- /run/mvc-output-transition 2>/dev/null) == '0:700:2' &&
           $(stat -c '%u:%a:%h' -- /run/mvc-output-transition/attempt 2>/dev/null) == '0:400:1' ]] || return 1
        expected_c13=$(ubs24pube_sha /run/mvc-output-transition/attempt) || return 1
    fi
    [[ ${rows[0]} == ubs-v240-public-early-openvpn-cleanup-v1 &&
       ${rows[1]} == state=cleanup-authorized-observation-driven &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" &&
       ${rows[6]} == "transaction=$tx" && ${rows[7]} == "c1=$c1" &&
       ${rows[8]} == "c7=$c7" && ${rows[9]} == "c13=$expected_c13" &&
       ${rows[10]} == "source=$UBS24PUBE_SOURCE_UUID" &&
       ${rows[11]} == "clone=$UBS24PUBE_CLONE_UUID" &&
       ${rows[12]} == "underlay=$UBS24PUBE_UNDERLAY" &&
       ${rows[13]} == "nm_owner=$UBS24PUBE_NM_OWNER" ]] || return 1
    if [[ $expected_c13 == '-' ]]; then
        UBS24PUBE_C13_PRESENT=no
        [[ ! -e $(ubs24pube_handback_batch_path) && ! -L $(ubs24pube_handback_batch_path) &&
           ! -e $(ubs24pube_handback_intent_path) && ! -L $(ubs24pube_handback_intent_path) ]] || return 1
    else
        UBS24PUBE_C13_PRESENT=yes
    fi
}

ubs24pube_publish_plan() {
    (( $# == 0 )) || return 1
    local runtime plan tmp boot userns netns mntns tx c1 c7 c13='-'
    runtime=$(ubs24pube_runtime) || return 1; plan=$(ubs24pube_plan_path) || return 1
    ubs24pube_rehydrate_c7_locked && ubs24pube_capture_guard_state || return 1
    [[ ! -e $plan && ! -L $plan ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx=$(ubs24pube_sha "$runtime/transaction") || return 1
    c1=$(ubs24pube_sha /run/mvc-controller/transition-attempt) || return 1
    c7=$(ubs24pube_sha /run/mvc-activation/attempt) || return 1
    if [[ $UBS24PUBE_C13_PRESENT == yes ]]; then c13=$(ubs24pube_sha /run/mvc-output-transition/attempt) || return 1; fi
    tmp=$runtime/.early-plan.tmp
    : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' \
      ubs-v240-public-early-openvpn-cleanup-v1 \
      state=cleanup-authorized-observation-driven \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "transaction=$tx" "c1=$c1" "c7=$c7" "c13=$c13" \
      "source=$UBS24PUBE_SOURCE_UUID" "clone=$UBS24PUBE_CLONE_UUID" \
      "underlay=$UBS24PUBE_UNDERLAY" "nm_owner=$UBS24PUBE_NM_OWNER" > "$tmp" || return 1
    mv -T -- "$tmp" "$plan" || return 1
    ubs24pube_plan_valid
}

ubs24pube_prepare_plan_locked() {
    (( $# == 0 )) || return 1
    ubs24pube_rehydrate_c7_locked || return 1
    local plan; plan=$(ubs24pube_plan_path) || return 1
    if [[ -e $plan || -L $plan ]]; then
        ubs24pube_plan_valid || return 1
        # Reconstruct C13-bound tunnel fields if C13 belongs to the plan.
        [[ $UBS24PUBE_C13_PRESENT == no ]] || ubs24gc15_load_bound_intent || return 1
        return 0
    fi
    ubs24pube_publish_plan
}

ubs24pube_guard_state_now() {
    (( $# == 0 )) || return 1
    if [[ $UBS24PUBE_C13_PRESENT == yes ]]; then
        local scratch a b c1=0 c11=0
        scratch=$(umask 077; mktemp -d /run/mvc-pube-now.XXXXXXXX) || return 1
        a=$scratch/a.json; b=$scratch/b.json
        if ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" && cmp -s -- "$a" "$b"; then
            ubs24gc19_kernel_witness c1 "$a" "$b" && c1=1
            ubs24gc19_kernel_witness c11 "$a" "$b" && c11=1
        fi
        rm -f -- "$a" "$b" || { rmdir -- "$scratch" 2>/dev/null || true; return 1; }
        rmdir -- "$scratch" || return 1
        (( c1 + c11 == 1 )) || return 1
        (( c11 == 1 )) && printf '%s\n' c11 || printf '%s\n' c1
    else
        ubs24gc5_guard_witness && printf '%s\n' c1
    fi
}

ubs24pube_publish_handback_intent() {
    (( $# == 0 )) || return 1
    [[ $UBS24PUBE_C13_PRESENT == yes ]] || return 1
    local runtime plan batch intent tmp boot plan_sha batch_sha
    runtime=$(ubs24pube_runtime); plan=$(ubs24pube_plan_path); batch=$(ubs24pube_handback_batch_path); intent=$(ubs24pube_handback_intent_path) || return 1
    [[ ! -e $batch && ! -L $batch && ! -e $intent && ! -L $intent ]] || return 1
    tmp=$runtime/.early-handback.tmp; : > "$tmp" || return 1; chmod 600 -- "$tmp" || return 1
    ubs24gc19_write_c1_handback "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$tmp" || return 1
    nft --check --file "$tmp" >/dev/null 2>&1 || return 1
    chmod 400 -- "$tmp" || return 1; mv -T -- "$tmp" "$batch" || return 1
    plan_sha=$(ubs24pube_sha "$plan") || return 1; batch_sha=$(ubs24pube_sha "$batch") || return 1; boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    tmp=$runtime/.early-handback-intent.tmp; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-early-handback-v1 state=c11-to-c1-observation-driven "boot=$boot" "plan=$plan_sha" "batch=$batch_sha" "clone=$UBS24PUBE_CLONE_UUID" > "$tmp" || return 1
    mv -T -- "$tmp" "$intent" || return 1
}

ubs24pube_handback_intent_valid() {
    (( $# == 0 )) || return 1
    local plan batch intent boot plan_sha batch_sha; local -a rows=()
    plan=$(ubs24pube_plan_path); batch=$(ubs24pube_handback_batch_path); intent=$(ubs24pube_handback_intent_path) || return 1
    [[ -f $batch && ! -L $batch && -f $intent && ! -L $intent ]] || return 1
    mapfile -t rows < "$intent" || return 1; (( ${#rows[@]} == 6 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); plan_sha=$(ubs24pube_sha "$plan"); batch_sha=$(ubs24pube_sha "$batch") || return 1
    # Bind the immutable candidate hash and let nft's parser validate the
    # generated C1 handback syntax; this is not the three-table release batch.
    [[ ${rows[0]} == ubs-v240-public-early-handback-v1 && ${rows[1]} == state=c11-to-c1-observation-driven &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "plan=$plan_sha" && ${rows[4]} == "batch=$batch_sha" &&
       ${rows[5]} == "clone=$UBS24PUBE_CLONE_UUID" ]] && nft --check --file "$batch" >/dev/null 2>&1
}

ubs24pube_ensure_c1_guard() {
    (( $# == 0 )) || return 1
    local state intent batch
    state=$(ubs24pube_guard_state_now) || return 1
    [[ $state == c1 ]] && return 0
    [[ $state == c11 && $UBS24PUBE_C13_PRESENT == yes ]] || return 1
    intent=$(ubs24pube_handback_intent_path); batch=$(ubs24pube_handback_batch_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_publish_handback_intent || return 1; fi
    ubs24pube_handback_intent_valid || return 1
    # This cleanup transform is idempotent from an exact C11 source state.
    nft --file "$batch" >/dev/null 2>&1 || return 1
    [[ $(ubs24pube_guard_state_now) == c1 ]]
}

ubs24pube_publish_simple_intent() {
    (( $# == 2 )) || return 1
    local kind=$1 path=$2 runtime tmp boot plan_sha
    runtime=$(ubs24pube_runtime); plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)") || return 1
    [[ ! -e $path && ! -L $path ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    tmp=$runtime/.early-${kind}.tmp; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' "ubs-v240-public-early-${kind}-v1" state=observation-driven-cleanup "boot=$boot" "plan=$plan_sha" "source=$UBS24PUBE_SOURCE_UUID" "clone=$UBS24PUBE_CLONE_UUID" "nm_owner=$UBS24PUBE_NM_OWNER" > "$tmp" || return 1
    mv -T -- "$tmp" "$path" || return 1
}

ubs24pube_simple_intent_valid() {
    (( $# == 2 )) || return 1
    local kind=$1 path=$2 boot plan_sha; local -a rows=()
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:400:1' ]] || return 1
    mapfile -t rows < "$path" || return 1; (( ${#rows[@]} == 7 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)") || return 1
    [[ ${rows[0]} == "ubs-v240-public-early-${kind}-v1" && ${rows[1]} == state=observation-driven-cleanup &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "plan=$plan_sha" &&
       ${rows[4]} == "source=$UBS24PUBE_SOURCE_UUID" && ${rows[5]} == "clone=$UBS24PUBE_CLONE_UUID" &&
       ${rows[6]} == "nm_owner=$UBS24PUBE_NM_OWNER" ]]
}

ubs24pube_active_clone_state() {
    (( $# == 0 )) || return 1
    local rows line uuid type name dev clone_count=0 foreign=0 tun_count=0
    rows=$(LC_ALL=C nmcli --wait 10 --colors no --terse --fields UUID,TYPE,NAME,DEVICE connection show --active </dev/null) || return 1
    while IFS=: read -r uuid type name dev; do
        [[ -n $type ]] || continue
        case ${type,,} in
          vpn)
            if [[ $uuid == "$UBS24PUBE_CLONE_UUID" && $name == vpnks-ovpn ]]; then clone_count=$((clone_count+1)); else foreign=1; fi ;;
          tun)
            [[ $name == tun-vpnks && $dev == tun-vpnks ]] && tun_count=$((tun_count+1)) || foreign=1 ;;
          wireguard|tap|ppp) foreign=1 ;;
        esac
    done <<< "$rows"
    (( foreign == 0 && clone_count <= 1 && tun_count <= 1 )) || return 1
    if (( clone_count == 1 )); then printf '%s\n' active; elif (( tun_count == 0 )); then printf '%s\n' inactive; else return 1; fi
}

ubs24pube_converged_no_vpn_topology() {
    (( $# == 0 )) || return 1
    local i
    for ((i=1; i<=20; i++)); do
        if ubs24gb4_no_active_vpn && ubs24gc23t_b2_topology_witness; then return 0; fi
        (( i < 20 )) || break
        ubs24gc23t_convergence_pause || return 1
    done
    return 1
}

ubs24pube_stop_clone_if_needed() {
    (( $# == 0 )) || return 1
    local intent state
    intent=$(ubs24pube_stop_intent_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_publish_simple_intent stop "$intent" || return 1; fi
    ubs24pube_simple_intent_valid stop "$intent" || return 1
    state=$(ubs24pube_active_clone_state) || return 1
    if [[ $state == active ]]; then
        LC_ALL=C nmcli --wait 60 --colors no connection down uuid "$UBS24PUBE_CLONE_UUID" </dev/null >/dev/null 2>&1 || true
    fi
    ubs24pube_converged_no_vpn_topology
}

ubs24pube_clone_exact_or_absent() {
    (( $# == 0 )) || return 1
    UBS24GC23T_SOURCE_UUID=$UBS24PUBE_SOURCE_UUID
    if ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID"; then return 0; fi
    ubs24gc23t_clone_present "$UBS24PUBE_CLONE_UUID" || return 1
    UBS24GA3_PREPARED_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GA3_PREPARED_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_SOURCE_SHA256=$UBS24GC7_SOURCE_SHA
    UBS24GA3_DERIVATIVE_SHA256=$UBS24GC7_CLONE_SHA
    UBS24GA_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_STAGE=prepared-nonsecret-parity-only; UBS24GA3_AUTHORITY=none; UBS24GA2_STATE=quarantined-exact-nonsecret-settings-verified
    local UBS24S_LOCK_HELD=1
    ubs24gc5_prepared_profile_witness
}

ubs24pube_delete_clone_if_needed() {
    (( $# == 0 )) || return 1
    local intent
    ubs24pube_converged_no_vpn_topology || return 1
    UBS24GC23T_SOURCE_UUID=$UBS24PUBE_SOURCE_UUID
    if ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID"; then return 0; fi
    ubs24pube_clone_exact_or_absent || return 1
    intent=$(ubs24pube_clone_delete_intent_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_publish_simple_intent clone-delete "$intent" || return 1; fi
    ubs24pube_simple_intent_valid clone-delete "$intent" || return 1
    if ubs24gc23t_clone_present "$UBS24PUBE_CLONE_UUID"; then
        ubs24pube_clone_exact_or_absent || return 1
        ubs24gc23t_nm_delete "$UBS24PUBE_CLONE_UUID" || true
    fi
    ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID"
}

ubs24pube_publish_release_intent() {
    (( $# == 0 )) || return 1
    local runtime batch intent tmp boot plan_sha batch_sha
    runtime=$(ubs24pube_runtime); batch=$(ubs24pube_release_batch_path); intent=$(ubs24pube_release_intent_path) || return 1
    [[ ! -e $batch && ! -L $batch && ! -e $intent && ! -L $intent ]] || return 1
    ubs24pube_converged_no_vpn_topology && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID" && [[ $(ubs24pube_guard_state_now) == c1 ]] || return 1
    tmp=$runtime/.early-release.tmp; : > "$tmp" || return 1; chmod 600 -- "$tmp" || return 1
    ubs24gc23t_release_batch_write "$tmp" || return 1; nft --check --file "$tmp" >/dev/null 2>&1 || return 1
    chmod 400 -- "$tmp" || return 1; mv -T -- "$tmp" "$batch" || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)"); batch_sha=$(ubs24pube_sha "$batch") || return 1
    tmp=$runtime/.early-release-intent.tmp; : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-early-guard-release-v1 state=owned-b4-delete-observation-driven "boot=$boot" "plan=$plan_sha" "batch=$batch_sha" "clone=$UBS24PUBE_CLONE_UUID" > "$tmp" || return 1
    mv -T -- "$tmp" "$intent" || return 1
}

ubs24pube_release_intent_valid() {
    (( $# == 0 )) || return 1
    local batch intent boot plan_sha batch_sha; local -a rows=()
    batch=$(ubs24pube_release_batch_path); intent=$(ubs24pube_release_intent_path) || return 1
    [[ -f $batch && ! -L $batch && -f $intent && ! -L $intent ]] || return 1
    ubs24gc23t_release_batch_valid "$batch" || return 1
    mapfile -t rows < "$intent" || return 1; (( ${#rows[@]} == 6 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id); plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)"); batch_sha=$(ubs24pube_sha "$batch") || return 1
    [[ ${rows[0]} == ubs-v240-public-early-guard-release-v1 && ${rows[1]} == state=owned-b4-delete-observation-driven &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "plan=$plan_sha" && ${rows[4]} == "batch=$batch_sha" &&
       ${rows[5]} == "clone=$UBS24PUBE_CLONE_UUID" ]]
}

ubs24pube_owned_tables_absent_now() {
    (( $# == 0 )) || return 1
    local tmp; tmp=$(umask 077; mktemp /run/mvc-pube-nft.XXXXXXXX) || return 1
    chmod 600 -- "$tmp" || return 1
    local ok=1
    ubs24gb1_capture_nft "$tmp" && ubs24gc23t_owned_tables_absent "$tmp" || ok=0
    rm -f -- "$tmp" || ok=0
    (( ok == 1 ))
}

ubs24pube_release_guard() {
    (( $# == 0 )) || return 1
    local intent batch
    intent=$(ubs24pube_release_intent_path); batch=$(ubs24pube_release_batch_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_publish_release_intent || return 1; fi
    ubs24pube_release_intent_valid || return 1
    if ! ubs24pube_owned_tables_absent_now; then
        [[ $(ubs24pube_guard_state_now) == c1 ]] || return 1
        ubs24pube_converged_no_vpn_topology && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID" || return 1
        nft --file "$batch" >/dev/null 2>&1 || return 1
    fi
    ubs24gc23t_release_post_witness && ubs24gc23t_b2_topology_witness && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID"
}

ubs24pube_retire_intent_valid() {
    (( $# == 0 )) || return 1
    local runtime path boot userns netns mntns tx_sha plan_sha release_sha expected_source expected_underlay
    local -a rows=()
    runtime=$(ubs24pube_runtime) || return 1
    path=$(ubs24pube_retire_intent_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path" 2>/dev/null) == '0:400:1' ]] || return 1
    mapfile -t rows < "$path" || return 1
    (( ${#rows[@]} == 13 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx_sha=$(ubs24pube_sha "$runtime/transaction") || return 1
    plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)") || return 1
    release_sha=$(ubs24pube_sha "$(ubs24pube_release_intent_path)") || return 1
    [[ ${rows[0]} == ubs-v240-public-early-retire-v1 &&
       ${rows[1]} == state=network-clean-runtime-retirement-pending &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" && ${rows[5]} == "mntns=$mntns" &&
       ${rows[6]} == "transaction=$tx_sha" && ${rows[7]} == "plan=$plan_sha" &&
       ${rows[8]} == "release=$release_sha" && ${rows[9]} == source=* &&
       ${rows[10]} == clone=* && ${rows[11]} == underlay=* && ${rows[12]} == c13=* ]] || return 1
    UBS24PUBE_SOURCE_UUID=${rows[9]#source=}
    UBS24PUBE_CLONE_UUID=${rows[10]#clone=}
    UBS24PUBE_UNDERLAY=${rows[11]#underlay=}
    UBS24PUBE_C13_PRESENT=${rows[12]#c13=}
    ubs24ga_uuid_valid "$UBS24PUBE_SOURCE_UUID" && ubs24ga_uuid_valid "$UBS24PUBE_CLONE_UUID" &&
      ubs24gb1_valid_ifname "$UBS24PUBE_UNDERLAY" || return 1
    [[ $UBS24PUBE_C13_PRESENT == yes || $UBS24PUBE_C13_PRESENT == no ]] || return 1
    if [[ ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        expected_source=${UBS24PUBC_OVPN_UUID:-}; expected_underlay=${UBS24PUBC_UNDERLAY:-}
    elif [[ ${UBS24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]]; then
        expected_source=${UBS24PUBD_OVPN_SOURCE_UUID:-}; expected_underlay=${UBS24PUBD_UNDERLAY:-}
    else
        return 1
    fi
    [[ $UBS24PUBE_SOURCE_UUID == "$expected_source" && $UBS24PUBE_UNDERLAY == "$expected_underlay" ]] || return 1
    ubs24pube_release_intent_valid
}

ubs24pube_publish_retire_intent() {
    (( $# == 0 )) || return 1
    local runtime path tmp boot userns netns mntns tx_sha plan_sha release_sha
    runtime=$(ubs24pube_runtime) || return 1
    path=$(ubs24pube_retire_intent_path) || return 1
    [[ ! -e $path && ! -L $path ]] || return 1
    ubs24pube_release_intent_valid && ubs24gc23t_release_post_witness &&
      ubs24gc23t_b2_topology_witness && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID" &&
      ubs24pube_owned_tables_absent_now || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    tx_sha=$(ubs24pube_sha "$runtime/transaction") || return 1
    plan_sha=$(ubs24pube_sha "$(ubs24pube_plan_path)") || return 1
    release_sha=$(ubs24pube_sha "$(ubs24pube_release_intent_path)") || return 1
    tmp=$runtime/.early-retire-intent.tmp
    : > "$tmp" || return 1; chmod 400 -- "$tmp" || return 1
    printf '%s\n' ubs-v240-public-early-retire-v1 \
      state=network-clean-runtime-retirement-pending \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "transaction=$tx_sha" "plan=$plan_sha" "release=$release_sha" \
      "source=$UBS24PUBE_SOURCE_UUID" "clone=$UBS24PUBE_CLONE_UUID" \
      "underlay=$UBS24PUBE_UNDERLAY" "c13=$UBS24PUBE_C13_PRESENT" > "$tmp" || return 1
    mv -T -- "$tmp" "$path" || return 1
    ubs24pube_retire_intent_valid
}

ubs24pube_single_attempt_dir_valid() {
    (( $# == 2 )) || return 1
    local dir=$1 expected_sha=$2
    [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == '0:700:2' &&
       -f $dir/attempt && ! -L $dir/attempt && $(stat -c '%u:%a:%h' -- "$dir/attempt" 2>/dev/null) == '0:400:1' ]] || return 1
    local -a entries=()
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ $(ubs24pube_sha "$dir/attempt") == "$expected_sha" ]]
}

ubs24pube_controller_dir_valid_for_retire() {
    (( $# == 2 )) || return 1
    local dir=$1 expected_transition=$2 file mode
    [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == '0:700:2' ]] || return 1
    local -a entries=()
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 10 )) || return 1
    for file in controller.lock prestate.json batch.nft links.json routes4.json routes6.json prepare-intent commit-attempt transition.nft transition-attempt; do
        [[ -f $dir/$file && ! -L $dir/$file ]] || return 1
        mode=400; [[ $file == controller.lock ]] && mode=600
        [[ $(stat -c '%u:%a:%h' -- "$dir/$file" 2>/dev/null) == "0:$mode:1" ]] || return 1
    done
    [[ $(ubs24pube_sha "$dir/transition-attempt") == "$expected_transition" ]]
}

ubs24pube_retire_plan_hashes() {
    (( $# == 0 )) || return 1
    local plan; local -a rows=()
    plan=$(ubs24pube_plan_path) || return 1
    [[ -f $plan && ! -L $plan ]] || return 1
    mapfile -t rows < "$plan" || return 1
    (( ${#rows[@]} == 14 )) || return 1
    [[ ${rows[0]} == ubs-v240-public-early-openvpn-cleanup-v1 &&
       ${rows[1]} == state=cleanup-authorized-observation-driven &&
       ${rows[9]} == c13=* ]] || return 1
    UBS24PUBE_RETIRE_C1_SHA=${rows[7]#c1=}
    UBS24PUBE_RETIRE_C7_SHA=${rows[8]#c7=}
    UBS24PUBE_RETIRE_C13_SHA=${rows[9]#c13=}
    [[ $UBS24PUBE_RETIRE_C1_SHA =~ ^[0-9a-f]{64}$ && $UBS24PUBE_RETIRE_C7_SHA =~ ^[0-9a-f]{64}$ ]] || return 1
    if [[ $UBS24PUBE_C13_PRESENT == yes ]]; then
        [[ $UBS24PUBE_RETIRE_C13_SHA =~ ^[0-9a-f]{64}$ ]] || return 1
    else
        [[ $UBS24PUBE_RETIRE_C13_SHA == - ]] || return 1
    fi
}

ubs24pube_move_runtime_dir_once() {
    (( $# == 3 )) || return 1
    local src=$1 dst=$2 kind=$3
    if [[ -e $src || -L $src ]]; then
        [[ ! -e $dst && ! -L $dst ]] || return 1
        case $kind in
          controller) ubs24pube_controller_dir_valid_for_retire "$src" "$UBS24PUBE_RETIRE_C1_SHA" || return 1 ;;
          activation) ubs24pube_single_attempt_dir_valid "$src" "$UBS24PUBE_RETIRE_C7_SHA" || return 1 ;;
          output) ubs24pube_single_attempt_dir_valid "$src" "$UBS24PUBE_RETIRE_C13_SHA" || return 1 ;;
          *) return 1 ;;
        esac
        mv -T -- "$src" "$dst" || return 1
    else
        [[ -d $dst && ! -L $dst ]] || return 1
        case $kind in
          controller) ubs24pube_controller_dir_valid_for_retire "$dst" "$UBS24PUBE_RETIRE_C1_SHA" ;;
          activation) ubs24pube_single_attempt_dir_valid "$dst" "$UBS24PUBE_RETIRE_C7_SHA" ;;
          output) ubs24pube_single_attempt_dir_valid "$dst" "$UBS24PUBE_RETIRE_C13_SHA" ;;
          *) return 1 ;;
        esac
    fi
}

ubs24pube_retire_archive_continue() {
    (( $# == 0 )) || return 1
    local runtime root archive controller activation output
    runtime=$(ubs24pube_runtime) || return 1
    ubs24pube_retire_intent_valid && ubs24pube_retire_plan_hashes || return 1
    # The retirement intent was published only after exact B2 topology was
    # observed.  Continuation may run after the controller snapshot directory
    # has already been archived, so do not require that fixed path again.
    # No network mutation occurs after the retirement intent: re-observe only
    # the independently checkable safety poststate needed to retire journals.
    ubs24gb4_no_active_vpn && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID" &&
      ubs24pube_owned_tables_absent_now || return 1
    [[ ! -e /run/mvc-disconnect && ! -L /run/mvc-disconnect &&
       ! -e /run/mvc-completion && ! -L /run/mvc-completion &&
       ! -e /run/mvc-wireguard && ! -L /run/mvc-wireguard ]] || return 1
    root=$(ubs24pube_archive_root) || return 1
    archive=$root/$UBS24PUBE_CLONE_UUID
    if [[ ! -e $root && ! -L $root ]]; then (umask 077; mkdir -m 700 -- "$root") || return 1; fi
    [[ -d $root && ! -L $root && $(stat -c '%u:%a' -- "$root" 2>/dev/null) == '0:700' ]] || return 1
    if [[ ! -e $archive && ! -L $archive ]]; then (umask 077; mkdir -m 700 -- "$archive") || return 1; fi
    [[ -d $archive && ! -L $archive && $(stat -c '%u:%a' -- "$archive" 2>/dev/null) == '0:700' ]] || return 1
    controller=$(ubs24pube_controller_runtime); activation=$(ubs24pube_activation_runtime); output=$(ubs24pube_output_runtime) || return 1
    if [[ $UBS24PUBE_C13_PRESENT == yes ]]; then
        ubs24pube_move_runtime_dir_once "$output" "$archive/output-transition" output || return 1
    else
        [[ ! -e $output && ! -L $output && ! -e $archive/output-transition && ! -L $archive/output-transition ]] || return 1
    fi
    ubs24pube_move_runtime_dir_once "$activation" "$archive/activation" activation || return 1
    ubs24pube_move_runtime_dir_once "$controller" "$archive/controller" controller || return 1
    # Move the public transaction directory last. This is the atomic boundary:
    # before it, plain disconnect can resume from the fixed runtime; after it,
    # every fixed live root is absent and baseline status is clean.
    [[ -d $runtime && ! -L $runtime && ! -e $archive/public-session && ! -L $archive/public-session ]] || return 1
    mv -T -- "$runtime" "$archive/public-session" || return 1
    [[ -d $archive/public-session && ! -L $archive/public-session &&
       ! -e $runtime && ! -L $runtime && ! -e $controller && ! -L $controller &&
       ! -e $activation && ! -L $activation && ! -e $output && ! -L $output ]]
}

ubs24pube_retire_runtime_roots() {
    (( $# == 0 )) || return 1
    ubs24pube_release_intent_valid && ubs24gc23t_release_post_witness &&
      ubs24gc23t_b2_topology_witness && ubs24gc23t_clone_absent "$UBS24PUBE_CLONE_UUID" &&
      ubs24pube_owned_tables_absent_now || return 1
    [[ ! -e /run/mvc-disconnect && ! -L /run/mvc-disconnect &&
       ! -e /run/mvc-completion && ! -L /run/mvc-completion &&
       ! -e /run/mvc-wireguard && ! -L /run/mvc-wireguard ]] || return 1
    local intent; intent=$(ubs24pube_retire_intent_path) || return 1
    if [[ ! -e $intent && ! -L $intent ]]; then ubs24pube_publish_retire_intent || return 1; fi
    ubs24pube_retire_intent_valid || return 1
    # Network cleanup is already complete. Close the B2 descriptor before its
    # directory is archived; subsequent continuation authenticates exclusively
    # from the durable public retirement record and observed clean poststate.
    ubs24gb2_close || return 1
    ubs24pube_retire_archive_continue
}

ubs24pube_reconcile_incomplete_start_locked() {
    (( $# == 0 )) || return 1
    UBS24PUBE_STAGE=authenticating-c7-partial-start
    ubs24pube_prepare_plan_locked || return 1

    # A prior process may have committed the final guard release and died
    # before retiring the journals. In that case C1 is intentionally gone;
    # authenticate the durable release intent and finish from observed state.
    if [[ -f $(ubs24pube_release_intent_path) && ! -L $(ubs24pube_release_intent_path) ]] &&
       ubs24pube_release_intent_valid && ubs24pube_owned_tables_absent_now; then
        UBS24PUBE_STAGE=observing-prior-guard-release
        ubs24pube_release_guard || return 1
    else
        UBS24PUBE_STAGE=restoring-c1-if-needed
        ubs24pube_ensure_c1_guard || return 1
        UBS24PUBE_STAGE=stopping-clone-if-active
        ubs24pube_stop_clone_if_needed || return 1
        UBS24PUBE_STAGE=deleting-exact-clone-if-present
        ubs24pube_delete_clone_if_needed || return 1
        UBS24PUBE_STAGE=releasing-owned-guard
        ubs24pube_release_guard || return 1
    fi
    UBS24PUBE_STAGE=retiring-early-runtime
    ubs24pube_retire_runtime_roots || return 1
    UBS24PUBE_STAGE=clean-baseline-restored
}

ubs24pube_reset
