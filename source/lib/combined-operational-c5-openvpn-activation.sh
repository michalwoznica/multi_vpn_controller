#!/usr/bin/env bash
# Gate C5: PRIVATE, OFFLINE-ONLY activation contract following a successful C3
# B2 -> A3 -> C1 bootstrap in the SAME root process and while its original
# B2 flock is still held. No public driver imports this file. Admission DENIES.
#
# An nmcli success is NOT proof of usable VPN traffic, prompt-free custody,
# correct tunnel DNS, socket provenance, full OUTPUT/FORWARD policy, or safe
# teardown/recovery. No NM delete/down, nft disarm, fallback or retry on error.

ubs24gc5_reset() {
    UBS24GC5_ATTEMPTED=no
    UBS24GC5_STAGE=unverified
    UBS24GC5_AUTHORITY=none
    UBS24GC5_NM_OWNER=
}

ubs24gc5_admission_witness() { return 1; }
ubs24gc5_authorize_public_activation() { return 1; }
ubs24gc5_authorize_cleanup() { return 1; }
ubs24gc5_authorize_disarm() { return 1; }
ubs24gc5_authorize_secret_export() { return 1; }
ubs24gc5_authorize_recovery() { return 1; }

# GetSettings does NOT reveal stored passwords. Its flags can only disqualify
# agent-owned/not-saved credentials, not demonstrate availability. Require
# explicit NM-owned flags for password-based authentication; do not downgrade
# absent, mixed or unknown flag values to a claimed reusable credential.
# Challenge-response is a recognised *additional* NM/OpenVPN secret policy:
# accept system-managed (0), not-required (4), absent, or the specific
# dynamic challenge NOT_SAVED (2) policy already recognised by the earlier
# Phase D credential gate. NOT_SAVED is NOT evidence of an available secret:
# a dynamic challenge requiring human input must prevent unattended operation.
# Agent-owned (1), mixtures, unknown flags and all unsaved primary/proxy
# credentials remain rejected. No secret or activation authority is granted.
ubs24gc5_nm_owned_credential_metadata() {
    (( $# == 1 )) || return 1
    local file=$1
    [[ -s $file && -f $file && ! -L $file && -O $file &&
       $(stat -c '%a:%h' -- "$file" 2>/dev/null) == 600:1 ]] || return 1
    jq -e '
      .type == "a{sa{sv}}" and (.data|type=="array" and length==1) and
      (.data[0].vpn|has("secrets")|not) and
      .data[0].vpn.data.type == "a{ss}" and
      (.data[0].vpn.data.data|type=="object") and
      (.data[0].vpn.data.data as $d |
        ($d["connection-type"] == "password" or $d["connection-type"] == "password-tls") and
        $d["password-flags"] == "0" and
        ([$d["cert-pass-flags"], $d["http-proxy-password-flags"]] |
          all(. == null or . == "0" or . == "4")) and
        ([$d["challenge-response-flags"]] |
          all(. == null or . == "0" or . == "2" or . == "4")) and
        ([$d | keys[] | select(endswith("-flags") and
          . != "password-flags" and . != "cert-pass-flags" and
          . != "http-proxy-password-flags" and
          . != "challenge-response-flags")] | length == 0))
    ' -- "$file" >/dev/null 2>&1
}

# Re-read BOTH original and temporary profiles and require the hashes saved
# by the guarded A3 stage. None of their nonsecret metadata is logged.
ubs24gc5_prepared_profile_witness() {
    (( $# == 0 )) || return 1
    declare -F ubs24op_settings_fingerprint >/dev/null &&
        declare -F ubs24op_settings_equal_except_runtime_timestamp >/dev/null || return 1
    local clone=${UBS24GA3_PREPARED_CLONE_UUID:-} source=${UBS24GA3_PREPARED_SOURCE_UUID:-}
    [[ ${UBS24GA3_STAGE:-} == prepared-nonsecret-parity-only &&
       ${UBS24GA3_AUTHORITY:-} == none &&
       ${UBS24GA2_STATE:-} == quarantined-exact-nonsecret-settings-verified &&
       $clone == "${UBS24GA_CLONE_UUID:-x}" && $clone != "$source" &&
       ${UBS24GA3_SOURCE_SHA256:-} =~ ^[a-f0-9]{64}$ &&
       ${UBS24GA3_DERIVATIVE_SHA256:-} =~ ^[a-f0-9]{64}$ ]] || return 1
    ubs24ga_uuid_valid "$clone" && ubs24ga_uuid_valid "$source" || return 1
    [[ -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local dir item h good=1
    dir=$(umask 077; mktemp -d /dev/shm/ubs-v240-c5.XXXXXXXX) || return 1
    [[ -d $dir && ! -L $dir && -O $dir && $(stat -c %a -- "$dir") == 700 ]] || return 1
    for item in source1 source2 clone1 clone2; do
        (umask 077; set -C; : > "$dir/$item.json") || { good=0; break; }
    done
    if (( good == 1 )); then
        ubs24ga3_capture_source "$source" "$dir/source1.json" &&
        ubs24ga3_capture_source "$source" "$dir/source2.json" &&
        ubs24ga3_capture_clone "$clone" "$dir/clone1.json" &&
        ubs24ga3_capture_clone "$clone" "$dir/clone2.json" &&
        ubs24op_settings_equal_except_runtime_timestamp "$dir/source1.json" "$dir/source2.json" &&
        ubs24op_settings_equal_except_runtime_timestamp "$dir/clone1.json" "$dir/clone2.json" &&
        ubs24ga3_source_format "$dir/source1.json" "$source" &&
        ubs24gc2_derivative_format "$dir/clone1.json" "$clone" &&
        ubs24gc5_nm_owned_credential_metadata "$dir/clone1.json" || good=0
    fi
    if (( good == 1 )); then
        h=$(ubs24op_settings_fingerprint "$dir/source1.json") || good=0
        [[ $h == "$UBS24GA3_SOURCE_SHA256" ]] || good=0
        h=$(ubs24op_settings_fingerprint "$dir/clone1.json") || good=0
        [[ $h == "$UBS24GA3_DERIVATIVE_SHA256" ]] || good=0
    fi
    for item in source1 source2 clone1 clone2; do
        if [[ -e $dir/$item.json || -L $dir/$item.json ]]; then
            if [[ -f $dir/$item.json && ! -L $dir/$item.json && -O $dir/$item.json ]]; then
                rm -f -- "$dir/$item.json" || good=0
            else
                good=0
            fi
        fi
    done
    rmdir -- "$dir" || good=0
    (( good == 1 ))
}

# The C3 observer freezes pre-activation routes/links; after NM changes the
# VPN routes it cannot be reused unchanged. Verify the still-held original
# B2 lock, exact C1 records, two identical kernel firewall snapshots and
# unchanged foreign nft ownership without assuming immutable NM routes.
ubs24gc5_guard_witness() {
    (( $# == 0 )) || return 1
    ubs24gc3_transition_records_valid || return 1
    local dir scratch a b before after good=1
    dir=$(ubs24gb2_runtime) || return 1
    scratch=$(umask 077; mktemp -d /run/ubs-v240-c5-guard.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c %a -- "$scratch") == 700 ]] || return 1
    a=$scratch/first.json b=$scratch/second.json
    if ! ubs24gb1_capture_nft "$a" || ! ubs24gb1_capture_nft "$b" ||
       ! cmp -s -- "$a" "$b" ||
       ! ubs24gc1_postshape_observation "$a" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" ||
       ! ubs24gc1_postshape_observation "$b" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT"; then
        good=0
    fi
    if (( good == 1 )); then
        before=$(ubs24gb2_foreign_projection "$dir/prestate.json") || good=0
        after=$(ubs24gb2_foreign_projection "$a") || good=0
        [[ $before == "$after" ]] || good=0
    fi
    rm -f -- "$a" "$b" || good=0
    rmdir -- "$scratch" || good=0
    (( good == 1 )) && ubs24gc3_transition_records_valid
}

# Decode the portable adapter's strict typed ao ActiveConnections result without
# importing the separate diagnostic relationship library. Reject duplicates,
# malformed paths, count mismatches and oversized inventories.
ubs24gc5_active_paths() {
    (( $# == 1 )) || return 1
    local raw=$1 count i token path
    local -a fields=() paths=()
    local -A seen=()
    read -r -a fields <<< "$raw"
    [[ ${fields[0]:-} == ao && ${fields[1]:-} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    count=${fields[1]}
    (( count >= 1 && count <= 256 && ${#fields[@]} == count + 2 )) || return 1
    for ((i=2; i<${#fields[@]}; i++)); do
        token=${fields[i]}
        [[ $token =~ ^\"(/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+)\"$ ]] || return 1
        path=${BASH_REMATCH[1]}
        [[ -z ${seen[$path]+present} ]] || return 1
        seen[$path]=1
        paths+=("$path")
    done
    printf '%s\n' "${paths[@]}"
}

# Collect a single strict ActiveConnection identity; two identical independent
# observations are required. This is not authentication of remote OpenVPN peer.
ubs24gc5_active_snapshot() {
    (( $# == 2 )) || return 1
    local clone=$1 owner=$2 raw paths path vpn uuid state kind name settings expected
    local match='' count=0
    local settings_re='^o "(/org/freedesktop/NetworkManager/Settings/[0-9]+)"$'
    ubs24op_session_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$owner" ]] || return 1
    declare -F ubs24g_get_property >/dev/null &&
        declare -F ubs24g_call_readonly >/dev/null || return 1
    raw=$(ubs24g_get_property org.freedesktop.NetworkManager \
        /org/freedesktop/NetworkManager \
        org.freedesktop.NetworkManager ActiveConnections ao) || return 1
    paths=$(ubs24gc5_active_paths "$raw") || return 1
    [[ -n $paths ]] || return 1
    expected=$(ubs24g_call_readonly org.freedesktop.NetworkManager \
        /org/freedesktop/NetworkManager/Settings \
        org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$clone" o) || return 1
    [[ $expected =~ $settings_re ]] || return 1
    expected=${BASH_REMATCH[1]}
    while IFS= read -r path; do
        [[ -n $path ]] || continue
        vpn=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active Vpn b) || return 1
        [[ $vpn == 'b true' || $vpn == 'b false' ]] || return 1
        [[ $vpn == 'b true' ]] || continue
        uuid=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active Uuid s) || return 1
        # Any other simultaneous VPN is inconsistent with the C4 inactive-VPN
        # admission and must not be silently ignored.
        [[ $uuid == "s \"$clone\"" ]] || return 1
        count=$((count+1))
        (( count == 1 )) || return 1
        state=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active State u) || return 1
        kind=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active Type s) || return 1
        name=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active Id s) || return 1
        settings=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.Connection.Active Connection o) || return 1
        [[ $state == 'u 2' && $kind == 's "vpn"' && $name == 's "vpnks-ovpn"' &&
           $settings == "o \"$expected\"" ]] || return 1
        state=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" org.freedesktop.NetworkManager.VPN.Connection VpnState u) || return 1
        [[ $state == 'u 5' ]] || return 1
        match="$path|$expected"
    done <<< "$paths"
    (( count == 1 )) || return 1
    ubs24op_session_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$owner" ]] || return 1
    printf '%s\n' "$match"
}

ubs24gc5_active_witness() {
    (( $# == 2 )) || return 1
    local first second
    first=$(ubs24gc5_active_snapshot "$1" "$2") || return 1
    second=$(ubs24gc5_active_snapshot "$1" "$2") || return 1
    [[ -n $first && $first == "$second" ]]
}

# No --ask, no passwd-file, no GetSecrets and no secret-bearing outputs.
# IMPORTANT: an independent NM secret agent could STILL display a prompt.
# Hence this stage is NOT admitted for unattended real-host operation.
ubs24gc5_nm_activate_noninteractive() {
    (( $# == 2 )) || return 1
    ubs24ga_uuid_valid "$1" && ubs24gb1_valid_ifname "$2" || return 1
    LC_ALL=C nmcli --wait 35 --colors no --terse connection up uuid "$1" \
        ifname "$2" </dev/null >/dev/null 2>&1
}

ubs24gc5_activate_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GC5_ATTEMPTED:-no} == no ]] || return 1
    UBS24GC5_ATTEMPTED=yes
    UBS24GC5_STAGE=preflight-unverified
    UBS24GC5_AUTHORITY=none
    [[ ${UBS24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${UBS24GC3_AUTHORITY:-} == none &&
       ${UBS24GC3_ATTEMPTED:-} == yes &&
       -n ${UBS24GC3_IFACE:-} && -n ${UBS24GC3_REMOTE:-} ]] || return 1
    ubs24gc5_admission_witness || return 1
    ubs24gc3_post_c1_witness && ubs24gc5_prepared_profile_witness &&
        ubs24gc2_route_witness "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" || return 1
    ubs24op_session_nm_identity || return 1
    UBS24GC5_NM_OWNER=$UBS24OP_SESSION_NM_IDENTITY
    [[ $UBS24GC5_NM_OWNER == *'|0' ]] || return 1
    ubs24gc5_guard_witness || return 1
    UBS24GC5_STAGE=nm-activation-attempted-uncertain
    if ! ubs24gc5_nm_activate_noninteractive "$UBS24GA3_PREPARED_CLONE_UUID" "$UBS24GC3_IFACE"; then
        return 1
    fi
    UBS24GC5_STAGE=nm-replied-activation-unverified
    ubs24gc5_active_witness "$UBS24GA3_PREPARED_CLONE_UUID" "$UBS24GC5_NM_OWNER" &&
        ubs24gc5_guard_witness &&
        ubs24gc5_prepared_profile_witness || return 1
    UBS24GC5_STAGE=nm-openvpn-active-and-bootstrap-guard-observed-no-traffic-authority
    UBS24GC5_AUTHORITY=none
}
