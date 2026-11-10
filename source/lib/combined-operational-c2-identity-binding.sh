#!/usr/bin/env bash
# Gate C2: PRIVATE, non-admitting A3/B2 -> C1 derivative-bound witnesses.
# Source only after B2, A3, candidate-plan and C1 libraries in an explicitly
# controlled root process. No public CLI imports this module. Its witnesses
# perform read-only checks; they install no guard, start no VPN, expose no
# secrets, never disarm a quarantine and never authorise activation/recovery.
# The B2 runtime and held flock are the authority; cached Bash variables are
# only comparison evidence and cannot independently grant authority.

# Helper intentionally accepts a file and FD for safe isolated unit tests;
# the production caller restricts the actual runtime to B2's /run path.
mvc24gc2_lock_held() {
    (( $# == 2 )) || return 1
    local lock=$1 fd=$2 probe result
    [[ $fd =~ ^[0-9]+$ && -f $lock && ! -L $lock ]] || return 1
    [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$fd" 2>/dev/null) == "$(stat -c '%d:%i' -- "$lock" 2>/dev/null)" ]] || return 1
    flock -n "$fd" >/dev/null 2>&1 || return 1
    exec {probe}< "$lock" || return 1
    if flock -n "$probe" >/dev/null 2>&1; then
        exec {probe}>&-
        return 1
    else
        result=$?
    fi
    exec {probe}>&- || return 1
    (( result == 1 ))
}

mvc24gc2_guard_witness() {
    (( $# == 0 )) || return 1
    declare -F mvc24gb2_root_scope >/dev/null &&
        declare -F mvc24gb2_runtime_shape >/dev/null &&
        declare -F mvc24gb2_lock_valid >/dev/null &&
        declare -F mvc24gb2_attest >/dev/null || return 1
    mvc24gb2_root_scope && mvc24gb2_runtime_shape &&
        mvc24gb2_lock_valid || return 1
    # B2's FD inode check alone doesn't demonstrate an acquired flock.
    # Reaffirm the lock on that same open-file description, then open a
    # *different* description: its nonblocking exclusive lock must contend.
    local dir
    dir=$(mvc24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller ]] || return 1
    mvc24gc2_lock_held "$dir/controller.lock" "$UBS24GB2_FD" || return 1
    mvc24gb2_attest || return 1
    [[ ${UBS24GB2_STAGE:-} == host-deny-all-attested-observation-only &&
       ${UBS24GB2_AUTHORITY:-} == none ]] && mvc24gb2_lock_valid
}

mvc24gc2_derivative_format() {
    (( $# == 2 )) || return 1
    local file=$1 uuid=$2
    [[ -s $file && -f $file && ! -L $file && -O $file &&
       $(stat -c '%a:%h' -- "$file") == '600:1' ]] || return 1
    jq -e --arg uuid "$uuid" '
        .type == "a{sa{sv}}" and (.data|type=="array" and length==1) and
        .data[0].connection.uuid == {type:"s",data:$uuid} and
        .data[0].connection.type == {type:"s",data:"vpn"} and
        .data[0].connection.id == {type:"s",data:"vpnks-ovpn"} and
        .data[0].connection.autoconnect == {type:"b",data:false} and
        ((.data[0].connection.secondaries // {type:"as",data:[]}).data == []) and
        .data[0].vpn["service-type"] == {type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
        .data[0].vpn.data.type == "a{ss}" and
        .data[0].vpn.data.data["proto-tcp"] == "yes" and
        .data[0].vpn.data.data["remote-random"] == "no" and
        ((.data[0].vpn.data.data["remote-random-hostname"] // "no") == "no") and
        .data[0].vpn.data.data.dev == "tun-vpnks" and
        .data[0].ipv4["dns-priority"] == {type:"i",data:-1000} and
        .data[0].ipv6["dns-priority"] == {type:"i",data:-1000} and
        (.data[0].vpn|has("secrets")|not)
    ' -- "$file" >/dev/null 2>&1 || return 1
    mvc24op_candidate_plan "$file" 1 >/dev/null || return 1
    [[ ${UBS24OP_CANDIDATE_COUNT:-} == 1 && ${UBS24OP_CANDIDATE_PROTO:-} == tcp ]]
}

# iproute2 commonly serialises the route-get source as "prefsrc", while
# other versions may use "src". Require an exact matching source; when both
# fields occur they must agree. Never infer a source from the caller alone.
mvc24gc2_route_snapshot_matches() {
    (( $# == 4 )) || return 1
    local json=$1 iface=$2 source=$3 remote=$4
    jq -e --arg iface "$iface" --arg src "$source" --arg dst "$remote" '
        type=="array" and length==1 and
        .[0].dst==$dst and .[0].dev==$iface and
        ((.[0].prefsrc==$src and (.[0].src == null or .[0].src==$src)) or
         (.[0].src==$src and .[0].prefsrc==null)) and
        ((.[0].type // "unicast") == "unicast") and
        (.[0]|has("multipath")|not)
    ' <<< "$json" >/dev/null 2>&1
}
mvc24gc2_route_witness() {
    (( $# == 3 )) || return 1
    local iface=$1 source=$2 remote=$3 route1 route2
    route1=$(ip -j -4 route get "$remote" 2>/dev/null) || return 1
    route2=$(ip -j -4 route get "$remote" 2>/dev/null) || return 1
    [[ -n $route1 && $route1 == "$route2" ]] || return 1
    mvc24gc2_route_snapshot_matches "$route1" "$iface" "$source" "$remote"
}

# Args are only propositions to verify, NEVER an endpoint-authorisation
# source. The endpoint comes from fresh authenticated NM GetSettings snapshots,
# checked against the fingerprint captured during the A3 hardening readback.
mvc24gc2_endpoint_witness() {
    (( $# == 4 )) || return 1
    local iface=$1 source=$2 remote=$3 port=$4
    declare -F mvc24gc1_parameters >/dev/null &&
        declare -F mvc24ga3_capture_source >/dev/null &&
        declare -F mvc24ga3_capture_clone >/dev/null &&
        declare -F mvc24op_candidate_plan >/dev/null &&
        declare -F mvc24op_settings_fingerprint >/dev/null &&
        declare -F mvc24op_settings_equal_except_runtime_timestamp >/dev/null || return 1
    mvc24gc1_parameters "$iface" "$source" "$remote" "$port" || return 1
    [[ ${UBS24GA3_STAGE:-} == prepared-nonsecret-parity-only &&
       ${UBS24GA3_AUTHORITY:-} == none &&
       ${UBS24GA2_STATE:-} == quarantined-exact-nonsecret-settings-verified &&
       ${UBS24GA2_AUTHORITY:-} == none &&
       ${UBS24GA_AUTHORITY:-} == none &&
       ${UBS24GA_STATE:-} == raw-temporary-clone-quarantined-needs-hardening &&
       ${UBS24GA3_PREPARED_CLONE_UUID:-} == "${UBS24GA_CLONE_UUID:-x}" &&
       -n ${UBS24GA3_PREPARED_SOURCE_UUID:-} &&
       ${UBS24GA3_PREPARED_SOURCE_UUID:-} != "${UBS24GA3_PREPARED_CLONE_UUID:-}" &&
       ${UBS24GA3_SOURCE_SHA256:-} =~ ^[a-f0-9]{64}$ &&
       ${UBS24GA3_DERIVATIVE_SHA256:-} =~ ^[a-f0-9]{64}$ ]] || return 1
    mvc24gc2_guard_witness || return 1
    [[ $(mvc24gb2_derive_iface) == "$iface" ]] || return 1
    # Private, ephemeral file permissions mirror A3. No profile content is
    # copied into persistent logs or the B2 runtime; all readbacks are fresh.
    [[ -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local scratch success=1 item hash1 hash2 selected
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c2.XXXXXXXX) || return 1
    if [[ ! -d $scratch || -L $scratch || ! -O $scratch ||
          $(stat -c %a -- "$scratch") != 700 ]]; then return 1; fi
    for item in source1 source2 clone1 clone2; do
        (umask 077; set -C; : > "$scratch/$item.json") || { success=0; break; }
    done
    if (( success == 1 )); then
        mvc24ga3_capture_source "$UBS24GA3_PREPARED_SOURCE_UUID" "$scratch/source1.json" &&
        mvc24ga3_capture_source "$UBS24GA3_PREPARED_SOURCE_UUID" "$scratch/source2.json" &&
        mvc24ga3_capture_clone "$UBS24GA3_PREPARED_CLONE_UUID" "$scratch/clone1.json" &&
        mvc24ga3_capture_clone "$UBS24GA3_PREPARED_CLONE_UUID" "$scratch/clone2.json" || success=0
    fi
    if (( success == 1 )); then
        hash1=$(mvc24op_settings_fingerprint "$scratch/source1.json") || success=0
        hash2=$(mvc24op_settings_fingerprint "$scratch/clone1.json") || success=0
        [[ $hash1 == "$UBS24GA3_SOURCE_SHA256" &&
           $hash2 == "$UBS24GA3_DERIVATIVE_SHA256" ]] || success=0
        mvc24op_settings_equal_except_runtime_timestamp "$scratch/source1.json" "$scratch/source2.json" &&
            mvc24op_settings_equal_except_runtime_timestamp "$scratch/clone1.json" "$scratch/clone2.json" || success=0
    fi
    if (( success == 1 )); then
        mvc24ga3_source_format "$scratch/source1.json" "$UBS24GA3_PREPARED_SOURCE_UUID" &&
            mvc24gc2_derivative_format "$scratch/clone1.json" "$UBS24GA3_PREPARED_CLONE_UUID" || success=0
        selected=${UBS24OP_CANDIDATE_ENDPOINT:-}
        [[ $selected == "$remote:$port" ]] || success=0
    fi
    if (( success == 1 )); then
        mvc24gc2_route_witness "$iface" "$source" "$remote" &&
            mvc24gc2_guard_witness || success=0
    fi
    # Clean only the read-only metadata snapshots, on success AND failure.
    for item in source1 source2 clone1 clone2; do
        if [[ -e $scratch/$item.json || -L $scratch/$item.json ]]; then
            if [[ -f $scratch/$item.json && ! -L $scratch/$item.json &&
                  -O $scratch/$item.json ]]; then
                rm -f -- "$scratch/$item.json" || success=0
            else success=0; fi
        fi
    done
    rmdir -- "$scratch" || success=0
    (( success == 1 ))
}

mvc24gc2_authorize_activation() { return 1; }
mvc24gc2_authorize_cleanup() { return 1; }
mvc24gc2_authorize_disarm() { return 1; }
mvc24gc2_authorize_recovery() { return 1; }
mvc24gc2_authorize_secret_export() { return 1; }
