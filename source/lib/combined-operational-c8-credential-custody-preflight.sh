#!/usr/bin/env bash
# Gate C8: PRIVATE NON-ADMITTING NetworkManager credential-custody preflight.
# This is strictly a read-only check of typed GetSettings metadata. It cannot
# determine whether NM can deliver a password to the OpenVPN plugin, whether
# an external secret agent may prompt, or whether authentication will succeed.
# Do not source it from public/real-host entry points. Never call GetSecrets,
# nmcli --show-secrets, activate, delete, modify, nft, DNS or recovery here.

ubs24gc8_reset() {
    UBS24GC8_STAGE=unverified
    UBS24GC8_AUTHORITY=none
}

ubs24gc8_authorize_activation() { return 1; }
ubs24gc8_authorize_secret_access() { return 1; }
ubs24gc8_authorize_prompt() { return 1; }
ubs24gc8_authorize_firewall() { return 1; }
ubs24gc8_authorize_cleanup() { return 1; }
ubs24gc8_authorize_recovery() { return 1; }

# Use the actual NetworkManager "http-proxy-password-flags" spelling. All
# unknown *-flags fail closed rather than being silently considered safe.
# A flag of zero means NM is responsible for storage, NOT secret availability.
# Not-required (4) is valid only for optional secondary secrets.
# challenge-response-flags is an NM/OpenVPN secondary secret policy. Its
# NOT_SAVED value (2) is recognised for an optional, dynamic challenge, as
# in the pre-existing Phase D verifier; unlike the primary password's flag,
# it is not proof that a required credential is absent. A future challenge
# could still require a prompt, so this cannot establish no-prompt operation.
# All primary/proxy/cert unsaved or agent-owned flags remain rejected.
ubs24gc8_metadata_policy() {
    (( $# == 2 )) || return 1
    local snapshot=$1 expected_uuid=$2
    [[ -s $snapshot && -f $snapshot && ! -L $snapshot && -O $snapshot &&
       $(stat -c '%a:%h' -- "$snapshot" 2>/dev/null) == 600:1 ]] || return 1
    ubs24ga_uuid_valid "$expected_uuid" || return 1
    jq -e --arg uuid "$expected_uuid" '
        .type == "a{sa{sv}}" and (.data|type == "array" and length == 1) and
        .data[0].connection.uuid == {type:"s",data:$uuid} and
        .data[0].connection.type == {type:"s",data:"vpn"} and
        .data[0].vpn["service-type"] == {type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
        (.data[0].vpn|has("secrets")|not) and
        .data[0].vpn.data.type == "a{ss}" and
        (.data[0].vpn.data.data|type == "object") and
        (.data[0].vpn.data.data as $d |
            ($d["connection-type"] == "password" or $d["connection-type"] == "password-tls") and
            $d["password-flags"] == "0" and
            ([$d["cert-pass-flags"],$d["http-proxy-password-flags"]] |
                all(. == null or . == "0" or . == "4")) and
            ([$d["challenge-response-flags"]] |
                all(. == null or . == "0" or . == "2" or . == "4")) and
            ([$d|keys[]|select(endswith("-flags") and
                . != "password-flags" and . != "cert-pass-flags" and
                . != "http-proxy-password-flags" and
                . != "challenge-response-flags")] | length == 0))
    ' -- "$snapshot" >/dev/null 2>&1
}

ubs24gc8_same_flags() {
    (( $# == 2 )) || return 1
    # Compare only secret-policy flags and authentication type: other profile
    # fields have already been checked against A3's exact derivative fingerprint.
    local source_flags clone_flags
    source_flags=$(jq -cS '.data[0].vpn.data.data |
        {"connection-type": .["connection-type"],
         "password-flags": .["password-flags"],
         "cert-pass-flags": (.["cert-pass-flags"] // null),
         "http-proxy-password-flags": (.["http-proxy-password-flags"] // null),
         "challenge-response-flags": (.["challenge-response-flags"] // null)}' -- "$1") || return 1
    clone_flags=$(jq -cS '.data[0].vpn.data.data |
        {"connection-type": .["connection-type"],
         "password-flags": .["password-flags"],
         "cert-pass-flags": (.["cert-pass-flags"] // null),
         "http-proxy-password-flags": (.["http-proxy-password-flags"] // null),
         "challenge-response-flags": (.["challenge-response-flags"] // null)}' -- "$2") || return 1
    [[ $source_flags == "$clone_flags" ]]
}

# Requires the already held C3 root transaction lock, exact C1 kernel guard,
# and C5's independent A3 source/derivative identity witness. Captures only
# GetSettings (which excludes secrets) in private tmpfs and erases snapshots.
# A positive result means metadata continuity only, never no-prompt proof.
ubs24gc8_preflight_locked() {
    ubs24gc8_reset
    (( $# == 0 )) || return 1
    declare -F ubs24op_settings_fingerprint >/dev/null &&
        declare -F ubs24op_settings_equal_except_runtime_timestamp >/dev/null || return 1
    [[ ${UBS24GC5_ATTEMPTED:-no} == no &&
       ${UBS24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${UBS24GC3_AUTHORITY:-} == none ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
       ubs24gc3_transition_records_valid &&
       ubs24gc5_guard_witness && ubs24gc5_prepared_profile_witness || return 1
    [[ -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local path source_uuid clone_uuid owner_before owner_after
    local item digest success=1 cleanup=1
    source_uuid=${UBS24GA3_PREPARED_SOURCE_UUID:-}
    clone_uuid=${UBS24GA3_PREPARED_CLONE_UUID:-}
    ubs24ga_uuid_valid "$source_uuid" && ubs24ga_uuid_valid "$clone_uuid" &&
        [[ $source_uuid != "$clone_uuid" ]] || return 1
    ubs24op_session_nm_identity || return 1
    owner_before=$UBS24OP_SESSION_NM_IDENTITY
    [[ $owner_before == *'|0' ]] || return 1
    path=$(umask 077; mktemp -d /dev/shm/ubs-v240-c8.XXXXXXXX) || return 1
    [[ -d $path && ! -L $path && -O $path && $(stat -c %a -- "$path") == 700 ]] || return 1
    for item in source1 source2 clone1 clone2; do
        if ! (umask 077; set -C; : > "$path/$item.json"); then success=0; break; fi
    done
    if (( success == 1 )); then
        ubs24ga3_capture_source "$source_uuid" "$path/source1.json" &&
        ubs24ga3_capture_source "$source_uuid" "$path/source2.json" &&
        ubs24ga3_capture_clone "$clone_uuid" "$path/clone1.json" &&
        ubs24ga3_capture_clone "$clone_uuid" "$path/clone2.json" &&
        ubs24op_settings_equal_except_runtime_timestamp "$path/source1.json" "$path/source2.json" &&
        ubs24op_settings_equal_except_runtime_timestamp "$path/clone1.json" "$path/clone2.json" &&
        ubs24gc8_metadata_policy "$path/source1.json" "$source_uuid" &&
        ubs24gc8_metadata_policy "$path/clone1.json" "$clone_uuid" &&
        ubs24gc8_same_flags "$path/source1.json" "$path/clone1.json" || success=0
    fi
    if (( success == 1 )); then
        digest=$(ubs24op_settings_fingerprint "$path/source1.json") || success=0
        [[ $digest == "${UBS24GA3_SOURCE_SHA256:-}" ]] || success=0
        digest=$(ubs24op_settings_fingerprint "$path/clone1.json") || success=0
        [[ $digest == "${UBS24GA3_DERIVATIVE_SHA256:-}" ]] || success=0
        ubs24op_session_nm_identity || success=0
        owner_after=${UBS24OP_SESSION_NM_IDENTITY:-}
        [[ $owner_after == "$owner_before" ]] &&
            ubs24gc5_guard_witness && ubs24gc5_prepared_profile_witness || success=0
    fi
    for item in source1 source2 clone1 clone2; do
        if [[ -e $path/$item.json || -L $path/$item.json ]]; then
            if [[ -f $path/$item.json && ! -L $path/$item.json && -O $path/$item.json ]]; then
                rm -f -- "$path/$item.json" || cleanup=0
            else
                cleanup=0
            fi
        fi
    done
    rmdir -- "$path" || cleanup=0
    if (( success == 1 && cleanup == 1 )); then
        UBS24GC8_STAGE=nm-source-clone-metadata-consistent-password-delivery-unproven
        UBS24GC8_AUTHORITY=none
        return 0
    fi
    return 1
}
