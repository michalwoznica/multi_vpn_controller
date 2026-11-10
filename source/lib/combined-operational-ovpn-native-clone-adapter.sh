#!/usr/bin/env bash
# Gate A1 (release focus): REAL nmcli-native temporary clone adapter.
# Not sourced/wired by vpn-v240 or its public controller. Deliberately
# UNREACHABLE on a real host pending production host-guard verification.
# Unit tests substitute both witness functions and the nmcli executable.
# Never interpret clone success as password availability, authentication,
# TLS parity, safe profile hardening, activation or recovery authority.
#
# nmcli's native clone can ask NetworkManager/libnm for the source's secrets.
# The native subprocess (not Bash) handles this. NM may keep the resulting
# temporary profile and its secrets in root-protected runtime storage /run;
# this is NOT proof of no on-disk NM-managed copies. Unattended password
# availability remains a LIVE, GUARDED acceptance condition.
#
# A raw clone inherits remote-random and multiple remotes. It is never ready
# to connect and MUST remain under independently attested strict quarantine.

ubs24ga_reset() {
    UBS24GA_STATE=unverified
    UBS24GA_CLONE_UUID=
    UBS24GA_CLONE_NAME=
    UBS24GA_AUTHORITY=none
}

# These intentionally deny until connected to the authenticated root guard,
# private transaction lock and independently checked source/NM owner.
# DO NOT replace them with shell-variable-only permission bits.
ubs24ga_live_guard_witness() { return 1; }
ubs24ga_nm_source_witness() { return 1; }

# Optional pre-mutation observer. The physically proven private composition keeps
# this no-op definition. The public controller overrides it to durably bind the
# unique clone name before NetworkManager receives the clone write.
ubs24ga_preclone_intent_hook() { return 0; }
ubs24ga_postclone_identity_hook() { return 0; }

ubs24ga_uuid_valid() {
    (( $# == 1 )) && [[ $1 =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# $1 = original source UUID. Must be invoked under an already-held and
# independently verified deny-all host/forward/underlay guard. This function
# DOES NOT install a guard, alter VPN routes, clean up or activate anything.
# On any ambiguous write/readback result, leave the guard installed. Never
# retry after nmcli clone has been attempted; do not blindly delete a clone.
ubs24ga_clone_temporary_once() {
    UBS24GA_STATE=blocked
    UBS24GA_AUTHORITY=none
    UBS24GA_CLONE_UUID=
    UBS24GA_CLONE_NAME=
    (( $# == 1 )) && ubs24ga_uuid_valid "$1" || return 1
    [[ ${UBS24GA_ATTEMPTED:-no} == no ]] || return 1
    declare -F ubs24ga_live_guard_witness >/dev/null || return 1
    declare -F ubs24ga_nm_source_witness >/dev/null || return 1
    command -v nmcli >/dev/null 2>&1 || return 1
    ubs24ga_live_guard_witness && ubs24ga_nm_source_witness "$1" || return 1
    local source_uuid=$1 random='' new_name='' new_uuid=''
    IFS= read -r random < /proc/sys/kernel/random/uuid || return 1
    ubs24ga_uuid_valid "$random" || return 1
    new_name="ubs-v240-prepared-$random"
    # Fail if the unique clone name exists before registration. Both stdout
    # and stderr are suppressed; nmcli may include user profile data.
    if nmcli --wait 10 -g connection.uuid connection show "$new_name" >/dev/null 2>&1; then
        return 1
    fi
    ubs24ga_live_guard_witness && ubs24ga_nm_source_witness "$source_uuid" || return 1
    # Public composition may bind this unguessable, pre-checked-absent name to a
    # root-owned same-boot journal. The default private hook is a no-op, so the
    # physically proven private lifecycle is behaviorally unchanged. A public
    # hook failure aborts before the first possible NetworkManager write.
    ubs24ga_preclone_intent_hook "$source_uuid" "$new_name" || return 1
    # Mark the attempt before the first possible NetworkManager write.
    UBS24GA_ATTEMPTED=yes
    UBS24GA_STATE=clone-attempted-not-admitted
    if ! nmcli --wait 10 connection clone --temporary uuid "$source_uuid" "$new_name" >/dev/null 2>&1; then
        return 1
    fi
    # The clone is raw and may retain remote-random, source secrets and
    # original DNS settings. It MUST NOT be activated at this stage.
    if ! ubs24ga_live_guard_witness || ! ubs24ga_nm_source_witness "$source_uuid"; then
        return 1
    fi
    new_uuid=$(nmcli --wait 10 -g connection.uuid connection show "$new_name" 2>/dev/null) || return 1
    [[ $new_uuid != *$'\n'* && $new_uuid != "$source_uuid" ]] &&
        ubs24ga_uuid_valid "$new_uuid" || return 1
    ubs24ga_live_guard_witness || return 1
    # Once NM returns a stable UUID, public composition may durably bind it
    # before A2 changes connection.id from the random raw-clone name.
    ubs24ga_postclone_identity_hook "$source_uuid" "$new_name" "$new_uuid" || return 1
    UBS24GA_CLONE_UUID=$new_uuid
    UBS24GA_CLONE_NAME=$new_name
    UBS24GA_STATE=raw-temporary-clone-quarantined-needs-hardening
    return 0
}

ubs24ga_authorize_activation() { return 1; }
ubs24ga_authorize_guard_release() { return 1; }
ubs24ga_authorize_cleanup() { return 1; }
ubs24ga_authorize_recovery() { return 1; }
ubs24ga_authorize_secret_export() { return 1; }
