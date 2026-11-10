#!/usr/bin/env bash
# UBS VPN Controller 2.4 — release Gate A2.
# Real nmcli *temporary* clone-hardening primitive; NOT wired to the public
# controller. Both authentication callbacks are permanent denials until a
# separately audited real-host root guard + NM identity/readback binding exists.
# No passwords, GetSecrets, activation, deletion or firewall modification here.
# Requires independently guarded A1 raw clone and authenticated, private typed
# source/projection, then obtains two fresh NetworkManager GetSettings snapshots.
# Success is only settings parity; secret custody, TLS and VPN remain unproven.

mvc24ga2_reset() {
    MVC24GA2_STATE=unverified
    MVC24GA2_AUTHORITY=none
    MVC24GA2_STEP=idle
}

mvc24ga2_guard_witness() { return 1; }
mvc24ga2_source_witness() { return 1; }
mvc24ga2_capture_readback() { return 1; }

mvc24ga2_private_regular() {
    (( $# == 1 )) && [[ $1 == /* && -f $1 && ! -L $1 && -O $1 ]] &&
        [[ $(stat -c '%a:%h' -- "$1" 2>/dev/null) == 600:1 ]]
}

# Args: authenticated source typed GetSettings, independently built exact
# derivative projection, two PRECREATED private empty 0600 GetSettings outputs.
# All source content is sensitive metadata and must never be printed/logged.
# A2 does not own any of these paths and never removes a clone on failure.
mvc24ga2_harden_once() {
    MVC24GA2_STATE=blocked
    MVC24GA2_AUTHORITY=none
    MVC24GA2_STEP=preconditions
    (( $# == 4 )) || return 1
    [[ ${MVC24GA2_ATTEMPTED:-no} == no ]] || return 1
    [[ ${MVC24GA_STATE:-} == raw-temporary-clone-quarantined-needs-hardening &&
       ${MVC24GA_ATTEMPTED:-} == yes && ${MVC24GA_AUTHORITY:-} == none ]] || return 1
    local source=$1 expected=$2 first=$3 second=$4 clone_uuid remote
    local item
    declare -A seen=()
    for item in "$source" "$expected" "$first" "$second"; do
        mvc24ga2_private_regular "$item" || return 1
        [[ ! ${seen[$item]+x} ]] || return 1
        seen[$item]=1
    done
    [[ ! -s $first && ! -s $second ]] || return 1
    [[ ${MVC24GA_CLONE_NAME:-} == mvc-prepared-* ]] || return 1
    clone_uuid=${MVC24GA_CLONE_UUID:-}
    declare -F mvc24ga_uuid_valid >/dev/null &&
        declare -F mvc24op_candidate_plan >/dev/null &&
        declare -F mvc24op_preview_verify >/dev/null &&
        declare -F mvc24op_settings_equal_except_runtime_timestamp >/dev/null &&
        mvc24ga_uuid_valid "$clone_uuid" || return 1
    command -v nmcli >/dev/null 2>&1 || return 1
    MVC24GA2_STEP=source-expected-plan
    mvc24op_candidate_plan "$source" 1 || return 1
    remote=$MVC24OP_CANDIDATE_ENDPOINT
    mvc24op_preview_verify "$source" "$expected" "$clone_uuid" "$remote" || return 1
    # NetworkManager may omit connection.autoconnect from GetSettings when the
    # saved VPN profile uses its default/effective value. Treat only an absent
    # key as that valid default; if present it must remain a typed boolean. A3
    # separately requires no secondaries. The derivative nevertheless MUST be
    # hardened and read back as explicit false by the exact checks below.
    MVC24GA2_STEP=source-autoconnect-shape
    jq -e '.data[0].connection as $connection |
           if ($connection | has("autoconnect")) then
             ($connection.autoconnect == {type:"b",data:false}) or
             ($connection.autoconnect == {type:"b",data:true})
           else true end' \
        -- "$source" >/dev/null 2>&1 || return 1
    MVC24GA2_STEP=prewrite-guard-source-witness
    mvc24ga2_guard_witness && mvc24ga2_source_witness "$source" || return 1
    # A single NetworkManager modify call. +vpn.data changes individual keys;
    # plain vpn.data would replace the whole map (including TLS settings).
    # --temporary prevents intentionally persisting the derivative settings.
    # No VPN password is transported through this Bash process.
    MVC24GA2_ATTEMPTED=yes
    MVC24GA2_STATE=modification-attempted-guard-retained
    MVC24GA2_STEP=nmcli-temporary-modify
    if ! nmcli --wait 10 connection modify --temporary uuid "$clone_uuid" \
        connection.id vpnks-ovpn \
        connection.autoconnect no \
        +vpn.data "remote=$remote" \
        +vpn.data remote-random=no \
        +vpn.data dev=tun-vpnks \
        ipv4.dns-priority -1000 \
        ipv6.dns-priority -1000 >/dev/null 2>&1; then
        return 1
    fi
    # Never trust a zero nmcli exit alone: independent typed GetSettings
    # readback must match the entire expected mutable settings map twice,
    # including opaque TLS and unknown options. NetworkManager's validated
    # read-only connection.timestamp runtime metadata is the sole excluded
    # field. A caller-supplied JSON file is NOT proof.
    local output read_index=0
    for output in "$first" "$second"; do
        read_index=$((read_index + 1))
        MVC24GA2_STEP="readback-${read_index}-guard-source-witness"
        mvc24ga2_guard_witness && mvc24ga2_source_witness "$source" || return 1
        MVC24GA2_STEP="readback-${read_index}-capture"
        mvc24ga2_capture_readback "$clone_uuid" "$output" || return 1
        MVC24GA2_STEP="readback-${read_index}-file-shape"
        mvc24ga2_private_regular "$output" || return 1
        MVC24GA2_STEP="readback-${read_index}-parity"
        mvc24op_preview_verify "$source" "$output" "$clone_uuid" "$remote" || return 1
    done
    # NetworkManager connection.timestamp is validated read-only runtime
    # metadata. C23O already excludes it from source/derivative identity and
    # later lifecycle fingerprints. Apply the same narrow rule between the two
    # immediate inactive-clone readbacks: all other typed settings must remain
    # semantically identical, while a valid timestamp may change.
    MVC24GA2_STEP=readbacks-semantic-stability
    mvc24op_settings_equal_except_runtime_timestamp "$first" "$second" || return 1
    MVC24GA2_STEP=final-guard-source-witness
    mvc24ga2_guard_witness && mvc24ga2_source_witness "$source" || return 1
    MVC24GA2_STEP=final-expected-parity
    mvc24ga2_private_regular "$expected" &&
        mvc24op_preview_verify "$source" "$expected" "$clone_uuid" "$remote" || return 1
    MVC24GA2_STATE=quarantined-exact-nonsecret-settings-verified
    MVC24GA2_AUTHORITY=none
    MVC24GA2_STEP=complete
}

mvc24ga2_authorize_activation() { return 1; }
mvc24ga2_authorize_guard_release() { return 1; }
mvc24ga2_authorize_cleanup() { return 1; }
mvc24ga2_authorize_recovery() { return 1; }
mvc24ga2_authorize_secret_export() { return 1; }
