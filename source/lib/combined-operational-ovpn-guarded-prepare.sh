#!/usr/bin/env bash
# Release Gate A3: compose A1 native temporary clone and A2 hardening.
# No public controller integration and no permission to install the host guard.
# The GUARD witness deliberately DENIES on a real host until an audited,
# held-lock, directly kernel-attested production guard exists. Do not substitute
# boolean environment switches or caller-supplied nft snapshots.
# NetworkManager GetSettings excludes secrets. This workflow proves only exact
# non-secret settings under quarantine, never unattended authentication.

mvc24ga3_reset() {
    UBS24GA3_STAGE=unverified
    UBS24GA3_AUTHORITY=none
    UBS24GA3_STEP=idle
    UBS24GA3_SOURCE_UUID=
    UBS24GA3_SOURCE_FILE=
    UBS24GA3_SCRATCH=
    # Same-process authenticated A3 identity, never a standalone authority.
    UBS24GA3_PREPARED_SOURCE_UUID=
    UBS24GA3_PREPARED_CLONE_UUID=
    UBS24GA3_SOURCE_SHA256=
    UBS24GA3_DERIVATIVE_SHA256=
}

# The single missing live-authority integration is deliberately visible.
mvc24ga3_guard_witness() {
    # Missing C2 binding is a hard denial. This does not make A3 publicly
    # callable; the controller entry point remains locked.
    declare -F mvc24gc2_guard_witness >/dev/null && mvc24gc2_guard_witness
}

# Read-only NetworkManager callbacks. Require a verified held controller lock,
# NM owner identity and profile object identity at both ends of a capture.
mvc24ga3_nm_identity() {
    declare -F mvc24op_session_nm_identity >/dev/null || return 1
    mvc24op_session_nm_identity || return 1
    [[ ${UBS24OP_SESSION_NM_IDENTITY:-} == *'|0' ]]
}

mvc24ga3_capture_uuid() {
    (( $# == 3 )) || return 1
    local uuid=$1 output=$2 source_kind=$3 reply obj unsaved owner_before owner_after
    [[ $source_kind == saved-source || $source_kind == temporary-clone ]] || return 1
    declare -F mvc24g_call_readonly >/dev/null &&
        declare -F mvc24g_get_property >/dev/null &&
        declare -F mvc24gs_capture_settings >/dev/null &&
        declare -F mvc24ga_uuid_valid >/dev/null || return 1
    mvc24ga_uuid_valid "$uuid" || return 1
    [[ -f $output && ! -L $output && -O $output &&
       $(stat -c '%a:%h' -- "$output") == 600:1 && ! -s $output ]] || return 1
    mvc24ga3_nm_identity || return 1
    owner_before=$UBS24OP_SESSION_NM_IDENTITY
    reply=$(mvc24g_call_readonly org.freedesktop.NetworkManager \
        /org/freedesktop/NetworkManager/Settings \
        org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || return 1
    [[ $reply =~ ^o\ \"(/org/freedesktop/NetworkManager/Settings/[0-9]+)\"$ ]] || return 1
    obj=${BASH_REMATCH[1]}
    unsaved=$(mvc24g_get_property org.freedesktop.NetworkManager "$obj" \
        org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || return 1
    [[ $unsaved == 'b false' || $unsaved == 'b true' ]] || return 1
    [[ $source_kind != saved-source || $unsaved == 'b false' ]] || return 1
    [[ $source_kind != temporary-clone || $unsaved == 'b true' ]] || return 1
    mvc24gs_capture_settings "$obj" "$output" || return 1
    [[ -s $output && $(stat -c '%a:%h' -- "$output") == 600:1 ]] || return 1
    jq -e --arg uuid "$uuid" '
        .type == "a{sa{sv}}" and (.data|type=="array" and length==1) and
        .data[0].connection.uuid == {type:"s",data:$uuid} and
        .data[0].connection.type == {type:"s",data:"vpn"} and
        .data[0].vpn["service-type"] == {type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
        (.data[0].vpn|has("secrets")|not)
    ' -- "$output" >/dev/null 2>&1 || return 1
    mvc24ga3_nm_identity || return 1
    owner_after=$UBS24OP_SESSION_NM_IDENTITY
    [[ $owner_before == "$owner_after" ]] || return 1
    reply=$(mvc24g_call_readonly org.freedesktop.NetworkManager \
        /org/freedesktop/NetworkManager/Settings \
        org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || return 1
    [[ $reply == "o \"$obj\"" ]] || return 1
    unsaved=$(mvc24g_get_property org.freedesktop.NetworkManager "$obj" \
        org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || return 1
    [[ $unsaved == 'b false' || $unsaved == 'b true' ]] || return 1
    [[ $source_kind != saved-source || $unsaved == 'b false' ]] &&
        [[ $source_kind != temporary-clone || $unsaved == 'b true' ]]
}

mvc24ga3_capture_source() { (( $# == 2 )) && mvc24ga3_capture_uuid "$1" "$2" saved-source; }
mvc24ga3_capture_clone() { (( $# == 2 )) && mvc24ga3_capture_uuid "$1" "$2" temporary-clone; }

mvc24ga3_private_empty() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 && -O $1 && ! -s $1 ]] &&
        [[ $(stat -c '%a:%h' -- "$1" 2>/dev/null) == 600:1 ]]
}

mvc24ga3_source_format() {
    (( $# == 2 )) || return 1
    local file=$1 uuid=$2
    [[ -s $file && -f $file && ! -L $file && -O $file &&
       $(stat -c '%a:%h' -- "$file") == 600:1 ]] || return 1
    jq -e --arg uuid "$uuid" '
       .type=="a{sa{sv}}" and (.data|type=="array" and length==1) and
       .data[0].connection.uuid == {type:"s",data:$uuid} and
       .data[0].connection.type == {type:"s",data:"vpn"} and
       (.data[0].connection as $connection |
        if ($connection | has("autoconnect")) then
          ($connection.autoconnect == {type:"b",data:false} or
           $connection.autoconnect == {type:"b",data:true})
        else true end) and
       ((.data[0].connection.secondaries // {type:"as",data:[]}).data == []) and
       .data[0].vpn["service-type"] == {type:"s",data:"org.freedesktop.NetworkManager.openvpn"} and
       (.data[0].vpn|has("secrets")|not)
    ' -- "$file" >/dev/null 2>&1 || return 1
    mvc24op_candidate_plan "$file" 1 >/dev/null || return 1
}

# The A1/A2 witness callbacks are deliberately bound to this controller.
# Unoverridden guard_witness() refuses every attempt on real hosts.
mvc24ga_live_guard_witness() { mvc24ga3_guard_witness; }
mvc24ga_nm_source_witness() { mvc24ga3_source_witness "$1"; }
mvc24ga2_guard_witness() { mvc24ga3_guard_witness; }
mvc24ga2_source_witness() {
    (( $# == 1 )) && [[ $1 == "${UBS24GA3_SOURCE_FILE:-/nonexistent}" ]] &&
        mvc24ga3_source_witness "${UBS24GA3_SOURCE_UUID:-}"
}
mvc24ga2_capture_readback() { mvc24ga3_capture_clone "$1" "$2"; }

mvc24ga3_source_witness() {
    (( $# == 1 )) || return 1
    [[ $1 == "${UBS24GA3_SOURCE_UUID:-}" && -n $1 &&
       -n ${UBS24GA3_SOURCE_FILE:-} && -n ${UBS24GA3_SCRATCH:-} ]] || return 1
    local scratch=$UBS24GA3_SCRATCH current=$UBS24GA3_SCRATCH/current.json
    mvc24ga3_guard_witness &&
        [[ -d $scratch && ! -L $scratch && -O $scratch &&
           $(stat -c %a -- "$scratch") == 700 ]] || return 1
    mvc24ga3_private_empty "$current" || return 1
    mvc24ga3_capture_source "$1" "$current" || return 1
    mvc24ga3_source_format "$current" "$1" &&
        cmp -s -- "$current" "$UBS24GA3_SOURCE_FILE" || return 1
    : > "$current" || return 1
    mvc24ga3_private_empty "$current" && mvc24ga3_guard_witness
}

mvc24ga3_execute_locked() {
    (( $# == 1 )) || return 1
    local source_uuid=$1 scratch=$UBS24GA3_SCRATCH item
    UBS24GA3_STEP=initial-guard-nm-identity
    mvc24ga3_guard_witness && mvc24ga3_nm_identity || return 1
    UBS24GA3_STAGE=source-readonly-preflight
    UBS24GA3_STEP=create-private-evidence-files
    for item in source1 source2 current expected read1 read2; do
        (umask 077; set -C; : > "$scratch/$item.json") || return 1
        mvc24ga3_private_empty "$scratch/$item.json" || return 1
    done
    UBS24GA3_STEP=source-readback-1
    mvc24ga3_capture_source "$source_uuid" "$scratch/source1.json" || return 1
    UBS24GA3_STEP=source-readback-2
    mvc24ga3_capture_source "$source_uuid" "$scratch/source2.json" || return 1
    UBS24GA3_STEP=source-readbacks-byte-stable
    cmp -s -- "$scratch/source1.json" "$scratch/source2.json" || return 1
    UBS24GA3_STEP=source-format
    mvc24ga3_source_format "$scratch/source1.json" "$source_uuid" || return 1
    UBS24GA3_SOURCE_UUID=$source_uuid
    UBS24GA3_SOURCE_FILE=$scratch/source1.json
    UBS24GA3_STEP=source-witness-before-clone
    mvc24ga3_source_witness "$source_uuid" || return 1
    # NetworkManager does not implement connection.autoconnect for VPN
    # profiles; VPN automatic start is expressed through connection.secondaries.
    # The source must still be a typed OpenVPN profile with no secondaries, and
    # any source drift or loss of NM ownership remains a hard denial. The raw
    # clone is created only under the independently attested deny-all guard,
    # then A2 explicitly hardens the derivative to autoconnect=false.
    UBS24GA3_STAGE=clone-attempted-no-activation-authority
    UBS24GA3_STEP=raw-temporary-clone
    mvc24ga_clone_temporary_once "$source_uuid" || return 1
    UBS24GA3_STEP=source-witness-after-clone
    mvc24ga3_source_witness "$source_uuid" || return 1
    UBS24GA3_STEP=build-expected-derivative
    mvc24op_preview_build "$scratch/source1.json" "$UBS24GA_CLONE_UUID" \
        "$scratch/expected.json" >/dev/null || return 1
    UBS24GA3_STAGE=hardening-attempted-no-activation-authority
    UBS24GA3_STEP=a2-hardening
    mvc24ga2_harden_once "$scratch/source1.json" "$scratch/expected.json" \
        "$scratch/read1.json" "$scratch/read2.json" || return 1
    UBS24GA3_STEP=source-and-guard-witness-after-a2
    mvc24ga3_source_witness "$source_uuid" && mvc24ga3_guard_witness || return 1
    UBS24GA3_STEP=a2-state-contract
    [[ ${UBS24GA2_STATE:-} == quarantined-exact-nonsecret-settings-verified &&
       ${UBS24GA2_AUTHORITY:-} == none && ${UBS24GA_AUTHORITY:-} == none ]] || return 1
    # Preserve just immutable evidence identifiers while discarding the
    # sensitive private JSON snapshots. Re-read from NM at C1 admission.
    local source_hash derivative_hash
    # Fingerprints cover the complete typed settings map except validated
    # NetworkManager connection.timestamp runtime metadata. That property is
    # read-only and may reset/update independently of profile configuration.
    UBS24GA3_STEP=source-fingerprint
    source_hash=$(mvc24op_settings_fingerprint "$scratch/source1.json") || return 1
    UBS24GA3_STEP=derivative-fingerprint
    derivative_hash=$(mvc24op_settings_fingerprint "$scratch/read1.json") || return 1
    UBS24GA3_SOURCE_SHA256=$source_hash
    UBS24GA3_DERIVATIVE_SHA256=$derivative_hash
    [[ $UBS24GA3_SOURCE_SHA256 =~ ^[0-9a-f]{64}$ &&
       $UBS24GA3_DERIVATIVE_SHA256 =~ ^[0-9a-f]{64}$ ]] || return 1
    UBS24GA3_STEP=publish-prepared-identifiers
    UBS24GA3_PREPARED_SOURCE_UUID=$source_uuid
    UBS24GA3_PREPARED_CLONE_UUID=$UBS24GA_CLONE_UUID
    UBS24GA3_STAGE=prepared-nonsecret-parity-only
    UBS24GA3_STEP=complete
}

# One-shot. Cleans only its own temporary *read-only evidence*. Never removes
# an uncertain NM clone or guard. No retry after any NM write was attempted.
mvc24ga3_prepare_once() {
    (( $# == 1 )) || return 1
    [[ ${UBS24GA3_ATTEMPTED:-no} == no ]] || return 1
    mvc24ga_uuid_valid "$1" || return 1
    UBS24GA3_ATTEMPTED=yes
    mvc24ga3_reset
    [[ -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local scratch success=1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-a3.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c %a -- "$scratch") == 700 ]] || return 1
    UBS24GA3_SCRATCH=$scratch
    local failure_stage=unverified
    if ! mvc24ga3_execute_locked "$1"; then
        success=0
        failure_stage=${UBS24GA3_STAGE:-unverified}
    fi
    # Never reuse cached source content across requests. This cleanup affects
    # ONLY our private /dev/shm evidence and does not touch NM, nftables or DNS.
    local file
    for file in source1 source2 current expected read1 read2; do
        if [[ -e $scratch/$file.json || -L $scratch/$file.json ]]; then
            [[ -f $scratch/$file.json && ! -L $scratch/$file.json && -O $scratch/$file.json ]] || success=0
            rm -f -- "$scratch/$file.json" || success=0
        fi
    done
    rmdir -- "$scratch" || success=0
    UBS24GA3_SCRATCH= UBS24GA3_SOURCE_FILE= UBS24GA3_SOURCE_UUID=
    if (( success == 1 )); then
        UBS24GA3_STAGE=prepared-nonsecret-parity-only
        UBS24GA3_AUTHORITY=none
        return 0
    fi
    UBS24GA3_PREPARED_SOURCE_UUID= UBS24GA3_PREPARED_CLONE_UUID=
    UBS24GA3_SOURCE_SHA256= UBS24GA3_DERIVATIVE_SHA256=
    case $failure_stage in
        source-readonly-preflight|clone-attempted-no-activation-authority|hardening-attempted-no-activation-authority)
            UBS24GA3_STAGE="blocked-${failure_stage}-guard-retained"
            ;;
        *)
            UBS24GA3_STAGE=blocked-ambiguous-guard-retained
            ;;
    esac
    UBS24GA3_AUTHORITY=none
    return 1
}

mvc24ga3_authorize_activation() { return 1; }
mvc24ga3_authorize_cleanup() { return 1; }
mvc24ga3_authorize_guard_release() { return 1; }
mvc24ga3_authorize_recovery() { return 1; }
mvc24ga3_authorize_secret_export() { return 1; }
