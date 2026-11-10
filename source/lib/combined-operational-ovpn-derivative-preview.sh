#!/usr/bin/env bash
# Step 2B2C3F6 — NON-ADMITTING read-only typed GetSettings projection.
# Bash/jq only; no GetSecrets, NM write, profile import, nft or network action.
# This is NOT a NetworkManager loadable keyfile or proof of credential parity.

mvc24op_preview_reset() {
    UBS24OP_PREVIEW_AUTH=unassessed
    UBS24OP_PREVIEW_FLAGS=unassessed
    UBS24OP_PREVIEW_TLS=unassessed
    UBS24OP_PREVIEW_STATE=unverified
}

# Inputs: authenticated, stable typed GetSettings JSON, reserved NEW UUID,
# precreated private 0600 scratch JSON. No source UUID or endpoints printed.
mvc24op_preview_build() {
    mvc24op_preview_reset
    (( $# == 3 )) || return 1
    local source_file=$1 new_uuid=$2 preview_file=$3 endpoint='' mode flags tls
    [[ -f $source_file && ! -L $source_file && -f $preview_file && ! -L $preview_file &&
       $source_file != "$preview_file" && -O $source_file && -O $preview_file &&
       $(stat -c %a:%h -- "$source_file") == 600:1 &&
       $(stat -c %a:%h -- "$preview_file") == 600:1 ]] || return 1
    declare -F mvc24op_candidate_plan >/dev/null &&
        declare -F mvc24_valid_uuid >/dev/null &&
        mvc24_valid_uuid "$new_uuid" || return 1
    mvc24op_candidate_plan "$source_file" 1 || return 1
    endpoint=$UBS24OP_CANDIDATE_ENDPOINT
    # A projection cannot carry secrets. It preserves non-secret options
    # exactly, except a narrow set of controller-owned identity/transport/DNS
    # overrides. Real secrets and agent custody require separate binding.
    jq -e --arg new_uuid "$new_uuid" --arg remote "$endpoint" '
        (.type == "a{sa{sv}}") and (.data|type == "array" and length == 1) and
        (.data[0].connection.uuid.type == "s") and
        (.data[0].connection.uuid.data|type == "string") and
        (.data[0].connection.uuid.data != $new_uuid) and
        (.data[0].vpn | has("secrets") | not) and
        ((.data[0].connection.secondaries // {type:"as",data:[]}) | .data == [])
    ' -- "$source_file" >/dev/null 2>&1 || return 1
    # No option trimming: plugin-specific settings (including TLS selectors)
    # are preserved byte-for-byte as jq values. No use of eval or keyfile data.
    if ! jq -e --arg new_uuid "$new_uuid" --arg remote "$endpoint" '
        .data[0].connection.uuid = {type:"s", data:$new_uuid} |
        .data[0].connection.id = {type:"s", data:"vpnks-ovpn"} |
        .data[0].connection.autoconnect = {type:"b", data:false} |
        .data[0].vpn.data.data.remote = $remote |
        .data[0].vpn.data.data["remote-random"] = "no" |
        .data[0].vpn.data.data.dev = "tun-vpnks" |
        .data[0].ipv4["dns-priority"] = {type:"i", data:-1000} |
        .data[0].ipv6["dns-priority"] = {type:"i", data:-1000}
    ' -- "$source_file" > "$preview_file"; then
        : > "$preview_file"
        return 1
    fi
    # Independent structural check: all original settings survive the exact
    # allowlisted changes, including original authentication/TLS options.
    if ! mvc24op_preview_verify "$source_file" "$preview_file" "$new_uuid" "$endpoint"; then
        : > "$preview_file"
        return 1
    fi
    # String-only output labels. Never print names, flags, paths or values.
    mode=$(jq -r '.data[0].vpn.data.data["connection-type"] // "missing"' -- "$source_file") || return 1
    case $mode in
        tls|password|password-tls|static-key) UBS24OP_PREVIEW_AUTH=$mode ;;
        *) UBS24OP_PREVIEW_AUTH=other-or-unspecified ;;
    esac
    flags=$(jq -r '
        [.data[0].vpn.data.data | to_entries[] | select(.key|endswith("-flags")) | .value] as $a |
        if ($a|length)==0 then "unreported"
        elif ($a|all(. == "0" or . == "1" or . == "2" or . == "3" or . == "4" or . == "5" or . == "6" or . == "7"))|not then "unsupported"
        elif ($a|any(. == "1" or . == "3" or . == "5" or . == "7")) then "includes-agent-owned"
        elif ($a|any(. == "2" or . == "6")) then "includes-not-saved"
        else "nm-owned-or-not-required" end
    ' -- "$source_file") || return 1
    UBS24OP_PREVIEW_FLAGS=$flags
    tls=$(jq -r '
        [.data[0].vpn.data.data | ["ca", "cert", "key", "pkcs12", "tls-auth", "tls-crypt"][] as $k | select(has($k))] |
        if length == 0 then "no-references-observed" else "references-unverified" end
    ' -- "$source_file") || return 1
    UBS24OP_PREVIEW_TLS=$tls
    UBS24OP_PREVIEW_STATE=exact-nonsecret-delta-only
}


# NetworkManager connection.timestamp is runtime/read-only activation metadata.
# It is not an authoritative profile-setting witness: NetworkManager may reset,
# omit or update it independently of the mutable profile settings we protect.
# Only a correctly typed uint64-shaped value may be ignored.
mvc24op_runtime_timestamp_valid() {
    (( $# == 1 )) || return 1
    local file=$1
    [[ -f $file && ! -L $file ]] || return 1
    jq -e '
      (.type == "a{sa{sv}}") and (.data|type == "array" and length == 1) and
      (.data[0].connection|type == "object") and
      (.data[0].connection as $c |
        if ($c|has("timestamp")) then
          ($c.timestamp.type == "t") and
          (($c.timestamp.data|type) == "number") and
          ($c.timestamp.data >= 0) and
          (($c.timestamp.data|floor) == $c.timestamp.data)
        else true end)
    ' -- "$file" >/dev/null 2>&1
}

# Semantic settings equality with exactly one exception: valid
# connection.timestamp runtime metadata. All other keys/types/values remain exact.
mvc24op_settings_equal_except_runtime_timestamp() {
    (( $# == 2 )) || return 1
    local first=$1 second=$2
    mvc24op_runtime_timestamp_valid "$first" &&
        mvc24op_runtime_timestamp_valid "$second" || return 1
    jq -e --slurpfile other "$second" '
      ($other|length == 1) and
      ((. | del(.data[0].connection.timestamp)) ==
       ($other[0] | del(.data[0].connection.timestamp)))
    ' -- "$first" >/dev/null 2>&1
}

# Stable identity fingerprint for a NetworkManager settings map. The only
# excluded field is validated connection.timestamp runtime metadata. Canonical
# key ordering prevents harmless JSON object-order changes from changing the
# fingerprint; typed setting values remain part of the digest.
mvc24op_settings_fingerprint() {
    (( $# == 1 )) || return 1
    local file=$1 digest
    mvc24op_runtime_timestamp_valid "$file" || return 1
    digest=$(jq -cS 'del(.data[0].connection.timestamp)' -- "$file" | sha256sum) || return 1
    digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

# Verify a supplied preview *without trusting the builder*. This compares
# all other settings for value equality and rejects extra changed/removed keys.
mvc24op_preview_verify() {
    (( $# == 4 )) || return 1
    local source_file=$1 preview_file=$2 uuid=$3 endpoint=$4
    [[ -f $source_file && -f $preview_file && ! -L $source_file && ! -L $preview_file ]] || return 1
    # Reject malformed runtime metadata rather than blindly deleting it. Once
    # validated, connection.timestamp alone is excluded from profile parity.
    mvc24op_runtime_timestamp_valid "$source_file" &&
        mvc24op_runtime_timestamp_valid "$preview_file" || return 1
    jq -e --slurpfile original "$source_file" --arg uuid "$uuid" --arg remote "$endpoint" '
        ($original | length == 1) and
        (.type == "a{sa{sv}}") and (.data|type == "array" and length == 1) and
        (.data[0].connection.uuid == {type:"s",data:$uuid}) and
        (.data[0].connection.id == {type:"s",data:"vpnks-ovpn"}) and
        (.data[0].connection.autoconnect == {type:"b",data:false}) and
        (.data[0].vpn.data.data.remote == $remote) and
        (.data[0].vpn.data.data["remote-random"] == "no") and
        (.data[0].vpn.data.data.dev == "tun-vpnks") and
        (.data[0].vpn.data.data["proto-tcp"] == "yes") and
        (.data[0].ipv4["dns-priority"] == {type:"i",data:-1000}) and
        (.data[0].ipv6["dns-priority"] == {type:"i",data:-1000}) and
        ((. | del(.data[0].connection.timestamp)) ==
         (($original[0] |
            .data[0].connection.uuid = {type:"s", data:$uuid} |
            .data[0].connection.id = {type:"s", data:"vpnks-ovpn"} |
            .data[0].connection.autoconnect = {type:"b", data:false} |
            .data[0].vpn.data.data.remote = $remote |
            .data[0].vpn.data.data["remote-random"] = "no" |
            .data[0].vpn.data.data.dev = "tun-vpnks" |
            .data[0].ipv4["dns-priority"] = {type:"i", data:-1000} |
            .data[0].ipv6["dns-priority"] = {type:"i", data:-1000}
          ) | del(.data[0].connection.timestamp)))
    ' -- "$preview_file" >/dev/null 2>&1
}
# Explicit permanent denials: even a perfect preview is no admission witness.
mvc24op_preview_authorize_nm_write() { return 1; }
mvc24op_preview_authorize_activation() { return 1; }
mvc24op_preview_authorize_nft() { return 1; }
