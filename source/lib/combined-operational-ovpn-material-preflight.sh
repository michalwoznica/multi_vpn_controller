#!/usr/bin/env bash
# Step 2B2C3F8: non-admitting, read-only TLS reference and unrecognised flag
# preflight. This deliberately NEVER reads file contents, credentials or secrets.
# Checks use the caller's privileges and are inherently raceable; the results
# are observations only, NEVER authority for clone, firewall or activation.

ubs24op_material_reset() {
    UBS24OP_MATERIAL_CA=unassessed
    UBS24OP_MATERIAL_TLS_CRYPT=unassessed
    UBS24OP_MATERIAL_NAME_CHECK=unassessed
    UBS24OP_MATERIAL_SERVER_CERT=unassessed
    UBS24OP_MATERIAL_OTHER_FLAGS=unassessed
    UBS24OP_MATERIAL_STATE=unverified
}

# Return only safe static labels in UBS24OP_MATERIAL_REF. Paths may be private
# and are kept inside this function; they are never printed or exported.
ubs24op_material_reference() {
    UBS24OP_MATERIAL_REF=unassessed
    (( $# == 2 )) || return 1
    local file=$1 key=$2 value
    case $key in ca|tls-crypt) ;; *) return 1 ;; esac
    if ! jq -e --arg key "$key" '.data[0].vpn.data.data | has($key)' "$file" >/dev/null 2>&1; then
        UBS24OP_MATERIAL_REF=absent
        return 0
    fi
    if ! jq -e --arg key "$key" '
        .data[0].vpn.data.data[$key] | type == "string"
    ' "$file" >/dev/null 2>&1; then
        UBS24OP_MATERIAL_REF=unsupported-reference
        return 0
    fi
    value=$(jq -r --arg key "$key" '.data[0].vpn.data.data[$key]' "$file") || return 1
    # A trailing newline could be silently removed by command substitution;
    # assert the original JSON field contains no control characters first.
    if ! jq -e --arg key "$key" '
        .data[0].vpn.data.data[$key] |
        length > 0 and length <= 4096 and
        (explode | all(. >= 32 and . != 127))
    ' "$file" >/dev/null 2>&1; then
        UBS24OP_MATERIAL_REF=unsupported-reference
    elif [[ $value != /* ]]; then
        UBS24OP_MATERIAL_REF=nonabsolute-or-inline
    elif [[ -L $value ]]; then
        UBS24OP_MATERIAL_REF=symlink-reference
    elif [[ ! -e $value ]]; then
        UBS24OP_MATERIAL_REF=missing-or-inaccessible
    elif [[ ! -f $value ]]; then
        UBS24OP_MATERIAL_REF=nonregular
    elif [[ -r $value ]]; then
        UBS24OP_MATERIAL_REF=regular-readable-by-caller
    else
        UBS24OP_MATERIAL_REF=regular-not-readable-by-caller
    fi
}

ubs24op_material_preflight() {
    ubs24op_material_reset
    (( $# == 1 )) || return 1
    local file=$1 classification
    [[ -f $file && ! -L $file && -O $file && $(stat -c %a:%h -- "$file") == 600:1 ]] || return 1
    # GetSettings MUST NOT return the secrets dictionary. The caller is also
    # responsible for double-snapshot and stable NetworkManager owner checks.
    jq -e '
        .type == "a{sa{sv}}" and (.data|type == "array" and length == 1) and
        .data[0].vpn.data.type == "a{ss}" and
        (.data[0].vpn.data.data|type == "object") and
        (.data[0].vpn | has("secrets") | not)
    ' "$file" >/dev/null 2>&1 || return 1

    ubs24op_material_reference "$file" ca || return 1
    UBS24OP_MATERIAL_CA=$UBS24OP_MATERIAL_REF
    ubs24op_material_reference "$file" tls-crypt || return 1
    UBS24OP_MATERIAL_TLS_CRYPT=$UBS24OP_MATERIAL_REF

    # Preserve all vendor options in the projection, but NEVER silently
    # interpret unknown *-flags as an available credential or clone authority.
    classification=$(jq -er '
        .data[0].vpn.data.data as $d |
        [$d | to_entries[] | select((.key | endswith("-flags")) and
            (.key != "password-flags") and (.key != "cert-pass-flags") and
            (.key != "http-proxy-password-flags"))] as $other |
        if ($other|length) == 0 then "none"
        elif ($other | all((.value | type) == "string" and
                            (.value == "0" or .value == "1" or .value == "2" or .value == "3" or
                             .value == "4" or .value == "5" or .value == "6" or .value == "7")))
             then "unmapped-known-bitfields"
        else "unmapped-unsupported-values" end
    ' "$file" 2>/dev/null) || return 1
    case $classification in
        none|unmapped-known-bitfields|unmapped-unsupported-values) UBS24OP_MATERIAL_OTHER_FLAGS=$classification ;;
        *) return 1 ;;
    esac
    classification=$(jq -er '
        .data[0].vpn.data.data as $d |
        if ($d|has("remote-cert-tls")|not) then "absent"
        elif $d["remote-cert-tls"] == "server" then "server"
        else "other-or-unsupported" end
    ' "$file" 2>/dev/null) || return 1
    case $classification in absent|server|other-or-unsupported) UBS24OP_MATERIAL_SERVER_CERT=$classification ;; *) return 1 ;; esac
    classification=$(jq -er '
        .data[0].vpn.data.data as $d |
        if ($d|has("verify-x509-name")) or ($d|has("tls-remote"))
           then "name-check-reference-present" else "no-name-check-reference" end
    ' "$file" 2>/dev/null) || return 1
    case $classification in name-check-reference-present|no-name-check-reference) UBS24OP_MATERIAL_NAME_CHECK=$classification ;; *) return 1 ;; esac
    UBS24OP_MATERIAL_STATE=metadata-only-not-admitting
}

ubs24op_material_authorize_nm_write() { return 1; }
ubs24op_material_authorize_activation() { return 1; }
ubs24op_material_authorize_nft() { return 1; }
