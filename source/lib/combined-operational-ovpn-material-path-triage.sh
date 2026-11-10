#!/usr/bin/env bash
# Step 2B2C3F9. Independent, non-admitting metadata-only triage.
# No TLS contents, credential values, paths or identifiers are printed.
# The result describes caller-visible filesystem state at a moment in time;
# it is NOT NM/OpenVPN file custody or TLS trust evidence.

mvc24op_path_triage_reset() {
    UBS24OP_TRIAGE_CA=unassessed
    UBS24OP_TRIAGE_TLS_CRYPT=unassessed
    UBS24OP_TRIAGE_STATE=unverified
}

mvc24op_path_triage_reference() {
    (( $# == 2 )) || return 1
    local file=$1 key=$2 value item prefix index
    local -a components=()
    case $key in ca|tls-crypt) ;; *) return 1 ;; esac
    UBS24OP_TRIAGE_REF=unassessed

    # First apply the existing conservative classifier. Re-examine even
    # readable paths to detect unsafe ancestor symlinks and path spelling.
    mvc24op_material_reference "$file" "$key" || return 1
    UBS24OP_TRIAGE_REF=$UBS24OP_MATERIAL_REF
    case $UBS24OP_TRIAGE_REF in
        absent|unsupported-reference|nonabsolute-or-inline) return 0 ;;
        *) : ;;
    esac

    # This read is from the already authenticated private GetSettings snapshot;
    # never export, log or print the value.
    value=$(jq -r --arg key "$key" '.data[0].vpn.data.data[$key]' "$file") || return 1
    # Reject ambiguous /./, /../, repeated separators or trailing separators.
    # No canonicalisation, realpath, pathname interpolation, or symlink follow.
    if [[ $value != /* ]]; then
        UBS24OP_TRIAGE_REF=unsupported-path-spelling
        return 0
    fi
    if [[ $value == */ || $value == */./* || $value == */../* || $value == */. || $value == */.. || $value == *//* ]]; then
        UBS24OP_TRIAGE_REF=unsupported-path-spelling
        return 0
    fi
    IFS='/' read -r -a components <<< "${value#/}"
    if (( ${#components[@]} < 1 || ${#components[@]} > 128 )); then
        UBS24OP_TRIAGE_REF=unsupported-path-spelling
        return 0
    fi
    prefix=''
    # Walk *parents* only; don't open files and don't dereference symlinks.
    for ((index=0; index<${#components[@]}-1; index++)); do
        item=${components[index]}
        [[ -n $item && $item != . && $item != .. ]] || {
            UBS24OP_TRIAGE_REF=unsupported-path-spelling
            return 0
        }
        prefix+=/$item
        if [[ -L $prefix ]]; then
            UBS24OP_TRIAGE_REF=symlink-ancestor
            return 0
        elif [[ ! -d $prefix ]]; then
            if [[ -e $prefix ]]; then
                UBS24OP_TRIAGE_REF=non-directory-ancestor
            else
                UBS24OP_TRIAGE_REF=missing-ancestor-as-caller
            fi
            return 0
        elif [[ ! -x $prefix ]]; then
            UBS24OP_TRIAGE_REF=ancestor-search-denied-to-caller
            return 0
        fi
    done
    # The metadata checks are raceable, and only reflect caller permissions.
    if [[ -L $value ]]; then
        UBS24OP_TRIAGE_REF=symlink-reference
    elif [[ ! -e $value ]]; then
        UBS24OP_TRIAGE_REF=missing-leaf-as-caller
    elif [[ ! -f $value ]]; then
        UBS24OP_TRIAGE_REF=nonregular
    elif [[ -r $value ]]; then
        UBS24OP_TRIAGE_REF=regular-readable-by-caller
    else
        UBS24OP_TRIAGE_REF=regular-not-readable-by-caller
    fi
}

mvc24op_path_triage() {
    mvc24op_path_triage_reset
    (( $# == 1 )) || return 1
    local file=$1
    # The existing preflight validates private capture metadata and rejects a
    # secrets dictionary; preserve that prerequisite rather than relaxing it.
    mvc24op_material_preflight "$file" || return 1
    mvc24op_path_triage_reference "$file" ca || return 1
    UBS24OP_TRIAGE_CA=$UBS24OP_TRIAGE_REF
    mvc24op_path_triage_reference "$file" tls-crypt || return 1
    UBS24OP_TRIAGE_TLS_CRYPT=$UBS24OP_TRIAGE_REF
    UBS24OP_TRIAGE_STATE=caller-metadata-only-not-admitting
}

mvc24op_path_triage_authorize_nm_write() { return 1; }
mvc24op_path_triage_authorize_activation() { return 1; }
mvc24op_path_triage_authorize_nft() { return 1; }
