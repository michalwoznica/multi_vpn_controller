#!/usr/bin/env bash
# F10: privilege-scoped observation only. This is not a NetworkManager service
# or OpenVPN plugin process/namespace/sandbox impersonation. No TLS data opened.

ubs24op_root_material_reset() {
    UBS24OP_ROOT_CA=unassessed
    UBS24OP_ROOT_TLS_CRYPT=unassessed
    UBS24OP_ROOT_STATE=unverified
}

ubs24op_root_material_observe() {
    ubs24op_root_material_reset
    (( $# == 1 && EUID == 0 )) || return 1
    # Reuse the F9 conservative pathname traversal (symlinks, component
    # spelling, missing and nonregular leafs). It already rejects secrets.
    ubs24op_path_triage "$1" || return 1
    case $UBS24OP_TRIAGE_CA in
        regular-readable-by-caller) UBS24OP_ROOT_CA=regular-readable-by-root ;;
        regular-not-readable-by-caller) UBS24OP_ROOT_CA=regular-not-readable-by-root ;;
        ancestor-search-denied-to-caller) UBS24OP_ROOT_CA=ancestor-search-denied-to-root ;;
        missing-ancestor-as-caller) UBS24OP_ROOT_CA=missing-ancestor-as-root ;;
        missing-leaf-as-caller) UBS24OP_ROOT_CA=missing-leaf-as-root ;;
        absent|unsupported-reference|nonabsolute-or-inline|unsupported-path-spelling|symlink-ancestor|non-directory-ancestor|symlink-reference|nonregular)
            UBS24OP_ROOT_CA=$UBS24OP_TRIAGE_CA ;;
        *) return 1 ;;
    esac
    case $UBS24OP_TRIAGE_TLS_CRYPT in
        regular-readable-by-caller) UBS24OP_ROOT_TLS_CRYPT=regular-readable-by-root ;;
        regular-not-readable-by-caller) UBS24OP_ROOT_TLS_CRYPT=regular-not-readable-by-root ;;
        ancestor-search-denied-to-caller) UBS24OP_ROOT_TLS_CRYPT=ancestor-search-denied-to-root ;;
        missing-ancestor-as-caller) UBS24OP_ROOT_TLS_CRYPT=missing-ancestor-as-root ;;
        missing-leaf-as-caller) UBS24OP_ROOT_TLS_CRYPT=missing-leaf-as-root ;;
        absent|unsupported-reference|nonabsolute-or-inline|unsupported-path-spelling|symlink-ancestor|non-directory-ancestor|symlink-reference|nonregular)
            UBS24OP_ROOT_TLS_CRYPT=$UBS24OP_TRIAGE_TLS_CRYPT ;;
        *) return 1 ;;
    esac
    UBS24OP_ROOT_STATE=root-caller-metadata-only-not-admitting
}

ubs24op_root_material_authorize_nm_write() { return 1; }
ubs24op_root_material_authorize_activation() { return 1; }
ubs24op_root_material_authorize_nft() { return 1; }
