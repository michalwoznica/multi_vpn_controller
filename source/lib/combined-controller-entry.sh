#!/usr/bin/env bash
# Multi VPN Controller 2.4.x: public dispatcher (legacy internal namespace retained).
# Public v2.4.0 compatibility dispatcher. Combined, OpenVPN-only and standalone
# protected WireGuard are admitted through separately authenticated coordinators.
# WireGuard-only --split is admitted through its standalone compatibility coordinator.

mvc24e_error() { printf 'Multi VPN Controller: %s\n' "$*" >&2; }

# This constant must only be changed when the connection and disconnection
# paths have had full activation/rollback and real-network validation. No
# environment variable, command-line flag or journal may override this gate.
mvc24e_operational_ready() { return 1; }

# The older broad operational gate remains deliberately off. Live authority is
# narrower: only the exact dispatcher call frame can admit the public live
# coordinators. An environment variable alone cannot satisfy this witness
# because dispatch shadows it with a local value and the direct caller must be
# mvc24e_dispatch.
mvc24e_c23aw_live_ready() {
    (( $# == 0 )) || return 1
    [[ ${MVC24E_DISPATCH_CONTEXT:-} == c23aw-explicit-combined-live &&
       ${FUNCNAME[1]:-} == mvc24e_dispatch ]]
}

# Public preflight uses the exact same read-only admission/binding that precedes
# live connect, but stops before any authority token or mutation is created.
# This keeps diagnostics and the released connect coordinator on one path.
mvc24e_preflight_adapter() {
    (( $# == 3 )) && [[ $2 == --split ]] || return 2
    mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
    if mvc24pubc_preflight_readonly "$1" "$3"; then
        printf '%s\n' 'PASS: exact public combined-mode read-only admission'
        printf '%s\n' 'RESULT: READ-ONLY MVC COMBINED SESSION ELIGIBLE — NO HOST CHANGES'
        return 0
    fi
    mvc24e_error "Preflight failed at stage: ${MVC24PUBC_STAGE:-unverified}; c4=${MVC24GC4_PREFLIGHT_STAGE:-unverified}"
    return 1
}

mvc24e_dispatch() {
    local verb=${1:-}
    case "$verb" in
        version|--version)
            (( $# == 1 )) || return 2
            printf '%s\n' 'Multi VPN Controller 2.4.1'
            ;;
        preflight)
            # Explicit read-only admission verb; v2.3.0 is not involved.
            (( EUID == 0 )) || { mvc24e_error 'Run preflight with sudo.'; return 1; }
            if (( $# == 2 )); then
                local single_kind
                mvc24_parse_command connect "$2" || return $?
                mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
                single_kind=$(mvc24pub_saved_profile_kind "$MVC24_PRIMARY_PROFILE") || {
                    mvc24e_error 'Selected single profile is not an exact saved OpenVPN/WireGuard profile.'
                    return 2
                }
                if [[ $single_kind == wireguard ]]; then
                    if mvc24gwg_preflight_readonly "$MVC24_PRIMARY_PROFILE"; then
                        printf '%s\n' 'PASS: exact public WireGuard-only protected read-only admission'
                        printf '%s\n' 'RESULT: READ-ONLY MVC WIREGUARD PROTECTED SESSION ELIGIBLE — NO HOST CHANGES'
                        return 0
                    fi
                    mvc24e_error "WireGuard-only protected preflight failed at stage: ${MVC24GWG_STAGE:-unverified}"
                    return 1
                fi
                if mvc24pubc_preflight_openvpn_readonly "$MVC24_PRIMARY_PROFILE"; then
                    printf '%s\n' 'PASS: exact public OpenVPN-only read-only admission'
                    printf '%s\n' 'RESULT: READ-ONLY MVC OPENVPN SESSION ELIGIBLE — NO HOST CHANGES'
                    return 0
                fi
                mvc24e_error "OpenVPN-only preflight failed at stage: ${MVC24PUBC_STAGE:-unverified}; c4=${MVC24GC4_PREFLIGHT_STAGE:-unverified}"
                return 1
            fi
            if (( $# == 3 )) && [[ "$3" == --split ]]; then
                local split_kind
                mvc24_parse_command connect "$2" "$3" || return $?
                [[ "$MVC24_MODE" == split ]] || return 2
                mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
                split_kind=$(mvc24pub_saved_profile_kind "$MVC24_PRIMARY_PROFILE") || {
                    mvc24e_error 'Selected split profile is not an exact saved WireGuard profile.'
                    return 2
                }
                [[ $split_kind == wireguard ]] || { mvc24e_error '--split is supported only for WireGuard.'; return 2; }
                if mvc24gws_preflight_readonly "$MVC24_PRIMARY_PROFILE"; then
                    printf '%s\n' 'PASS: exact public WireGuard-only split read-only admission'
                    printf '%s\n' 'RESULT: READ-ONLY MVC WIREGUARD SPLIT SESSION ELIGIBLE — NO HOST CHANGES'
                    return 0
                fi
                mvc24e_error "WireGuard-only split preflight failed at stage: ${MVC24GWS_STAGE:-unverified}"
                return 1
            fi
            (( $# == 4 )) && [[ "$3" == --split ]] || {
                mvc24e_error 'Usage: mvc preflight OPENVPN | preflight WIREGUARD | preflight WIREGUARD --split | preflight WIREGUARD --split OPENVPN'
                return 2
            }
            mvc24_parse_command connect "$2" "$3" "$4" || return $?
            [[ "$MVC24_MODE" == combined ]] || return 2
            mvc24e_preflight_adapter "$MVC24_PRIMARY_PROFILE" --split "$MVC24_OVPN_PROFILE"
            ;;
        list)
            (( $# == 1 )) || return 2
            (( EUID == 0 )) || { mvc24e_error 'Run list with sudo.'; return 1; }
            mvc24pub_list_readonly
            ;;
        status)
            (( $# == 1 )) || return 2
            (( EUID == 0 )) || { mvc24e_error 'Run status with sudo.'; return 1; }
            mvc24pub_status_readonly
            ;;
        connect)
            mvc24_parse_command "$@" || return $?
            (( EUID == 0 )) || { mvc24e_error 'Run connect with sudo.'; return 1; }
            case ${MVC24_MODE:-} in
                protected)
                    local single_kind
                    mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
                    single_kind=$(mvc24pub_saved_profile_kind "$MVC24_PRIMARY_PROFILE") || {
                        mvc24e_error 'Selected single profile is not an exact saved OpenVPN/WireGuard profile.'
                        return 2
                    }
                    local MVC24E_DISPATCH_CONTEXT=c23aw-explicit-combined-live
                    mvc24e_c23aw_live_ready || { mvc24e_error 'Live dispatcher refused authority.'; return 78; }
                    if [[ $single_kind == wireguard ]]; then
                        if mvc24pubc_connect_wireguard_protected_once "$MVC24_PRIMARY_PROFILE"; then
                            printf '%s\n' 'PASS: protected WireGuard-only session started'
                            printf '%s\n' 'RESULT: WIREGUARD PROTECTED SESSION ACTIVE — ordinary Internet is kill-switched; use vpn-v240 disconnect for authenticated same-boot teardown'
                            return 0
                        fi
                    elif mvc24pubc_connect_openvpn_once "$MVC24_PRIMARY_PROFILE"; then
                        printf '%s\n' 'PASS: protected OpenVPN-only session started'
                        printf '%s\n' 'RESULT: OPENVPN SESSION ACTIVE — use vpn-v240 disconnect for authenticated same-boot teardown'
                        return 0
                    fi
                    ;;
                combined)
                    [[ -n ${MVC24_PRIMARY_PROFILE:-} && -n ${MVC24_OVPN_PROFILE:-} ]] || return 2
                    mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
                    local MVC24E_DISPATCH_CONTEXT=c23aw-explicit-combined-live
                    mvc24e_c23aw_live_ready || { mvc24e_error 'Combined live dispatcher refused authority.'; return 78; }
                    if mvc24pubc_connect_once "$MVC24_PRIMARY_PROFILE" "$MVC24_OVPN_PROFILE"; then
                        printf '%s\n' 'PASS: protected parallel OpenVPN + WireGuard session started'
                        printf '%s\n' 'RESULT: DUAL SESSION ACTIVE — use vpn-v240 disconnect for authenticated same-boot teardown'
                        return 0
                    fi
                    ;;
                split)
                    [[ -n ${MVC24_PRIMARY_PROFILE:-} && -z ${MVC24_OVPN_PROFILE:-} ]] || return 2
                    mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
                    local split_kind
                    split_kind=$(mvc24pub_saved_profile_kind "$MVC24_PRIMARY_PROFILE") || {
                        mvc24e_error 'Selected split profile is not an exact saved WireGuard profile.'
                        return 2
                    }
                    [[ $split_kind == wireguard ]] || { mvc24e_error '--split is supported only for WireGuard.'; return 2; }
                    local MVC24E_DISPATCH_CONTEXT=c23aw-explicit-combined-live
                    mvc24e_c23aw_live_ready || { mvc24e_error 'Split live dispatcher refused authority.'; return 78; }
                    if mvc24pubc_connect_wireguard_split_once "$MVC24_PRIMARY_PROFILE"; then
                        printf '%s\n' 'PASS: WireGuard-only split session started'
                        printf '%s\n' 'RESULT: WIREGUARD SPLIT SESSION ACTIVE — ordinary Internet remains on the physical underlay; use vpn-v240 disconnect for authenticated same-boot teardown'
                        return 0
                    fi
                    ;;
                *) return 2 ;;
            esac
            case ${MVC24PUBC_STAGE:-unverified} in
                *-auto-cleaned-baseline|connect-failed-clean-baseline-restored)
                    mvc24e_error "Connect failed at stage: ${MVC24PUBC_STAGE}; authenticated cleanup completed."
                    printf '%s\n' 'RESULT: CONNECT FAILED — AUTHENTICATED CLEANUP COMPLETE; BASELINE RESTORED'
                    ;;
                *)
                    mvc24e_error "Connect failed at stage: ${MVC24PUBC_STAGE:-unverified}; authenticated state may remain. Run vpn-v240 disconnect once; if it refuses, inspect packaged recovery tools."
                    ;;
            esac
            return 1
            ;;
        disconnect)
            mvc24_parse_command "$@" || return $?
            (( EUID == 0 )) || { mvc24e_error 'Run disconnect with sudo.'; return 1; }
            mvc24pub_process_initialize || { mvc24e_error 'Public process initialization failed.'; return 1; }
            local MVC24E_DISPATCH_CONTEXT=c23aw-explicit-combined-live
            mvc24e_c23aw_live_ready || { mvc24e_error 'Combined live dispatcher refused authority.'; return 78; }
            if mvc24pubd_disconnect_once; then
                case ${MVC24PUBD_STAGE:-unverified} in
                    already-clean-baseline|public-partial-session-clean-no-mutation)
                        printf '%s\n' 'PASS: no managed v2.4 session requires teardown'
                        printf '%s\n' 'RESULT: ALREADY CLEAN — BASELINE NETWORKING'
                        ;;
                    public-openvpn-session-complete-sameboot-ready)
                        printf '%s\n' 'PASS: authenticated OpenVPN-only session stopped and finalized'
                        printf '%s\n' 'RESULT: OPENVPN SESSION COMPLETE — SAME-BOOT FRESH SESSION ELIGIBLE'
                        ;;
                    public-wireguard-protected-session-complete-sameboot-ready)
                        printf '%s\n' 'PASS: authenticated WireGuard-only protected session stopped and finalized'
                        printf '%s\n' 'RESULT: WIREGUARD PROTECTED SESSION COMPLETE — SAME-BOOT FRESH SESSION ELIGIBLE'
                        ;;
                    public-wireguard-split-session-complete-sameboot-ready)
                        printf '%s\n' 'PASS: authenticated WireGuard-only split session stopped and finalized'
                        printf '%s\n' 'RESULT: WIREGUARD SPLIT SESSION COMPLETE — SAME-BOOT FRESH SESSION ELIGIBLE'
                        ;;
                    public-openvpn-partial-session-complete-sameboot-ready|public-incomplete-openvpn-start-clean-baseline-restored)
                        printf '%s\n' 'PASS: authenticated partial OpenVPN session stopped and finalized'
                        printf '%s\n' 'RESULT: PARTIAL SESSION CLEANUP COMPLETE — BASELINE RESTORED'
                        ;;
                    *)
                        printf '%s\n' 'PASS: authenticated same-boot parallel session stopped and finalized'
                        printf '%s\n' 'RESULT: DUAL SESSION COMPLETE — SAME-BOOT FRESH SESSION ELIGIBLE'
                        ;;
                esac
                return 0
            fi
            mvc24e_error "Disconnect failed at stage: ${MVC24PUBD_STAGE:-unverified}; authenticated state may remain. Do not retry blindly; inspect packaged recovery tools."
            return 1
            ;;
        *)
            mvc24e_error 'Usage: vpn-v240 {version|preflight OPENVPN|preflight WIREGUARD|preflight WIREGUARD --split|preflight WG --split OVPN|list|status|connect OPENVPN|connect WIREGUARD|connect WIREGUARD --split|connect WG --split OVPN|disconnect}'
            return 2
            ;;
    esac
}

# Strict, read-only /run boundary. For testing, caller supplies its
# own uid and stubs the fs-type accessor; the production wrapper uses uid 0.
# The future live controller must validate this under the process lock BEFORE
# creating session data. This routine NEVER creates a directory or file.
mvc24e_fs_type() { stat -f -c %T -- "$1"; }
mvc24e_runtime_root_valid() {
    (( $# == 2 )) || return 1
    local root=$1 uid=$2 entry name mode
    [[ "$root" == /* && "$root" != / && "$root" != */ &&
       "$root" != *//* && "$root" != */./* && "$root" != */../* &&
       "$root" != */. && "$root" != */.. &&
       "$root" != *$'\n'* && "$root" != *$'\r'* && "$root" != *$'\t'* ]] || return 1
    [[ "$uid" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    local ancestor=$root
    while [[ "$ancestor" != / ]]; do
        [[ ! -L "$ancestor" ]] || return 1
        ancestor=${ancestor%/*}
        [[ -n "$ancestor" ]] || ancestor=/
    done
    [[ -d "$root" && ! -L "$root" ]] || return 1
    [[ $(stat -c %u -- "$root") == "$uid" &&
       $(stat -c %a -- "$root") == 700 &&
       $(mvc24e_fs_type "$root") == tmpfs ]] || return 1
    for entry in "$root"/* "$root"/.[!.]* "$root"/..?*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        name=${entry##*/}
        case "$name" in
            controller.lock|state)
                [[ -f "$entry" && ! -L "$entry" &&
                   $(stat -c %u -- "$entry") == "$uid" &&
                   $(stat -c %a -- "$entry") == 600 &&
                   $(stat -c %h -- "$entry") == 1 ]] || return 1
                ;;
            session|captures)
                [[ -d "$entry" && ! -L "$entry" &&
                   $(stat -c %u -- "$entry") == "$uid" &&
                   $(stat -c %a -- "$entry") == 700 ]] || return 1
                ;;
            *) return 1 ;;
        esac
    done
}

mvc24e_production_root_valid() {
    (( $# == 0 )) || return 1
    # /run must be the real root-controlled tmpfs, not an attacker-supplied
    # alternate runtime or a symlink. This does not prepare the directory.
    [[ -d /run && ! -L /run &&
       $(stat -c %u -- /run) == 0 &&
       $(mvc24e_fs_type /run) == tmpfs ]] || return 1
    local perms
    perms=$(stat -c %a -- /run) || return 1
    [[ "$perms" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$perms & 0022) == 0 )) || return 1
    mvc24e_runtime_root_valid /run/ubs-vpn-controller-v240 0
}
