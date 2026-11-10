#!/usr/bin/env bash
# Multi VPN Controller 2.4.1 — release-candidate installer.
# File-management only. Never mutates VPN/network state.
# Lowercase internal functions use mvc24*; uppercase internal variables use MVC24*.
set -euo pipefail
umask 077
export LC_ALL=C

mvc24i_die() { printf 'install-mvc: %s\n' "$*" >&2; exit 1; }
mvc24i_usage() {
    cat <<'USAGE'
Usage:
  sudo ./source/tools/install-mvc.sh install [--root ROOT]
  sudo ./source/tools/install-mvc.sh update [--root ROOT]
  sudo ./source/tools/install-mvc.sh verify [--root ROOT]
  sudo ./source/tools/install-mvc.sh uninstall [--root ROOT]

Without --root, manages:
  /usr/local/sbin/mvc
  /root/mvc-emergency-rollback
  /root/mvc-dual-recovery

Existing MVC files are replaced only when their identity matches this package.
Unknown existing files are never overwritten or removed.

--root is for isolated fake-root testing only. It prefixes all managed paths and
never inspects or mutates the real host network.
USAGE
}

(( EUID == 0 )) || mvc24i_die 'must run as root'
(( $# >= 1 )) || { mvc24i_usage >&2; exit 2; }
action=$1
shift
case $action in install|update|verify|uninstall) ;; *) mvc24i_usage >&2; exit 2 ;; esac

root_prefix=/
if (( $# > 0 )); then
    (( $# == 2 )) && [[ $1 == --root ]] || { mvc24i_usage >&2; exit 2; }
    root_prefix=$2
fi
[[ $root_prefix == /* && -d $root_prefix && ! -L $root_prefix ]] || mvc24i_die 'ROOT must be an existing absolute real directory'
root_prefix=$(cd -- "$root_prefix" && pwd -P) || exit 1

script=${BASH_SOURCE[0]}
[[ $script == /* ]] || script=$PWD/$script
script_dir=$(cd -- "${script%/*}" && pwd -P) || exit 1
project_root=$(cd -- "$script_dir/../.." && pwd -P) || exit 1
controller_src=$project_root/dist/mvc
emergency_src=$project_root/source/tools/recover-mvc-host-guard-local.sh
dual_src=$project_root/source/tools/recover-mvc-dual-local.sh
manifest=$project_root/source/build/monolith-runtime.manifest
builder=$project_root/source/build/build-mvc-monolith.sh


mvc24i_target() {
    (( $# == 1 )) || return 1
    if [[ $root_prefix == / ]]; then printf '%s\n' "$1"; else printf '%s%s\n' "$root_prefix" "$1"; fi
}
controller_dst=$(mvc24i_target /usr/local/sbin/mvc)
emergency_dst=$(mvc24i_target /root/mvc-emergency-rollback)
dual_dst=$(mvc24i_target /root/mvc-dual-recovery)

mvc24i_hash() { sha256sum -- "$1" | awk '{print $1}'; }
mvc24i_info_value() {
    (( $# == 2 )) || return 1
    local text=$1 key=$2 line count
    count=$(grep -c "^${key}=" <<<"$text" || :)
    [[ $count == 1 ]] || return 1
    line=$(grep "^${key}=" <<<"$text")
    printf '%s\n' "${line#*=}"
}

mvc24i_package_verify() {
    local f info manifest_sha builder_sha emergency_sha dual_sha
    for f in "$controller_src" "$emergency_src" "$dual_src" "$manifest" "$builder"; do
        [[ -f $f && ! -L $f ]] || mvc24i_die "package input missing or unsafe: $f"
    done
    [[ -x $controller_src ]] || mvc24i_die 'generated controller is not executable'
    bash -n "$controller_src" || mvc24i_die 'generated controller fails bash -n'
    info=$($controller_src --monolith-build-info) || mvc24i_die 'cannot read generated controller provenance'
    manifest_sha=$(mvc24i_hash "$manifest")
    builder_sha=$(mvc24i_hash "$builder")
    emergency_sha=$(mvc24i_hash "$emergency_src")
    dual_sha=$(mvc24i_hash "$dual_src")
    [[ $(mvc24i_info_value "$info" checkpoint) == MVC_R7_STANDALONE_PUBLIC_IDENTITY ]] || mvc24i_die 'controller checkpoint mismatch'
    [[ $(mvc24i_info_value "$info" authority) == audited-dispatch-mvc-v241-candidate-physical-pending ]] || mvc24i_die 'controller authority provenance mismatch'
    [[ $(mvc24i_info_value "$info" manifest_sha256) == "$manifest_sha" ]] || mvc24i_die 'controller/manifest provenance mismatch'
    [[ $(mvc24i_info_value "$info" builder_sha256) == "$builder_sha" ]] || mvc24i_die 'controller/builder provenance mismatch'
    [[ $(mvc24i_info_value "$info" emergency_recovery_sha256) == "$emergency_sha" ]] || mvc24i_die 'emergency recovery provenance mismatch'
    [[ $(mvc24i_info_value "$info" dual_recovery_sha256) == "$dual_sha" ]] || mvc24i_die 'dual recovery provenance mismatch'
}

mvc24i_assert_destination_parent() {
    (( $# == 1 )) || return 1
    local d=${1%/*}
    [[ -d $d && ! -L $d && $(stat -c %u -- "$d") == 0 ]] || mvc24i_die "destination directory is unsafe: $d"
}

mvc24i_assert_target_replaceable() {
    (( $# == 1 )) || return 1
    local p=$1
    [[ ! -e $p && ! -L $p ]] && return 0
    [[ -f $p && ! -L $p && $(stat -c %u:%g:%h -- "$p") == 0:0:1 ]] || \
        mvc24i_die "refusing to replace unsafe target: $p"
}

mvc24i_assert_existing_identity() {
    local emergency_sha dual_sha
    emergency_sha=$(mvc24i_hash "$emergency_src")
    dual_sha=$(mvc24i_hash "$dual_src")
    if [[ -f $controller_dst && ! -L $controller_dst ]]; then
        [[ $(mvc24i_hash "$controller_dst") == $(mvc24i_hash "$controller_src") ]] || \
            mvc24i_die 'refusing to replace unrecognized existing MVC controller'
    fi
    if [[ -f $emergency_dst && ! -L $emergency_dst ]]; then
        [[ $(mvc24i_hash "$emergency_dst") == "$emergency_sha" ]] || \
            mvc24i_die 'refusing to replace unrecognized MVC emergency recovery tool'
    fi
    if [[ -f $dual_dst && ! -L $dual_dst ]]; then
        [[ $(mvc24i_hash "$dual_dst") == "$dual_sha" ]] || \
            mvc24i_die 'refusing to replace unrecognized MVC dual recovery tool'
    fi
}


mvc24i_assert_quiescent() {
    local rel p active
    # Refuse package maintenance whenever MVC-owned runtime state is present.
    for rel in \
        /run/mvc-controller /run/mvc-activation \
        /run/mvc-output-transition /run/mvc-disconnect \
        /run/mvc-completion /run/mvc-wireguard \
        /run/mvc-public-session; do
        p=$(mvc24i_target "$rel")
        [[ ! -e $p && ! -L $p ]] || mvc24i_die "managed runtime state is present; refuse package maintenance: $rel"
    done

    [[ $root_prefix != / ]] && return 0

    command -v nmcli >/dev/null 2>&1 || mvc24i_die 'cannot prove quiescent state: nmcli missing'
    command -v ip >/dev/null 2>&1 || mvc24i_die 'cannot prove quiescent state: ip missing'
    active=$(nmcli -t -f NAME connection show --active) || mvc24i_die 'cannot read active NetworkManager connections'
    ! grep -Fxq 'vpnks-ovpn' <<<"$active" || mvc24i_die 'managed OpenVPN connection is active; refuse package maintenance'
    ! grep -Fxq 'vpnks-wg' <<<"$active" || mvc24i_die 'managed WireGuard connection is active; refuse package maintenance'
    ! ip link show dev tun-vpnks >/dev/null 2>&1 || mvc24i_die 'managed tun-vpnks link is present; refuse package maintenance'
    ! ip link show dev vpnks-wg >/dev/null 2>&1 || mvc24i_die 'managed vpnks-wg link is present; refuse package maintenance'
}

mvc24i_verify_one() {
    (( $# == 4 )) || return 1
    local path=$1 mode=$2 expected_sha=$3 label=$4
    [[ -f $path && ! -L $path ]] || mvc24i_die "$label is missing or unsafe: $path"
    [[ $(stat -c %u:%g:%a:%h -- "$path") == "0:0:${mode}:1" ]] || mvc24i_die "$label ownership/mode mismatch: $path"
    [[ $(mvc24i_hash "$path") == "$expected_sha" ]] || mvc24i_die "$label content mismatch: $path"
}

mvc24i_verify_installed() {
    local controller_sha emergency_sha dual_sha info
    controller_sha=$(mvc24i_hash "$controller_src")
    emergency_sha=$(mvc24i_hash "$emergency_src")
    dual_sha=$(mvc24i_hash "$dual_src")
    mvc24i_verify_one "$controller_dst" 755 "$controller_sha" controller
    mvc24i_verify_one "$emergency_dst" 700 "$emergency_sha" 'emergency recovery tool'
    mvc24i_verify_one "$dual_dst" 700 "$dual_sha" 'dual recovery tool'
    [[ $($controller_dst version) == 'Multi VPN Controller 2.4.1' ]] || mvc24i_die 'installed controller version mismatch'
    info=$($controller_dst --monolith-build-info) || mvc24i_die 'installed controller provenance unreadable'
    [[ $(mvc24i_info_value "$info" checkpoint) == MVC_R7_STANDALONE_PUBLIC_IDENTITY ]] || mvc24i_die 'installed controller checkpoint mismatch'
    [[ $(mvc24i_info_value "$info" emergency_recovery_sha256) == "$emergency_sha" ]] || mvc24i_die 'installed emergency recovery identity mismatch'
    [[ $(mvc24i_info_value "$info" dual_recovery_sha256) == "$dual_sha" ]] || mvc24i_die 'installed dual recovery identity mismatch'
}

mvc24i_stage_file() {
    (( $# == 3 )) || return 1
    local src=$1 dst=$2 mode=$3 dir base tmp
    dir=${dst%/*}; base=${dst##*/}
    tmp=$(mktemp "$dir/.${base}.new.XXXXXXXX") || return 1
    install -o root -g root -m "$mode" -- "$src" "$tmp" || { rm -f -- "$tmp"; return 1; }
    [[ -f $tmp && ! -L $tmp && $(stat -c %u:%g:%a:%h -- "$tmp") == "0:0:${mode}:1" ]] || { rm -f -- "$tmp"; return 1; }
    printf '%s\n' "$tmp"
}

mvc24i_install_or_update() {
    local emergency_tmp dual_tmp controller_tmp
    mvc24i_package_verify
    mvc24i_assert_quiescent
    mvc24i_assert_destination_parent "$controller_dst"
    mvc24i_assert_destination_parent "$emergency_dst"
    mvc24i_assert_destination_parent "$dual_dst"
    mvc24i_assert_target_replaceable "$controller_dst"
    mvc24i_assert_target_replaceable "$emergency_dst"
    mvc24i_assert_target_replaceable "$dual_dst"
    mvc24i_assert_existing_identity

    emergency_tmp=$(mvc24i_stage_file "$emergency_src" "$emergency_dst" 700) || mvc24i_die 'failed to stage emergency recovery tool'
    dual_tmp=$(mvc24i_stage_file "$dual_src" "$dual_dst" 700) || { rm -f -- "$emergency_tmp"; mvc24i_die 'failed to stage dual recovery tool'; }
    controller_tmp=$(mvc24i_stage_file "$controller_src" "$controller_dst" 755) || { rm -f -- "$emergency_tmp" "$dual_tmp"; mvc24i_die 'failed to stage controller'; }

    # Recoveries commit first; controller commits last. Every rename is within
    # one destination directory and therefore atomic for that file.
    mv -fT -- "$emergency_tmp" "$emergency_dst" || { rm -f -- "$emergency_tmp" "$dual_tmp" "$controller_tmp"; mvc24i_die 'failed to commit emergency recovery tool'; }
    mv -fT -- "$dual_tmp" "$dual_dst" || { rm -f -- "$dual_tmp" "$controller_tmp"; mvc24i_die 'failed to commit dual recovery tool'; }
    mv -fT -- "$controller_tmp" "$controller_dst" || { rm -f -- "$controller_tmp"; mvc24i_die 'failed to commit controller; recovery tools may already be updated, which is fail-closed'; }

    mvc24i_verify_installed
    printf 'RESULT: MULTI VPN CONTROLLER 2.4.1 FILE SET INSTALLED AND VERIFIED%s\n' "$( [[ $root_prefix == / ]] && printf '' || printf ' IN FAKE ROOT' )"
}

mvc24i_uninstall() {
    local p
    mvc24i_assert_quiescent
    for p in "$controller_dst" "$emergency_dst" "$dual_dst"; do
        [[ ! -e $p && ! -L $p ]] && continue
        [[ -f $p && ! -L $p && $(stat -c %u:%g:%h -- "$p") == 0:0:1 ]] || mvc24i_die "refusing to remove unsafe target: $p"
    done
    if [[ -f $controller_dst && ! -L $controller_dst ]]; then
        [[ $(mvc24i_hash "$controller_dst") == $(mvc24i_hash "$controller_src") ]] || \
            mvc24i_die 'refusing to remove unrecognized MVC controller'
    fi
    if [[ -f $emergency_dst && ! -L $emergency_dst ]]; then
        [[ $(mvc24i_hash "$emergency_dst") == $(mvc24i_hash "$emergency_src") ]] || mvc24i_die 'refusing to remove unrecognized MVC emergency recovery tool'
    fi
    if [[ -f $dual_dst && ! -L $dual_dst ]]; then
        [[ $(mvc24i_hash "$dual_dst") == $(mvc24i_hash "$dual_src") ]] || mvc24i_die 'refusing to remove unrecognized MVC dual recovery tool'
    fi
    rm -f -- "$controller_dst" "$emergency_dst" "$dual_dst"
    for p in "$controller_dst" "$emergency_dst" "$dual_dst"; do
        [[ ! -e $p && ! -L $p ]] || mvc24i_die "failed to remove target: $p"
    done
    printf 'RESULT: MULTI VPN CONTROLLER 2.4.1 FILE SET REMOVED; NETWORK STATE WAS NOT MUTATED%s\n' "$( [[ $root_prefix == / ]] && printf '' || printf ' (FAKE ROOT)' )"
}

case $action in
    install|update) mvc24i_install_or_update ;;
    verify) mvc24i_package_verify; mvc24i_verify_installed; printf '%s\n' 'RESULT: INSTALLED MULTI VPN CONTROLLER 2.4.1 FILE SET VERIFIED' ;;
    uninstall) mvc24i_uninstall ;;
esac
