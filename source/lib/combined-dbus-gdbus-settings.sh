#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 — optional read-only GDBus GetSettings capture.
# Uses Bash, GDBus, standard awk, jq; no systemd utilities, no Python.
# The bounded decoder accepts only unambiguous typed GVariant forms. It never
# evaluates D-Bus strings. Unrecognised forms fail, rather than lose type data.

# Optional diagnostics never print profile contents or raw GVariant data.
# Enabled only for a deliberate read-only probe invocation.
mvc24gs_diag() {
    [[ ${MVC24_GDBUS_SETTINGS_DIAG:-} == 1 ]] || return 0
    case ${1:-} in
        method-failed) printf 'DIAG: GetSettings D-Bus call failed or was denied\n' >&2 ;;
        reply-size) printf 'DIAG: GetSettings reply empty or exceeded bounded input size\n' >&2 ;;
        decoder-failed) printf 'DIAG: GetSettings typed GVariant decoder rejected response\n' >&2 ;;
        shape-failed) printf 'DIAG: decoded GetSettings JSON failed schema validation\n' >&2 ;;
    esac
}

mvc24gs_capture_settings() {
    (( $# == 2 )) || return 1
    local object=$1 output=$2 raw='' decoder
    [[ ${MVC24S_LOCK_HELD:-} == 1 ]] || return 1
    [[ $object =~ ^/org/freedesktop/NetworkManager/Settings/[0-9]+$ ]] || return 1
    [[ $output == /* && -f $output && ! -L $output ]] || return 1
    command -v gdbus >/dev/null 2>&1 && command -v awk >/dev/null 2>&1 &&
      command -v jq >/dev/null 2>&1 || return 1
    decoder=${BASH_SOURCE[0]%/*}/combined-gvariant-settings-to-json.awk
    [[ -f $decoder && ! -L $decoder ]] || return 1
    raw=$(LC_ALL=C gdbus call --system --timeout 5 \
      --dest org.freedesktop.NetworkManager \
      --object-path "$object" \
      --method org.freedesktop.NetworkManager.Settings.Connection.GetSettings \
      2>/dev/null) || { mvc24gs_diag method-failed; return 1; }
    if (( ${#raw} == 0 || ${#raw} > 262144 )); then
        mvc24gs_diag reply-size
        return 1
    fi
    if ! printf '%s\n' "$raw" | LC_ALL=C awk \
      -v mvc24_variant_diag="${MVC24_GDBUS_SETTINGS_DIAG:-0}" \
      -f "$decoder" > "$output"; then
        mvc24gs_diag decoder-failed
        return 1
    fi
    if ! jq -e '.type == "a{sa{sv}}" and (.data | type) == "array" and (.data | length) == 1 and (.data[0] | type) == "object"' "$output" >/dev/null 2>&1; then
        mvc24gs_diag shape-failed
        return 1
    fi
}
