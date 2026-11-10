#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 — init-independent, read-only GDBus primitive adapter.
# OFFLINE MIGRATION WORK: not wired to the operational controller.
# Dependency: gdbus (GLib/GIO), Bash. Does not require systemd or busctl.
# Intentionally supports only simple, security-relevant typed properties/calls.
# Nested GVariant maps/arrays MUST NOT be reduced to untyped strings; migrate
# them separately before removing the old busctl based settings reader.
# GDBus display format is not a stable machine protocol. Refuse unrecognised
# spellings/escapes instead of guessing; test with a live read-only bus later.

ubs24g_safe_bus_name() {
    (( $# == 1 )) && [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)+$ || $1 =~ ^:[0-9]+\.[0-9]+$ ]]
}

ubs24g_safe_object_path() {
    (( $# == 1 )) && [[ $1 == / || $1 =~ ^(/[A-Za-z_0-9]+)+$ ]]
}

ubs24g_safe_member() {
    (( $# == 1 )) && [[ $1 =~ ^[A-Za-z_][A-Za-z_0-9]*$ ]]
}

ubs24g_safe_interface() { ubs24g_safe_bus_name "$1"; }

# Argument/result data is not shell-evaluated, and is never logged. Restrict
# this increment to ASCII values that cannot require GVariant escaping.
ubs24g_safe_string() {
    (( $# == 1 )) && [[ $1 =~ ^[a-zA-Z0-9_./:@+-]+$ ]] && ((${#1} <= 1024))
}

# Translate ONE gdbus call reply into the same typed single-value vocabulary
# historically used by the strict checks: s "...", o "...", u ..., etc.
# No regex tolerance for multiple returns, arbitrary text or injected escapes.
ubs24g_decode_one() {
    (( $# == 2 )) || return 1
    local signature=$1 raw=$2 value='' re
    (( ${#raw} <= 8192 )) || return 1
    case $signature in
      s)
        re="^\([[:space:]]*'([A-Za-z0-9_./:@+-]+)'[[:space:]]*,[[:space:]]*\)$"
        [[ $raw =~ $re ]] || return 1
        value=${BASH_REMATCH[1]}
        ubs24g_safe_string "$value" || return 1
        printf 's "%s"\n' "$value"
        ;;
      o)
        re="^\([[:space:]]*objectpath[[:space:]]+'(/[A-Za-z_0-9/]*)'[[:space:]]*,[[:space:]]*\)$"
        [[ $raw =~ $re ]] || return 1
        value=${BASH_REMATCH[1]}
        ubs24g_safe_object_path "$value" || return 1
        printf 'o "%s"\n' "$value"
        ;;
      b)
        [[ $raw =~ ^\([[:space:]]*(true|false)[[:space:]]*,[[:space:]]*\)$ ]] || return 1
        printf 'b %s\n' "${BASH_REMATCH[1]}"
        ;;
      u)
        [[ $raw =~ ^\([[:space:]]*uint32[[:space:]]+(0|[1-9][0-9]*)[[:space:]]*,[[:space:]]*\)$ ]] || return 1
        value=${BASH_REMATCH[1]}
        ((${#value} <= 10)) || return 1
        ((10#$value <= 4294967295)) || return 1
        printf 'u %s\n' "$value"
        ;;
      t)
        [[ $raw =~ ^\([[:space:]]*uint64[[:space:]]+(0|[1-9][0-9]*)[[:space:]]*,[[:space:]]*\)$ ]] || return 1
        value=${BASH_REMATCH[1]}
        # Bash integers are signed; validate decimal uint64 lexical/range.
        ((${#value} <= 20)) || return 1
        if ((${#value} == 20)); then
            [[ $value == 1* && ( $value == 1[0-7]* || $value == 18* ) ]] || return 1
            [[ $value < 18446744073709551616 ]] || return 1
        fi
        printf 't %s\n' "$value"
        ;;
      *) return 1 ;;
    esac
}

# One variant wrapper returned by org.freedesktop.DBus.Properties.Get.
# Accept only elementary GVariant spellings; prohibit nested variants,
# arrays and type confusion. Caller must supply the EXPECTED signature.
ubs24g_decode_property() {
    (( $# == 2 )) || return 1
    local signature=$1 raw=$2 inner='' re
    (( ${#raw} <= 8192 )) || return 1
    re="^\([<][[:space:]]*(.*)[[:space:]]*[>][[:space:]]*,[[:space:]]*\)$"
    [[ $raw =~ $re ]] || return 1
    inner=${BASH_REMATCH[1]}
    case "$signature" in
      s)
        re="^'([A-Za-z0-9_./:@+-]+)'[[:space:]]*$"
        [[ $inner =~ $re ]] || return 1
        ubs24g_decode_one s "('${BASH_REMATCH[1]}',)" ;;
      o)
        re="^objectpath[[:space:]]+'(/[A-Za-z_0-9/]*)'[[:space:]]*$"
        [[ $inner =~ $re ]] || return 1
        ubs24g_decode_one o "(objectpath '${BASH_REMATCH[1]}',)" ;;
      u)
        [[ $inner =~ ^uint32[[:space:]]+(0|[1-9][0-9]*)[[:space:]]*$ ]] || return 1
        ubs24g_decode_one u "(uint32 ${BASH_REMATCH[1]},)" ;;
      t)
        [[ $inner =~ ^uint64[[:space:]]+(0|[1-9][0-9]*)[[:space:]]*$ ]] || return 1
        ubs24g_decode_one t "(uint64 ${BASH_REMATCH[1]},)" ;;
      b)
        [[ $inner =~ ^(true|false)[[:space:]]*$ ]] || return 1
        ubs24g_decode_one b "(${BASH_REMATCH[1]},)" ;;
      *) return 1 ;;
    esac
}

# Bounded GVariant array decoder for two identity-only collections.
# A successful result uses historical busctl vocabulary (as/ao COUNT "item"...).
# The grammar is intentionally narrow: no escape sequences, nested containers,
# annotations inside the array, duplicated separators or untyped values.
ubs24g_decode_array() {
    (( $# == 3 )) || return 1
    local signature=$1 raw=$2 variant=$3 body='' remainder item matched
    local -a items=()
    local re
    [[ $signature == as || $signature == ao ]] || return 1
    (( ${#raw} <= 65536 )) || return 1
    # Only an EXPLICITLY typed empty object-path array is safe to classify.
    # GVariant prints bare [] without an element type. Retain the historical
    # rejection of ambiguous empty arrays and reject all untyped empties.
    if [[ $variant == property && $signature == ao &&
          $raw =~ ^\(\<@ao[[:space:]]+\[\]\>,[[:space:]]*\)$ ]]; then
        printf 'ao 0\n'
        return 0
    fi
    if [[ $variant == direct ]]; then
        re='^\(\[([^][]*)\],[[:space:]]*\)$'
    elif [[ $variant == property ]]; then
        re='^\(<\[([^][]*)\]>,[[:space:]]*\)$'
    else
        return 1
    fi
    [[ $raw =~ $re ]] || return 1
    body=${BASH_REMATCH[1]}
    # Empty arrays have no distinctive type in ordinary GVariant display;
    # never accept one as proof of a specific array signature.
    [[ -n ${body//[[:space:]]/} ]] || return 1
    while :; do
        body=${body#"${body%%[![:space:]]*}"}
        if [[ $signature == as ]]; then
            re="^'([A-Za-z0-9_.:-]+)'"
            [[ $body =~ $re ]] || return 1
            matched=${BASH_REMATCH[0]} item=${BASH_REMATCH[1]}
            ubs24g_safe_bus_name "$item" || return 1
        else
            # Real GDBus property replies may annotate only the first member
            # of an object-path array: <[objectpath '/one', '/two']>.
            # Demand the leading objectpath type annotation, then accept
            # either abbreviated or repeated annotations for later entries.
            # A bare-string first element remains ambiguous and is rejected.
            if (( ${#items[@]} == 0 )) || [[ $body == objectpath[[:space:]]* ]]; then
                re="^objectpath[[:space:]]+'(/[A-Za-z0-9_/]+)'"
            else
                re="^'(/[A-Za-z0-9_/]+)'"
            fi
            [[ $body =~ $re ]] || return 1
            matched=${BASH_REMATCH[0]} item=${BASH_REMATCH[1]}
            ubs24g_safe_object_path "$item" || return 1
        fi
        items+=("$item")
        (( ${#items[@]} <= 2048 )) || return 1
        body=${body:${#matched}}
        body=${body#"${body%%[![:space:]]*}"}
        [[ -n $body ]] || break
        [[ ${body:0:1} == , ]] || return 1
        body=${body:1}
        [[ -n ${body//[[:space:]]/} ]] || return 1
    done
    printf '%s %d' "$signature" "${#items[@]}"
    for item in "${items[@]}"; do
        printf ' "%s"' "$item"
    done
    printf '\n'
}

# Read-only zero-argument method. No arbitrary D-Bus method calls permitted.
ubs24g_call_noargs_readonly() {
    (( $# == 5 )) || return 1
    local dest=$1 path=$2 interface=$3 method=$4 signature=$5 raw
    [[ $dest == org.freedesktop.DBus && $path == /org/freedesktop/DBus &&
       $interface == org.freedesktop.DBus && $method == ListNames &&
       $signature == as ]] || return 1
    command -v gdbus >/dev/null 2>&1 || return 1
    raw=$(LC_ALL=C gdbus call --system --timeout 5 --dest "$dest" \
       --object-path "$path" --method "$interface.$method" 2>/dev/null) || return 1
    ubs24g_decode_array as "$raw" direct
}

# Read-only property access. Type is pinned by caller, never inferred from data.
ubs24g_get_property() {
    (( $# == 5 )) || return 1
    local dest=$1 path=$2 interface=$3 property=$4 signature=$5 raw
    ubs24g_safe_bus_name "$dest" && ubs24g_safe_object_path "$path" &&
      ubs24g_safe_interface "$interface" && ubs24g_safe_member "$property" || return 1
    [[ $signature == s || $signature == o || $signature == b ||
       $signature == u || $signature == t || $signature == ao ]] || return 1
    command -v gdbus >/dev/null 2>&1 || return 1
    raw=$(LC_ALL=C gdbus call --system --timeout 5 --dest "$dest" \
       --object-path "$path" --method org.freedesktop.DBus.Properties.Get \
       "$interface" "$property" 2>/dev/null) || return 1
    if [[ $signature == ao ]]; then
        ubs24g_decode_array ao "$raw" property
    else
        ubs24g_decode_property "$signature" "$raw"
    fi
}

# Read-only method access, explicit method allowlist and argument/return types.
# No activation, disconnect, GetSecrets, Set, or other mutation permitted.
ubs24g_call_readonly() {
    (( $# == 7 )) || return 1
    local dest=$1 path=$2 interface=$3 method=$4 in_sig=$5 argument=$6 out_sig=$7 raw
    ubs24g_safe_bus_name "$dest" && ubs24g_safe_object_path "$path" &&
      ubs24g_safe_interface "$interface" && ubs24g_safe_member "$method" || return 1
    ubs24g_safe_string "$argument" || return 1
    case "$dest|$path|$interface|$method|$in_sig|$out_sig" in
      'org.freedesktop.NetworkManager|/org/freedesktop/NetworkManager/Settings|org.freedesktop.NetworkManager.Settings|GetConnectionByUuid|s|o'|\
      'org.freedesktop.NetworkManager|/org/freedesktop/NetworkManager|org.freedesktop.NetworkManager|GetDeviceByIpIface|s|o'|\
      'org.freedesktop.DBus|/org/freedesktop/DBus|org.freedesktop.DBus|GetNameOwner|s|s'|\
      'org.freedesktop.DBus|/org/freedesktop/DBus|org.freedesktop.DBus|GetConnectionUnixProcessID|s|u'|\
      'org.freedesktop.DBus|/org/freedesktop/DBus|org.freedesktop.DBus|GetConnectionUnixUser|s|u') ;;
      *) return 1 ;;
    esac
    command -v gdbus >/dev/null 2>&1 || return 1
    raw=$(LC_ALL=C gdbus call --system --timeout 5 --dest "$dest" \
       --object-path "$path" --method "$interface.$method" "$argument" 2>/dev/null) || return 1
    ubs24g_decode_one "$out_sig" "$raw"
}
