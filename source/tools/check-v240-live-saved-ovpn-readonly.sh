#!/usr/bin/env bash
# Step 2B2C3F10: explicit-UUID, read-only real NetworkManager saved OpenVPN
# GetSettings compatibility and sanitised source-shape diagnosis. Never prints raw settings or endpoints.
# Does not authenticate a prepared session or authorise any network mutation.
set -euo pipefail
umask 077
export LC_ALL=C
export UBS24_DBUS_BACKEND=gdbus

mvc24spf_fail() { printf 'UNVERIFIED: %s\n' "$1" >&2; return 1; }
mvc24spf_pass() { printf 'PASS: %s\n' "$1"; }

# Only metadata flags. Keep remote, credentials, profile ID and UUID private.
mvc24spf_validate() {
    (( $# == 3 )) || return 1
    local file=$1 expected_uuid=$2 action=$3 remote proto random
    [[ $action == --run || $action == --assess-source || $action == --diagnose-source || $action == --inventory-remotes || $action == --plan-first-remote || $action == --preview-derivative || $action == --audit-auth-custody || $action == --audit-extra-flag-names || $action == --audit-challenge-flags || $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]] || return 1
    jq -e --arg uuid "$expected_uuid" '
        .type == "a{sa{sv}}" and
        (.data|type) == "array" and (.data|length) == 1 and
        .data[0].connection.uuid == {type:"s", data:$uuid} and
        .data[0].connection.type == {type:"s", data:"vpn"} and
        .data[0].vpn["service-type"] == {type:"s", data:"org.freedesktop.NetworkManager.openvpn"} and
        .data[0].vpn.data.type == "a{ss}" and
        (.data[0].vpn.data.data|type) == "object"
    ' "$file" >/dev/null 2>&1 || return 1
    # Diagnostic mode observes the original shape, even if it does not meet
    # the strict remote/transport constraints. Never admit it as authority.
    if [[ $action == --diagnose-source || $action == --inventory-remotes || $action == --plan-first-remote || $action == --preview-derivative || $action == --audit-auth-custody || $action == --audit-extra-flag-names || $action == --audit-challenge-flags || $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]]; then return 0; fi
    jq -e '(.data[0].vpn.data.data.remote|type) == "string"' "$file" >/dev/null 2>&1 || return 1
    remote=$(jq -r '.data[0].vpn.data.data.remote' "$file") || return 1
    proto=$(jq -r '.data[0].vpn.data.data["proto-tcp"] // "MISSING"' "$file") || return 1
    random=$(jq -r '.data[0].vpn.data.data["remote-random"] // "no"' "$file") || return 1
    # --run remains strict. --assess-source only classifies whether the saved
    # representation could serve as *input* to a future controller-owned
    # single-endpoint profile. It never authorises use of the source as-is.
    case $random in
        no) : ;;
        yes)
            if [[ $action == --run ]]; then
                mvc24spf_fail 'saved profile has remote-random=yes; strict v2.4 bootstrap requires remote-random=no'
                return 1
            fi ;;
        *)
            mvc24spf_fail 'saved profile remote-random value is unsupported by the strict v2.4 bootstrap'
            return 1 ;;
    esac
    # A second port field can change effective endpoint semantics and is not
    # supported by the prepared-session exact-source witness at this stage.
    if jq -e '.data[0].vpn.data.data | has("port")' "$file" >/dev/null 2>&1; then
        mvc24spf_fail 'separate OpenVPN port field requires explicit source reconciliation'
        return 1
    fi
    [[ $proto == yes || $proto == no ]] || {
        mvc24spf_fail 'saved OpenVPN proto-tcp is missing or not an explicit yes/no'; return 1;
    }
    if ! mvc24b_canonical_endpoint "$remote"; then
        mvc24spf_fail 'saved OpenVPN remote is not a single canonical numeric IPv4:port'; return 1
    fi
    UBS24SPF_PROTO=$proto
    UBS24SPF_RANDOM=$random
}

# All classifications are static labels. NO profile fields, endpoint bytes,
# credentials or identifiers may appear in the resulting stdout/stderr.
# Labels describe *syntax*, NOT NetworkManager's effective connection choice.
mvc24spf_diagnose() {
    (( $# == 1 )) || return 1
    local file=$1 remote port proto random random_hostname
    local remote_type remote_shape port_shape proto_shape random_shape hostname_shape
    local data_filter='.data[0].vpn.data.data'
    remote_type=$(jq -r "$data_filter | if has(\"remote\") then (.remote|type) else \"missing\" end" "$file") || return 1
    remote_shape=unsupported-type
    if [[ $remote_type == missing ]]; then
        remote_shape=missing
    elif [[ $remote_type == string ]]; then
        remote=$(jq -r "$data_filter.remote" "$file") || return 1
        if [[ -z $remote ]]; then
            remote_shape=empty
        elif [[ $remote == *[[:space:],]* || $remote == *';'* ]]; then
            remote_shape=delimited-or-multiple
        elif mvc24b_canonical_endpoint "$remote"; then
            remote_shape=single-ipv4-with-port
        elif [[ $remote == \[* ]]; then
            remote_shape=bracketed-ipv6-or-unsupported
        elif [[ $remote =~ ^([[:alnum:].-]+):([0-9]+):([[:alnum:]-]+)$ ]]; then
            remote_shape=single-host-with-port-and-protocol
        elif [[ $remote =~ ^([[:alnum:].-]+):([0-9]+)$ ]]; then
            remote_shape=single-host-with-port
        elif [[ $remote =~ ^[0-9.]+$ ]]; then
            remote_shape=ipv4-without-port-or-invalid
        elif [[ $remote =~ ^[[:alnum:].-]+$ ]]; then
            remote_shape=single-host-without-port
        elif [[ $remote == *:* ]]; then
            remote_shape=colon-form-or-ipv6-unsupported
        else
            remote_shape=other-unsupported
        fi
    fi
    if ! jq -e "$data_filter | has(\"port\")" "$file" >/dev/null 2>&1; then
        port_shape=absent
    else
        port=$(jq -r "$data_filter.port" "$file") || return 1
        if [[ $port =~ ^[0-9]+$ ]]; then
            port_shape=numeric-present
        else
            port_shape=non-numeric-or-empty
        fi
    fi
    proto_shape=absent
    if jq -e "$data_filter | has(\"proto-tcp\")" "$file" >/dev/null 2>&1; then
        proto=$(jq -r "$data_filter.[\"proto-tcp\"]" "$file") || return 1
        case $proto in
            yes) proto_shape=explicit-tcp-fallback ;;
            no) proto_shape=explicit-udp-fallback ;;
            *) proto_shape=other ;;
        esac
    fi
    random_shape=absent
    if jq -e "$data_filter | has(\"remote-random\")" "$file" >/dev/null 2>&1; then
        random=$(jq -r "$data_filter.[\"remote-random\"]" "$file") || return 1
        case $random in
            yes) random_shape=enabled ;;
            no) random_shape=disabled ;;
            *) random_shape=other ;;
        esac
    fi
    hostname_shape=absent
    if jq -e "$data_filter | has(\"remote-random-hostname\")" "$file" >/dev/null 2>&1; then
        random_hostname=$(jq -r "$data_filter.[\"remote-random-hostname\"]" "$file") || return 1
        case $random_hostname in
            yes) hostname_shape=enabled ;;
            no) hostname_shape=disabled ;;
            *) hostname_shape=other ;;
        esac
    fi
    UBS24SPF_DIAG_REMOTE=$remote_shape
    UBS24SPF_DIAG_PORT=$port_shape
    UBS24SPF_DIAG_PROTO=$proto_shape
    UBS24SPF_DIAG_RANDOM=$random_shape
    UBS24SPF_DIAG_RANDOM_HOSTNAME=$hostname_shape
}

# Non-admitting summary of *candidate syntax*, not the plugin's fully
# validated/effective remotes. In particular this never resolves hostnames,
# selects a candidate, generates a profile, or authorises network mutation.
# No raw remote values, exact numeric ports or UUIDs are emitted.
mvc24spf_inventory() {
    (( $# == 1 )) || return 1
    local file=$1 remote entry host port proto
    local -a entries=()
    local n=0 numeric_hosts=0 dns_hosts=0 ipv6_hosts=0 invalid=0
    local port_count=0 proto_count=0 tcp_count=0 udp_count=0
    local proto_fallback='' count_band addr_label port_label proto_label transport_label syntax_label

    UBS24SPF_INV_COUNT=unassessed
    UBS24SPF_INV_HOSTS=unassessed
    UBS24SPF_INV_PORTS=unassessed
    UBS24SPF_INV_PER_ENTRY_PROTO=unassessed
    UBS24SPF_INV_TRANSPORT=unassessed
    UBS24SPF_INV_SYNTAX=unsupported-or-out-of-scope

    # Check characters/size *before* importing untrusted settings into Bash.
    # The plugin may accept more forms; those must remain out of scope here.
    if ! jq -e '
        (.data[0].vpn.data.data.remote | type) == "string" and
        (.data[0].vpn.data.data.remote | length) <= 8192 and
        (.data[0].vpn.data.data.remote | test("^[A-Za-z0-9.,:_\\[\\] \\t-]+$"))
    ' "$file" >/dev/null 2>&1; then
        return 0
    fi
    remote=$(jq -r '.data[0].vpn.data.data.remote' "$file") || return 1
    [[ -n $remote ]] || return 0
    remote=${remote//,/ }
    # NetworkManager's strsep separator set is space, tab and comma. Empty
    # tokens are ignored; no shell evaluation or arbitrary data in output.
    read -r -a entries <<< "$remote"
    n=${#entries[@]}
    (( n > 0 && n <= 128 )) || return 0
    case $n in
        1) count_band=one ;;
        2|3|4) count_band=two-to-four ;;
        *) if (( n <= 16 )); then count_band=five-to-sixteen; else count_band=over-sixteen; fi ;;
    esac

    proto_fallback=$(jq -r '.data[0].vpn.data.data["proto-tcp"] // "no"' "$file") || return 1
    for entry in "${entries[@]}"; do
        host='' port='' proto=''
        # Only the uncomplicated host[:port[:protocol]] syntax is recognised.
        # IPv6 is flagged but intentionally not interpreted or admitted here.
        if [[ $entry == \[* ]]; then
            ((ipv6_hosts+=1))
            ((invalid+=1))
            continue
        elif [[ $entry =~ ^([A-Za-z0-9._-]+):([0-9]+):([A-Za-z0-9-]+)$ ]]; then
            host=${BASH_REMATCH[1]}
            port=${BASH_REMATCH[2]}
            proto=${BASH_REMATCH[3]}
        elif [[ $entry =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then
            host=${BASH_REMATCH[1]}
            port=${BASH_REMATCH[2]}
        elif [[ $entry =~ ^[A-Za-z0-9._-]+$ ]]; then
            host=$entry
        else
            ((invalid+=1))
            continue
        fi

        if [[ $host == *[!0-9.]* ]]; then
            ((dns_hosts+=1))
        elif mvc24b_canonical_endpoint "$host:1194"; then
            ((numeric_hosts+=1))
        else
            ((invalid+=1))
            continue
        fi
        if [[ -n $port ]]; then
            # Explicit valid port only: avoid Bash octal interpretation and
            # integer overflow on arbitrarily large digit strings.
            if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$port > 65535 )); then
                ((invalid+=1))
                continue
            fi
            ((port_count+=1))
        fi
        if [[ -n $proto ]]; then
            ((proto_count+=1))
            case $proto in
                tcp|tcp4|tcp6|tcp-client|tcp4-client|tcp6-client) ((tcp_count+=1)) ;;
                udp|udp4|udp6) ((udp_count+=1)) ;;
                *) ((invalid+=1)) ;;
            esac
        else
            case $proto_fallback in
                yes) ((tcp_count+=1)) ;;
                no) ((udp_count+=1)) ;;
                *) ((invalid+=1)) ;;
            esac
        fi
    done

    if ((invalid > 0)); then
        syntax_label=some-unsupported
    else
        syntax_label=recognised-simple-forms
    fi
    if ((ipv6_hosts > 0)); then
        addr_label=includes-ipv6-or-bracketed
    elif ((invalid > 0)); then
        addr_label=includes-unsupported
    elif ((numeric_hosts > 0 && dns_hosts > 0)); then
        addr_label=mixed-ipv4-and-hostnames
    elif ((numeric_hosts > 0)); then
        addr_label=ipv4-only
    else
        addr_label=hostname-shaped-only
    fi
    if ((port_count == n)); then port_label=all-explicit
    elif ((port_count == 0)); then port_label=none-explicit
    else port_label=some-explicit
    fi
    if ((proto_count == n)); then proto_label=all-explicit
    elif ((proto_count == 0)); then proto_label=none-explicit
    else proto_label=some-explicit
    fi
    if ((invalid > 0)); then transport_label=unassessed
    elif ((tcp_count == n)); then transport_label=tcp-only
    elif ((udp_count == n)); then transport_label=udp-only
    else transport_label=mixed-tcp-udp
    fi
    UBS24SPF_INV_COUNT=$count_band
    UBS24SPF_INV_HOSTS=$addr_label
    UBS24SPF_INV_PORTS=$port_label
    UBS24SPF_INV_PER_ENTRY_PROTO=$proto_label
    UBS24SPF_INV_TRANSPORT=$transport_label
    UBS24SPF_INV_SYNTAX=$syntax_label
}

_UBS24SPF_PRIVATE=''
mvc24spf_cleanup() {
    if [[ -n ${_UBS24SPF_PRIVATE:-} ]]; then
        rm -f -- "$_UBS24SPF_PRIVATE/first.json" "$_UBS24SPF_PRIVATE/second.json" "$_UBS24SPF_PRIVATE/preview.json" 2>/dev/null || :
        rmdir -- "$_UBS24SPF_PRIVATE" 2>/dev/null || :
    fi
}

mvc24spf_main() {
    (( $# == 1 || $# == 2 )) || mvc24spf_fail 'usage: --preflight, --run PROFILE_UUID, --assess-source PROFILE_UUID or --diagnose-source PROFILE_UUID or --inventory-remotes PROFILE_UUID or --plan-first-remote PROFILE_UUID or --preview-derivative PROFILE_UUID or --audit-auth-custody PROFILE_UUID or --audit-extra-flag-names PROFILE_UUID or --audit-challenge-flags PROFILE_UUID or --audit-material-readonly PROFILE_UUID or --triage-material-readonly PROFILE_UUID or --triage-root-material-readonly PROFILE_UUID'
    local action=$1 uuid=${2:-} root initial_owner final_owner
    local object first_obj second_obj side reply unsaved_before unsaved_after
    local path first_json='' identity='' re='^o "(/org/freedesktop/NetworkManager/Settings/[0-9]+)"$'
    [[ $action == --preflight || $action == --run || $action == --assess-source || $action == --diagnose-source || $action == --inventory-remotes || $action == --plan-first-remote || $action == --preview-derivative || $action == --audit-auth-custody || $action == --audit-extra-flag-names || $action == --audit-challenge-flags || $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]] || mvc24spf_fail 'unsupported action'
    if [[ $action == --preflight ]]; then
        (( $# == 1 )) || mvc24spf_fail 'preflight takes no profile UUID'
    else
        (( $# == 2 )) || mvc24spf_fail 'supply exactly one saved-profile UUID'
    fi
    # A root-scope check is opt-in, never an implicit sudo escalation. Refuse
    # before any D-Bus interaction when invoked under ordinary privileges.
    if [[ $action == --triage-root-material-readonly && $EUID -ne 0 ]]; then
        mvc24spf_fail 'root-scope observation requires explicit root invocation; no escalation attempted'
    fi
    for bin in gdbus awk jq mktemp cmp stat sha256sum; do
        command -v "$bin" >/dev/null 2>&1 || mvc24spf_fail "missing prerequisite: $bin"
    done
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || return 1
    source "$root/lib/dual-session.sh"
    source "$root/lib/combined-routing-guard.sh"
    source "$root/lib/combined-dbus-gdbus-portable.sh"
    source "$root/lib/combined-dbus-gdbus-settings.sh"
    source "$root/lib/combined-operational-session-underlay-binding.sh"
    source "$root/lib/combined-operational-ovpn-remote-candidate-plan.sh"
    source "$root/lib/combined-operational-ovpn-derivative-preview.sh"
    source "$root/lib/combined-operational-ovpn-auth-custody-audit.sh"
    source "$root/lib/combined-operational-ovpn-material-preflight.sh"
    source "$root/lib/combined-operational-ovpn-material-path-triage.sh"
    source "$root/lib/combined-operational-ovpn-material-root-observation.sh"
    mvc24op_session_nm_identity || mvc24spf_fail 'NetworkManager owner/PID/UID not authenticated'
    initial_owner=$UBS24OP_SESSION_NM_IDENTITY
    mvc24spf_pass 'real NetworkManager owner/PID/UID available'
    if [[ $action == --preflight ]]; then
        printf 'RESULT: PASS — saved-profile probe prerequisites; no profile inspected\n'
        return 0
    fi
    mvc24_valid_uuid "$uuid" || mvc24spf_fail 'invalid profile UUID format'
    [[ -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] ||
        mvc24spf_fail 'private tmpfs /dev/shm required'
    _UBS24SPF_PRIVATE=$(mktemp -d /dev/shm/ubs24-saved-host.XXXXXXXX) ||
        mvc24spf_fail 'cannot create private scratch'
    trap 'mvc24spf_cleanup' EXIT
    [[ -d $_UBS24SPF_PRIVATE && ! -L $_UBS24SPF_PRIVATE && -O $_UBS24SPF_PRIVATE &&
       $(stat -c %a -- "$_UBS24SPF_PRIVATE") == 700 ]] ||
        mvc24spf_fail 'insecure scratch directory'
    first_json=$_UBS24SPF_PRIVATE/first.json
    # The settings adapter requires this read-only compatibility flag; it does
    # NOT attest lock ownership. No admission or mutation functions are called.
    UBS24S_LOCK_HELD=1
    for side in first second; do
        path=$_UBS24SPF_PRIVATE/$side.json
        (umask 077; set -C; : > "$path") || mvc24spf_fail 'scratch creation failed'
        [[ -f $path && ! -L $path && $(stat -c %a:%h -- "$path") == 600:1 ]] ||
            mvc24spf_fail 'scratch file not private'
        reply=$(mvc24g_call_readonly org.freedesktop.NetworkManager \
            /org/freedesktop/NetworkManager/Settings \
            org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) ||
            mvc24spf_fail 'saved profile not found by exact UUID'
        [[ $reply =~ $re ]] || mvc24spf_fail 'unexpected Settings object-path response'
        object=${BASH_REMATCH[1]}
        if [[ $side == first ]]; then first_obj=$object; else second_obj=$object; fi
        unsaved_before=$(mvc24g_get_property org.freedesktop.NetworkManager "$object" \
            org.freedesktop.NetworkManager.Settings.Connection Unsaved b) ||
            mvc24spf_fail 'unable to read saved-profile Unsaved property'
        [[ $unsaved_before == 'b false' ]] || mvc24spf_fail 'profile has unsaved changes'
        mvc24gs_capture_settings "$object" "$path" ||
            mvc24spf_fail 'actual OpenVPN GetSettings could not be decoded'
        mvc24spf_validate "$path" "$uuid" "$action" || return 1
        unsaved_after=$(mvc24g_get_property org.freedesktop.NetworkManager "$object" \
            org.freedesktop.NetworkManager.Settings.Connection Unsaved b) ||
            mvc24spf_fail 'repeat Unsaved property unavailable'
        [[ $unsaved_after == 'b false' ]] || mvc24spf_fail 'profile changed during inspection'
        mvc24op_session_nm_identity || mvc24spf_fail 'NetworkManager identity changed during inspection'
        [[ $initial_owner == "$UBS24OP_SESSION_NM_IDENTITY" ]] ||
            mvc24spf_fail 'NetworkManager identity drift'
    done
    [[ $first_obj == "$second_obj" ]] || mvc24spf_fail 'profile object identity changed'
    cmp -s -- "$first_json" "$_UBS24SPF_PRIVATE/second.json" ||
        mvc24spf_fail 'saved GetSettings snapshots changed'
    mvc24op_session_nm_identity || mvc24spf_fail 'final NetworkManager identity unavailable'
    [[ $initial_owner == "$UBS24OP_SESSION_NM_IDENTITY" ]] ||
        mvc24spf_fail 'final NetworkManager identity drift'
    if [[ $action == --diagnose-source ]]; then
        mvc24spf_diagnose "$first_json" || mvc24spf_fail 'unable to classify saved profile safely'
    elif [[ $action == --inventory-remotes ]]; then
        mvc24spf_inventory "$first_json" || mvc24spf_fail 'unable to inventory saved profile safely'
    elif [[ $action == --preview-derivative || $action == --audit-auth-custody || $action == --audit-extra-flag-names || $action == --audit-challenge-flags || $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]]; then
        local preview_json=$_UBS24SPF_PRIVATE/preview.json preview_uuid
        (umask 077; set -C; : > "$preview_json") || mvc24spf_fail 'private preview scratch creation failed'
        [[ -f $preview_json && ! -L $preview_json && $(stat -c %a:%h -- "$preview_json") == 600:1 ]] ||
            mvc24spf_fail 'private preview scratch unsafe'
        preview_uuid=$(cat /proc/sys/kernel/random/uuid) || mvc24spf_fail 'cannot obtain temporary preview identity'
        mvc24op_preview_build "$first_json" "$preview_uuid" "$preview_json" ||
            mvc24spf_fail 'source unsupported for strict read-only derivative projection'
        if [[ $action == --audit-auth-custody || $action == --audit-extra-flag-names || $action == --audit-challenge-flags || $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]]; then
            mvc24op_auth_audit "$first_json" ||
                mvc24spf_fail 'read-only credential/TLS metadata is unsupported'
        fi
        if [[ $action == --audit-material-readonly || $action == --triage-material-readonly || $action == --triage-root-material-readonly ]]; then
            mvc24op_material_preflight "$first_json" ||
                mvc24spf_fail 'read-only TLS/option metadata inspection unavailable'
        fi
        if [[ $action == --triage-material-readonly ]]; then
            mvc24op_path_triage "$first_json" ||
                mvc24spf_fail 'caller-only TLS path triage unavailable'
        elif [[ $action == --triage-root-material-readonly ]]; then
            mvc24op_root_material_observe "$first_json" ||
                mvc24spf_fail 'root-scope TLS metadata observation unavailable'
        fi
    elif [[ $action == --plan-first-remote ]]; then
        mvc24op_candidate_plan "$first_json" 1 ||
            mvc24spf_fail 'profile remote list is outside the strict candidate-planning subset'
    fi
    if [[ $action == --audit-challenge-flags ]]; then
        mvc24op_auth_challenge_flag_class "$first_json" ||
            mvc24spf_fail 'cannot safely classify OpenVPN challenge-response flags'
    fi
    if [[ $action == --audit-extra-flag-names ]]; then
        mvc24op_auth_extra_flag_names "$first_json" ||
            mvc24spf_fail 'cannot safely classify additional credential flag names'
    fi
    # No success is reported while raw profile data remains in scratch.
    rm -f -- "$_UBS24SPF_PRIVATE/first.json" "$_UBS24SPF_PRIVATE/second.json" "$_UBS24SPF_PRIVATE/preview.json" ||
        mvc24spf_fail 'private capture cleanup failed'
    rmdir -- "$_UBS24SPF_PRIVATE" || mvc24spf_fail 'private scratch cleanup failed'
    _UBS24SPF_PRIVATE=''
    mvc24spf_pass 'saved OpenVPN UUID and typed GetSettings snapshots consistent'
    if [[ $action == --diagnose-source ]]; then
        printf 'SOURCE-SHAPE: remote=%s; port=%s; proto-tcp=%s; remote-random=%s; remote-random-hostname=%s\n' \
            "$UBS24SPF_DIAG_REMOTE" "$UBS24SPF_DIAG_PORT" "$UBS24SPF_DIAG_PROTO" \
            "$UBS24SPF_DIAG_RANDOM" "$UBS24SPF_DIAG_RANDOM_HOSTNAME"
        printf 'RESULT: READ-ONLY SYNTAX DIAGNOSIS ONLY — NOT endpoint resolution, plugin option parity, firewall or activation authority\n'
    elif [[ $action == --inventory-remotes ]]; then
        printf 'REMOTE-INVENTORY: count=%s; hosts=%s; ports=%s; per-entry-protocol=%s; transports=%s; syntax=%s\n' \
            "$UBS24SPF_INV_COUNT" "$UBS24SPF_INV_HOSTS" "$UBS24SPF_INV_PORTS" \
            "$UBS24SPF_INV_PER_ENTRY_PROTO" "$UBS24SPF_INV_TRANSPORT" "$UBS24SPF_INV_SYNTAX"
        printf 'RESULT: READ-ONLY INDICATIVE REMOTE INVENTORY — NOT plugin parity, endpoint selection, DNS, firewall or activation authority\n'
    elif [[ $action == --preview-derivative ]]; then
        printf 'DERIVATIVE-PREVIEW: single-ipv4-tcp=yes; identity=separate; remote-random=off; autoconnect=off; nonsecret-settings=exact-delta\n'
        printf 'AUTH-REVIEW: method=%s; secret-flags=%s; tls=%s; secret-values=not-read\n' \
            "$UBS24OP_PREVIEW_AUTH" "$UBS24OP_PREVIEW_FLAGS" "$UBS24OP_PREVIEW_TLS"
        printf 'RESULT: READ-ONLY IN-MEMORY SETTINGS PROJECTION — NOT a loadable profile, secret custody, TLS parity, guard or activation authority\n'
    elif [[ $action == --audit-challenge-flags ]]; then
        printf 'CHALLENGE-RESPONSE-FLAGS: %s; secret=not-read\n' "$UBS24OP_AUTH_CHALLENGE_CLASS"
        printf 'RESULT: READ-ONLY KNOWN SECRET-POLICY CLASSIFICATION — NOT prompt-free credential delivery, future challenge absence, clone compatibility or activation authority\n'
    elif [[ $action == --audit-extra-flag-names ]]; then
        printf 'EXTRA-CREDENTIAL-FLAG-KEYS: %s; values=not-read\n' "$UBS24OP_AUTH_EXTRA_FLAG_NAMES"
        printf 'RESULT: READ-ONLY EXTRA FLAG NAMES ONLY — NOT secret validity, credential availability, clone compatibility or activation authority\n'
    elif [[ $action == --audit-auth-custody ]]; then
        printf 'AUTH-CUSTODY: method=%s; password=%s; cert-pass=%s; proxy-password=%s; other-flags=%s\n' \
            "$UBS24OP_AUTH_METHOD" "$UBS24OP_AUTH_PASSWORD" "$UBS24OP_AUTH_CERT_PASS" \
            "$UBS24OP_AUTH_PROXY_PASSWORD" "$UBS24OP_AUTH_OTHER_FLAGS"
        printf 'TLS-REFERENCES: ca=%s; client=%s; control-channel=%s; file-content=not-read; file-access=not-checked\n' \
            "$UBS24OP_AUTH_CA" "$UBS24OP_AUTH_CLIENT" "$UBS24OP_AUTH_CONTROL"
        printf 'RESULT: READ-ONLY CREDENTIAL FLAGS AND TLS REFERENCES — NOT secret availability, NM agent compatibility, TLS trust or activation authority\n'
    elif [[ $action == --audit-material-readonly ]]; then
        printf 'TLS-METADATA: ca=%s; tls-crypt=%s; remote-cert-tls=%s; name-check=%s\n' \
            "$UBS24OP_MATERIAL_CA" "$UBS24OP_MATERIAL_TLS_CRYPT" \
            "$UBS24OP_MATERIAL_SERVER_CERT" "$UBS24OP_MATERIAL_NAME_CHECK"
        printf 'EXTRA-SECRET-FLAGS: %s; credentials=not-read; profile=unchanged\n' \
            "$UBS24OP_MATERIAL_OTHER_FLAGS"
        printf 'RESULT: CALLER-ONLY READ-ONLY FILE METADATA — NOT NM/PLUGIN FILE ACCESS, TLS CONTENT/TRUST, PASSWORD AVAILABILITY OR ACTIVATION AUTHORITY\n'
    elif [[ $action == --triage-material-readonly ]]; then
        printf 'PATH-TRIAGE: ca=%s; tls-crypt=%s; scope=caller-only; contents=not-read\n' \
            "$UBS24OP_TRIAGE_CA" "$UBS24OP_TRIAGE_TLS_CRYPT"
        printf 'EXTRA-SECRET-FLAGS: %s; credentials=not-read; profile=unchanged\n' \
            "$UBS24OP_MATERIAL_OTHER_FLAGS"
        printf 'RESULT: RACEABLE READ-ONLY CALLER PATH TRIAGE — NOT NM ACCESS, TLS TRUST, SECRET AVAILABILITY OR ACTIVATION AUTHORITY\n'
    elif [[ $action == --triage-root-material-readonly ]]; then
        printf 'ROOT-PATH-TRIAGE: ca=%s; tls-crypt=%s; scope=root-caller-only; contents=not-read\n' \
            "$UBS24OP_ROOT_CA" "$UBS24OP_ROOT_TLS_CRYPT"
        printf 'EXTRA-SECRET-FLAGS: %s; credentials=not-read; profile=unchanged\n' \
            "$UBS24OP_MATERIAL_OTHER_FLAGS"
        printf 'RESULT: READ-ONLY ROOT-CALLER FILE METADATA — NOT OPENVPN PLUGIN ACCESS, TLS TRUST, SECRET AVAILABILITY OR ACTIVATION AUTHORITY\n'
    elif [[ $action == --plan-first-remote ]]; then
        # Deliberately no endpoint, port, count or profile UUID printed.
        printf 'CANDIDATE-PLAN: source-order=first; endpoints=all-canonical-ipv4-with-explicit-ports; transport=tcp-only; source-profile=unchanged\n'
        printf 'RESULT: READ-ONLY SINGLE-CANDIDATE PROPOSAL — NOT saved derivative, TLS/secret parity, firewall, socket or activation authority\n'
    elif [[ $action == --assess-source ]]; then
        mvc24spf_pass 'source has one canonical numeric IPv4:port and explicit UDP/TCP transport'
        if [[ $UBS24SPF_RANDOM == yes ]]; then
            printf 'ASSESSMENT: source shape could support a controller-owned single-endpoint derivative; remote-random=yes source remains REJECTED by strict bootstrap\n'
        else
            printf 'ASSESSMENT: source shape supports a single endpoint; no controller-owned derivative has been prepared\n'
        fi
        printf 'RESULT: READ-ONLY SOURCE ASSESSMENT ONLY — NOT credential/option-parity proof, rendered profile, firewall or activation authority\n'
    else
        mvc24spf_pass 'saved profile representation supports current strict IPv4:port and proto-tcp witness'
        printf 'RESULT: PASS — real saved OpenVPN profile shape compatible; NOT prepared-session authority or activation\n'
    fi
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    mvc24spf_main "$@"
fi
