#!/usr/bin/env bash
# C23AM — standalone manual recovery for C23AI-owned WireGuard residue ONLY.
#
# This tool deliberately does NOT remove the B4 nftables quarantine and does
# NOT stop OpenVPN. Its only mutation authority is:
#   * stop the exact C23AI temporary WireGuard UUID, if still active;
#   * delete that exact temporary NetworkManager profile, if present;
#   * add exact profile-derived private unreachable hold routes (proto 187
#     metric 4241) before WG is stopped, preventing private traffic from
#     falling through the still-active OpenVPN default route;
#   * remove the exact controller-owned endpoint /32 route (proto 186 metric 4240);
#   * remove the exact /run keyfile if NetworkManager is already absent and the
#     file still carries the authenticated temporary UUID;
#   * remove the private hold routes only when no active OpenVPN remains.
#
# The /run/ubs-v240-wireguard intent is retained as same-boot evidence. After
# successful recovery, use /root/mvc-emergency-rollback separately only
# if you consciously want to DISABLE the v2.4 kill switch.
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: recover-mvc-dual-local.sh --inspect|--rollback' >&2
    exit 2
}
(( $# == 1 )) || usage
case $1 in --inspect|--rollback) mode=$1 ;; *) usage ;; esac
(( EUID == 0 )) || { echo 'ERROR: root required' >&2; exit 1; }
for cmd in awk cat grep ip nmcli readlink rm stat wg; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'ERROR: required command missing: %s\n' "$cmd" >&2; exit 1; }
done

RUNTIME=/run/ubs-v240-wireguard
INTENT=$RUNTIME/intent
TEMP_NAME=vpnks-wg
TEMP_FILE=/run/NetworkManager/system-connections/vpnks-wg.nmconnection
HOLD_PROTO=187
HOLD_METRIC=4241

valid_uuid() { [[ ${1:-} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]; }
valid_ipv4() {
    local ip=${1:-} a b c d extra
    IFS=. read -r a b c d extra <<< "$ip"
    [[ -z ${extra:-} && $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $c =~ ^[0-9]+$ && $d =~ ^[0-9]+$ ]] || return 1
    (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 ))
}
valid_ifname() { [[ ${1:-} =~ ^[A-Za-z0-9_.:-]{1,15}$ && ${1:-} != lo ]]; }
valid_port() { [[ ${1:-} =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_ipv4_prefix() {
    local value=${1:-} ip bits
    [[ $value =~ ^([^/]+)/([0-9]{1,2})$ ]] || return 1
    ip=${BASH_REMATCH[1]}; bits=${BASH_REMATCH[2]}
    valid_ipv4 "$ip" && (( 10#$bits >= 1 && 10#$bits <= 32 ))
}

private_ipv4_prefix() {
    (( $# == 1 )) || return 1
    local value=$1 ip bits a b c d
    valid_ipv4_prefix "$value" || return 1
    ip=${value%/*}; bits=${value##*/}
    IFS=. read -r a b c d <<< "$ip"
    if (( 10#$a == 10 && 10#$bits >= 8 )); then return 0; fi
    if (( 10#$a == 172 && 10#$b >= 16 && 10#$b <= 31 && 10#$bits >= 12 )); then return 0; fi
    if (( 10#$a == 192 && 10#$b == 168 && 10#$bits >= 16 )); then return 0; fi
    return 1
}

keyfile_scalar() {
    (( $# == 3 )) || return 1
    local file=$1 section=$2 key=$3
    [[ -f $file && ! -L $file && $section =~ ^[A-Za-z0-9_.-]+$ && $key =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    awk -v want="[$section]" -v key="$key" '
      BEGIN{sec=""; n=0}
      /^\[/ {sec=$0; next}
      sec==want && index($0,key "=")==1 {sub("^" key "=",""); print; n++}
      END{if(n!=1) exit 1}
    ' "$file"
}
keyfile_uuid() { (( $# == 1 )) && keyfile_scalar "$1" connection uuid; }

route_line_matches() {
    (( $# == 5 )) || return 1
    local dest=$1 iface=$2 via=$3 source=$4 output=$5
    local -a parts=()
    local token i found_dev='' found_via='-' found_src='' found_proto='' found_metric=''
    valid_ipv4 "$dest" && valid_ifname "$iface" && valid_ipv4 "$source" || return 1
    [[ $via == - ]] || valid_ipv4 "$via" || return 1
    [[ -n $output && $output != *$'\n'* && $output != *$'\r'* ]] || return 1
    read -r -a parts <<< "$output"
    [[ ${parts[0]:-} == "$dest" || ${parts[0]:-} == "$dest/32" ]] || return 1
    for ((i=1;i<${#parts[@]};i++)); do
        token=${parts[i]}
        case $token in
          via|dev|src|proto|metric)
            (( i+1 < ${#parts[@]} )) || return 1
            case $token in
              via)    [[ $found_via == - ]] || return 1; found_via=${parts[++i]} ;;
              dev)    [[ -z $found_dev ]] || return 1; found_dev=${parts[++i]} ;;
              src)    [[ -z $found_src ]] || return 1; found_src=${parts[++i]} ;;
              proto)  [[ -z $found_proto ]] || return 1; found_proto=${parts[++i]} ;;
              metric) [[ -z $found_metric ]] || return 1; found_metric=${parts[++i]} ;;
            esac ;;
          scope)
            (( i+1 < ${#parts[@]} )) && [[ ${parts[i+1]} == link ]] || return 1
            ((i+=1)) ;;
          table)
            (( i+1 < ${#parts[@]} )) && [[ ${parts[i+1]} == main ]] || return 1
            ((i+=1)) ;;
          *) return 1 ;;
        esac
    done
    [[ $found_dev == "$iface" && $found_via == "$via" && $found_src == "$source" &&
       $found_proto == 186 && $found_metric == 4240 ]]
}

route_json_matches() {
    (( $# == 5 )) || return 1
    local dest=$1 iface=$2 via=$3 source=$4 json=$5 expected_gateway=$3
    valid_ipv4 "$dest" && valid_ifname "$iface" && valid_ipv4 "$source" || return 1
    [[ $via == - ]] || valid_ipv4 "$via" || return 1
    [[ $expected_gateway == - ]] && expected_gateway=''
    jq -e --arg dst "$dest" --arg dev "$iface" --arg src "$source" --arg gw "$expected_gateway" '
      type=="array" and length==1 and
      ((.[0].dst // "") == $dst or (.[0].dst // "") == ($dst + "/32")) and
      (.[0].dev // "") == $dev and (.[0].prefsrc // "") == $src and
      (.[0].gateway // "") == $gw and ((.[0].protocol // "")|tostring) == "186" and
      ((.[0].metric // -1)|tonumber) == 4240 and
      ((.[0].multipath // [])|length) == 0
    ' <<< "$json" >/dev/null 2>&1
}

runtime_absent_residue_check() {
    local rows routes
    rows=$(nmcli -e no -t -f NAME,UUID,TYPE connection show 2>/dev/null) || return 1
    if awk -F: -v n="$TEMP_NAME" '$1==n {found=1} END{exit(found?0:1)}' <<< "$rows"; then return 1; fi
    routes=$(ip -4 route show table all proto 186) || return 1
    [[ -z $routes ]] || return 1
    routes=$(ip -4 route show table all proto "$HOLD_PROTO") || return 1
    [[ -z $routes && ! -e $TEMP_FILE && ! -L $TEMP_FILE ]] || return 1
    ! ip link show dev "$TEMP_NAME" >/dev/null 2>&1 && ! wg show "$TEMP_NAME" >/dev/null 2>&1
}

read_intent() {
    [[ -d $RUNTIME && ! -L $RUNTIME && $(stat -c '%u:%a:%h' -- "$RUNTIME") == '0:700:2' ]] || return 1
    [[ -f $INTENT && ! -L $INTENT && $(stat -c '%u:%a:%h' -- "$INTENT") == '0:400:1' ]] || return 1
    mapfile -t lines < "$INTENT"
    (( ${#lines[@]} == 14 )) || return 1
    [[ ${lines[0]} == ubs-v240-c23ai-wireguard-intent-v1 &&
       ${lines[1]} == state=prepared-no-wireguard-mutation-yet ]] || return 1
    [[ ${lines[2]} == boot=* && ${lines[3]} == userns=* && ${lines[4]} == netns=* && ${lines[5]} == mntns=* &&
       ${lines[6]} == source_uuid=* && ${lines[7]} == source_sha=* &&
       ${lines[8]} == temp_name=* && ${lines[9]} == temp_uuid=* &&
       ${lines[10]} == wg_source=* && ${lines[11]} == endpoint=* &&
       ${lines[12]} == underlay=* && ${lines[13]} == allowedips=* ]] || return 1
    local boot=${lines[2]#boot=} userns=${lines[3]#userns=} netns=${lines[4]#netns=} mntns=${lines[5]#mntns=}
    [[ ${lines[2]} == boot=* && ${lines[3]} == userns=* && ${lines[4]} == netns=* && ${lines[5]} == mntns=* ]] || return 1
    [[ $boot == "$(cat /proc/sys/kernel/random/boot_id)" &&
       $userns == "$(readlink /proc/self/ns/user)" &&
       $netns == "$(readlink /proc/self/ns/net)" &&
       $mntns == "$(readlink /proc/self/ns/mnt)" ]] || return 1

    local line key value
    SOURCE_UUID='' SOURCE_SHA='' TEMP_NAME_I='' TEMP_UUID='' WG_SOURCE=''
    ENDPOINT='' UNDERLAY_SPEC='' ALLOWEDIPS=''
    for line in "${lines[@]}"; do
      key=${line%%=*}; value=${line#*=}
      case $key in
        source_uuid) SOURCE_UUID=$value ;;
        source_sha) SOURCE_SHA=$value ;;
        temp_name) TEMP_NAME_I=$value ;;
        temp_uuid) TEMP_UUID=$value ;;
        wg_source) WG_SOURCE=$value ;;
        endpoint) ENDPOINT=$value ;;
        underlay) UNDERLAY_SPEC=$value ;;
        allowedips) ALLOWEDIPS=$value ;;
      esac
    done
    valid_uuid "$SOURCE_UUID" && [[ $SOURCE_SHA =~ ^[0-9a-f]{64}$ ]] &&
      [[ $TEMP_NAME_I == "$TEMP_NAME" ]] && valid_uuid "$TEMP_UUID" && valid_ipv4 "$WG_SOURCE" || return 1
    [[ $ENDPOINT == *:* && $ENDPOINT != *:*:* ]] || return 1
    ENDPOINT_IP=${ENDPOINT%:*}; ENDPOINT_PORT=${ENDPOINT##*:}
    valid_ipv4 "$ENDPOINT_IP" && valid_port "$ENDPOINT_PORT" || return 1
    IFS='|' read -r UNDERLAY source_part gateway_part extra <<< "$UNDERLAY_SPEC"
    [[ -z ${extra:-} && ${source_part:-} == source=* && ${gateway_part:-} == gateway=* ]] || return 1
    UNDERLAY_SOURCE=${source_part#source=}; UNDERLAY_GATEWAY=${gateway_part#gateway=}
    valid_ifname "$UNDERLAY" && valid_ipv4 "$UNDERLAY_SOURCE" || return 1
    [[ $UNDERLAY_GATEWAY == - ]] || valid_ipv4 "$UNDERLAY_GATEWAY" || return 1
    [[ -n $ALLOWEDIPS && $ALLOWEDIPS == *';' ]] || return 1
    IFS=';' read -r -a ALLOWED_PREFIXES <<< "$ALLOWEDIPS"
    (( ${#ALLOWED_PREFIXES[@]} >= 1 )) || return 1
    local prefix
    for prefix in "${ALLOWED_PREFIXES[@]}"; do private_ipv4_prefix "$prefix" || return 1; done
}

# Inventory the exact temporary connection. Either the intended UUID/name/type
# appears once, or it is absent. Any collision/duplicate fails closed.
nm_inventory() {
    local rows line n=0 observed_uuid observed_type observed_name active found=0
    NM_STATUS=''
    rows=$(nmcli -e no -t -f UUID,TYPE,NAME connection show 2>/dev/null) || return 1
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        observed_uuid=${line%%:*}; local rest=${line#*:}
        [[ $rest != "$line" ]] || return 1
        observed_type=${rest%%:*}; observed_name=${rest#*:}
        [[ $observed_name != "$rest" ]] || return 1
        if [[ $observed_name == "$TEMP_NAME" || $observed_uuid == "$TEMP_UUID" ]]; then
            [[ $observed_uuid == "$TEMP_UUID" && $observed_type == wireguard && $observed_name == "$TEMP_NAME" ]] || return 1
            ((n+=1))
        fi
    done <<< "$rows"
    (( n <= 1 )) || return 1
    active=$(nmcli -e no -t -f UUID connection show --active 2>/dev/null) || return 1
    while IFS= read -r line; do [[ $line == "$TEMP_UUID" ]] && ((found+=1)); done <<< "$active"
    (( found <= 1 && found <= n )) || return 1
    if (( n == 0 )); then NM_STATUS=absent
    elif (( found == 1 )); then NM_STATUS=active
    else NM_STATUS=down
    fi
    if [[ $NM_STATUS != absent ]]; then
        local iface
        iface=$(nmcli --wait 10 -g connection.interface-name connection show uuid "$TEMP_UUID" 2>/dev/null) || return 1
        [[ $iface == "$TEMP_NAME" ]] || return 1
    fi
}

kernel_inventory() {
    local link_present=no wg_present=no
    KERNEL_STATUS=absent
    if ip link show dev "$TEMP_NAME" >/dev/null 2>&1; then link_present=yes; fi
    if wg show "$TEMP_NAME" >/dev/null 2>&1; then wg_present=yes; fi
    [[ $link_present == "$wg_present" ]] || return 1
    [[ $link_present == yes ]] && KERNEL_STATUS=active
    case $NM_STATUS in
      active) [[ $KERNEL_STATUS == active ]] ;;
      down|absent) [[ $KERNEL_STATUS == absent ]] ;;
      *) return 1 ;;
    esac
}

route_inventory() {
    local all exact count global_dst global_dev global_gateway global_src global_metric expected_gateway
    ROUTE_STATUS=absent
    all=$(ip -j -N -4 route show table all proto 186) || return 1
    jq -e 'type=="array" and length<=1' <<< "$all" >/dev/null 2>&1 || return 1
    count=$(jq -r 'length' <<< "$all") || return 1
    exact=$(ip -j -N -4 route show exact "$ENDPOINT_IP/32" table main) || return 1
    jq -e 'type=="array"' <<< "$exact" >/dev/null 2>&1 || return 1
    if (( count == 1 )); then
        global_dst=$(jq -r '.[0].dst // ""' <<< "$all") || return 1
        global_dev=$(jq -r '.[0].dev // ""' <<< "$all") || return 1
        global_gateway=$(jq -r '.[0].gateway // ""' <<< "$all") || return 1
        global_src=$(jq -r '.[0].prefsrc // ""' <<< "$all") || return 1
        global_metric=$(jq -r '.[0].metric // ""' <<< "$all") || return 1
        expected_gateway=$UNDERLAY_GATEWAY; [[ $expected_gateway == - ]] && expected_gateway=''
        [[ $global_dst == "$ENDPOINT_IP" || $global_dst == "$ENDPOINT_IP/32" ]] || return 1
        [[ $global_dev == "$UNDERLAY" && $global_gateway == "$expected_gateway" &&
           $global_src == "$UNDERLAY_SOURCE" && $global_metric == 4240 ]] || return 1
        route_json_matches "$ENDPOINT_IP" "$UNDERLAY" "$UNDERLAY_GATEWAY" "$UNDERLAY_SOURCE" "$exact" || return 1
        ROUTE_STATUS=owned
    else
        # A route to the same endpoint under some other owner is an ownership
        # change, not successful cleanup.
        jq -e 'length==0' <<< "$exact" >/dev/null 2>&1 || return 1
    fi
}


hold_line_matches() {
    (( $# == 2 )) || return 1
    local prefix=$1 output=$2 token i proto='' metric=''
    local -a parts=()
    valid_ipv4_prefix "$prefix" || return 1
    [[ -n $output && $output != *$'\n'* && $output != *$'\r'* ]] || return 1
    read -r -a parts <<< "$output"
    [[ ${parts[0]:-} == unreachable && ${parts[1]:-} == "$prefix" ]] || return 1
    for ((i=2;i<${#parts[@]};i++)); do
      token=${parts[i]}
      case $token in
        proto|metric)
          (( i+1 < ${#parts[@]} )) || return 1
          case $token in
            proto) [[ -z $proto ]] || return 1; proto=${parts[++i]} ;;
            metric) [[ -z $metric ]] || return 1; metric=${parts[++i]} ;;
          esac ;;
        table)
          (( i+1 < ${#parts[@]} )) && [[ ${parts[i+1]} == main ]] || return 1
          ((i+=1)) ;;
        *) return 1 ;;
      esac
    done
    [[ $proto == "$HOLD_PROTO" && $metric == "$HOLD_METRIC" ]]
}

hold_json_matches() {
    (( $# == 2 )) || return 1
    local prefix=$1 json=$2
    valid_ipv4_prefix "$prefix" || return 1
    jq -e --arg p "$prefix" --arg proto "$HOLD_PROTO" --argjson metric "$HOLD_METRIC" '
      type=="array" and length==1 and
      ((((.[0].type // "")|tostring) == "unreachable") or (((.[0].type // "")|tostring) == "7")) and
      ((.[0].dst // "") == $p or (($p|endswith("/32")) and (.[0].dst // "") == ($p|sub("/32$";"")))) and
      ((.[0].protocol // "")|tostring) == $proto and
      ((.[0].metric // -1)|tonumber) == $metric
    ' <<< "$json" >/dev/null 2>&1
}

hold_inventory() {
    local json type prefix metric exact count=0 profile_prefix candidate
    local -A wanted=() seen=()
    HOLD_STATUS=absent
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        [[ -z ${wanted[$prefix]:-} ]] || return 1
        wanted[$prefix]=1
    done
    json=$(ip -j -N -4 route show table all proto "$HOLD_PROTO") || return 1
    jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
    while IFS=$'\t' read -r type prefix metric; do
        [[ -n $prefix ]] || continue
        [[ ( $type == unreachable || $type == 7 ) && $metric == "$HOLD_METRIC" ]] || return 1
        profile_prefix=$prefix
        if [[ -z ${wanted[$profile_prefix]:-} ]] && valid_ipv4 "$profile_prefix"; then
            candidate="${profile_prefix}/32"
            [[ -n ${wanted[$candidate]:-} ]] && profile_prefix=$candidate
        fi
        [[ -n ${wanted[$profile_prefix]:-} && -z ${seen[$profile_prefix]:-} ]] || return 1
        exact=$(ip -j -N -4 route show exact "$profile_prefix" table main type unreachable) || return 1
        hold_json_matches "$profile_prefix" "$exact" || return 1
        seen[$profile_prefix]=1; ((count+=1))
    done < <(jq -r '.[] | [(.type // "unicast"), (.dst // ""), ((.metric // "")|tostring)] | @tsv' <<< "$json")
    if (( count == 0 )); then HOLD_STATUS=absent
    elif (( count == ${#ALLOWED_PREFIXES[@]} )); then HOLD_STATUS=full
    else HOLD_STATUS=partial
    fi
}

ensure_hold_routes() {
    local prefix json rc
    hold_inventory || return 1
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
        jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
        if ! jq -e 'length==0' <<< "$json" >/dev/null 2>&1; then
            hold_json_matches "$prefix" "$json" || return 1
            continue
        fi
        set +e
        ip -4 route add unreachable "$prefix" proto "$HOLD_PROTO" metric "$HOLD_METRIC" >/dev/null 2>&1
        rc=$?
        set -e
        json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
        hold_json_matches "$prefix" "$json" || return 1
        printf 'DETAIL: c23am-private-hold-add=%s exit=%s\n' "$prefix" "$rc"
    done
    hold_inventory && [[ $HOLD_STATUS == full ]]
}

remove_hold_routes() {
    local prefix rc json
    hold_inventory || return 1
    [[ $HOLD_STATUS == full ]] || return 1
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        set +e
        ip -4 route del unreachable "$prefix" proto "$HOLD_PROTO" metric "$HOLD_METRIC" >/dev/null 2>&1
        rc=$?
        set -e
        json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
        jq -e 'type=="array" and length==0' <<< "$json" >/dev/null 2>&1 || return 1
        printf 'DETAIL: c23am-private-hold-delete=%s exit=%s\n' "$prefix" "$rc"
    done
    hold_inventory && [[ $HOLD_STATUS == absent ]]
}

openvpn_active() {
    local types count=0 line
    types=$(nmcli -e no -t -f TYPE connection show --active 2>/dev/null) || return 2
    while IFS= read -r line; do [[ $line == vpn ]] && ((count+=1)); done <<< "$types"
    (( count <= 1 )) || return 2
    (( count == 1 ))
}

keyfile_inventory() {
    KEYFILE_STATUS=absent
    if [[ -e $TEMP_FILE || -L $TEMP_FILE ]]; then
        [[ -f $TEMP_FILE && ! -L $TEMP_FILE && $(stat -c '%u:%a:%h' -- "$TEMP_FILE") == '0:600:1' ]] || return 1
        [[ $(keyfile_uuid "$TEMP_FILE") == "$TEMP_UUID" &&
           $(keyfile_scalar "$TEMP_FILE" connection id) == "$TEMP_NAME" &&
           $(keyfile_scalar "$TEMP_FILE" connection type) == wireguard &&
           $(keyfile_scalar "$TEMP_FILE" connection interface-name) == "$TEMP_NAME" ]] || return 1
        KEYFILE_STATUS=owned
    fi
}

inspect_state() {
    if [[ ! -e $RUNTIME && ! -L $RUNTIME ]]; then
        runtime_absent_residue_check || { echo 'UNVERIFIED: C23AI residue exists without authenticated /run intent' >&2; return 1; }
        printf '%s\n' 'PASS: no C23AI WireGuard runtime, temporary profile, kernel link, proto-186 endpoint route or proto-187 private hold is present' \
          'RESULT: READ-ONLY MVC DUAL RECOVERY CLEAN — NO CHANGES'
        return 0
    fi
    read_intent || { echo 'UNVERIFIED: C23AI WireGuard intent is malformed, foreign or from another boot/namespace' >&2; return 1; }
    nm_inventory && kernel_inventory && route_inventory && hold_inventory && keyfile_inventory || {
        echo 'UNVERIFIED: C23AI WireGuard ownership inventory failed; no recovery mutation attempted' >&2
        return 1
    }
    printf 'C23AI_TEMP_UUID: %s\n' "$TEMP_UUID"
    printf 'C23AI_ENDPOINT: %s:%s\n' "$ENDPOINT_IP" "$ENDPOINT_PORT"
    printf 'C23AI_NM_STATUS: %s\n' "$NM_STATUS"
    printf 'C23AI_KERNEL_WG_STATUS: %s\n' "$KERNEL_STATUS"
    printf 'C23AI_ROUTE_STATUS: %s\n' "$ROUTE_STATUS"
    printf 'C23AI_KEYFILE_STATUS: %s\n' "$KEYFILE_STATUS"
    printf 'C23AI_PRIVATE_HOLD_STATUS: %s\n' "$HOLD_STATUS"
    printf '%s\n' 'RESULT: READ-ONLY MVC DUAL RECOVERY INVENTORY VERIFIED — NO CHANGES'
}

inspect_state || exit 1
[[ $mode == --inspect ]] && exit 0

[[ -e $RUNTIME || -L $RUNTIME ]] || {
    echo 'PASS: no C23AI WireGuard residue requires recovery'
    exit 0
}
[[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty && -z ${SSH_CONNECTION:-} && -z ${SSH_TTY:-} ]] || {
    echo 'ERROR: --rollback requires a local interactive terminal' >&2; exit 1;
}
printf '%s\n' \
  'WARNING: This removes ONLY authenticated C23AI WireGuard residue.' \
  'It does NOT stop OpenVPN and does NOT remove the v2.4 nftables quarantine.' \
  'The /run/ubs-v240-wireguard intent is retained as evidence; do not start another session in this boot.' \
  'Type exactly: RECOVER MVC DUAL WIREGUARD' > /dev/tty
printf '> ' > /dev/tty
IFS= read -r confirmation < /dev/tty || exit 1
[[ $confirmation == 'RECOVER MVC DUAL WIREGUARD' ]] || { echo 'ERROR: confirmation refused' >&2; exit 1; }

# Re-inventory immediately before mutation.
read_intent && nm_inventory && kernel_inventory && route_inventory && hold_inventory && keyfile_inventory || {
    echo 'ERROR: C23AI ownership changed before recovery; no mutation attempted' >&2; exit 1;
}

# Before stopping WG, make every selected private destination fail-closed if
# its NetworkManager WG route disappears. These holds remain while OpenVPN is
# active and are removed only after no active TYPE=vpn connection is observed.
ensure_hold_routes || { echo 'UNVERIFIED: could not establish exact private-destination hold routes; WG left untouched' >&2; exit 1; }

if [[ $NM_STATUS == active ]]; then
    set +e
    nmcli --wait 60 connection down uuid "$TEMP_UUID" >/dev/null 2>&1
    down_rc=$?
    set -e
    nm_inventory && kernel_inventory || { echo 'UNVERIFIED: WG disconnect submitted but NM/kernel poststate cannot be authenticated' >&2; exit 1; }
    [[ $NM_STATUS == down || $NM_STATUS == absent ]] || { echo 'UNVERIFIED: WG remains active; no further recovery mutation attempted' >&2; exit 1; }
    printf 'DETAIL: c23am-nm-down-exit=%s poststate=%s\n' "$down_rc" "$NM_STATUS"
fi

# Remove the owned route only after WG is proven inactive/absent. No retry.
route_inventory || { echo 'UNVERIFIED: route ownership changed before deletion' >&2; exit 1; }
if [[ $ROUTE_STATUS == owned ]]; then
    argv=(-4 route del "$ENDPOINT_IP/32")
    [[ $UNDERLAY_GATEWAY == - ]] || argv+=(via "$UNDERLAY_GATEWAY")
    argv+=(dev "$UNDERLAY" src "$UNDERLAY_SOURCE" proto 186 metric 4240)
    set +e
    ip "${argv[@]}" >/dev/null 2>&1
    route_rc=$?
    set -e
    route_inventory || { echo 'UNVERIFIED: route delete submitted but poststate cannot be authenticated' >&2; exit 1; }
    [[ $ROUTE_STATUS == absent ]] || { echo 'UNVERIFIED: owned endpoint route remains; no profile deletion attempted' >&2; exit 1; }
    printf 'DETAIL: c23am-route-delete-exit=%s poststate=absent\n' "$route_rc"
fi

nm_inventory || { echo 'UNVERIFIED: NM ownership changed before profile deletion' >&2; exit 1; }
if [[ $NM_STATUS == down ]]; then
    set +e
    nmcli --wait 30 connection delete uuid "$TEMP_UUID" >/dev/null 2>&1
    delete_rc=$?
    set -e
    nm_inventory && kernel_inventory || { echo 'UNVERIFIED: profile delete submitted but NM/kernel poststate cannot be authenticated' >&2; exit 1; }
    [[ $NM_STATUS == absent ]] || { echo 'UNVERIFIED: temporary WG profile remains loaded' >&2; exit 1; }
    printf 'DETAIL: c23am-profile-delete-exit=%s poststate=absent\n' "$delete_rc"
fi

keyfile_inventory || { echo 'UNVERIFIED: temporary keyfile ownership changed' >&2; exit 1; }
if [[ $KEYFILE_STATUS == owned ]]; then
    rm -f -- "$TEMP_FILE" || { echo 'UNVERIFIED: could not remove exact temporary WG keyfile' >&2; exit 1; }
fi
nm_inventory && kernel_inventory && route_inventory && hold_inventory && keyfile_inventory || {
    echo 'UNVERIFIED: final C23AI recovery poststate cannot be authenticated' >&2; exit 1;
}
[[ $NM_STATUS == absent && $ROUTE_STATUS == absent && $KEYFILE_STATUS == absent && $HOLD_STATUS == full ]] || {
    echo 'UNVERIFIED: C23AI WireGuard cleanup or private hold state is incomplete' >&2; exit 1;
}
if openvpn_active; then
    hold_note='Private-destination hold routes retained because OpenVPN is still active.'
else
    openvpn_rc=$?
    if (( openvpn_rc > 1 )); then
        echo 'UNVERIFIED: active OpenVPN inventory failed; private hold routes retained' >&2
        exit 1
    fi
    remove_hold_routes || { echo 'UNVERIFIED: OpenVPN is down but private hold routes could not be removed exactly' >&2; exit 1; }
    hold_note='Private-destination hold routes removed because no active OpenVPN remains.'
fi
printf '%s\n' \
  'PASS: authenticated C23AI WireGuard profile and endpoint route are absent' \
  'RESULT: MVC WIREGUARD RECOVERY COMPLETE — CONTROLLER FIREWALL LEFT IN PLACE' \
  "NOTE: $hold_note" \
  'NOTE: /run/ubs-v240-wireguard is intentionally retained; do not retry this session in the same boot.' \
  'NOTE: use /root/mvc-emergency-rollback separately only if you deliberately choose to disable the kill switch.'
