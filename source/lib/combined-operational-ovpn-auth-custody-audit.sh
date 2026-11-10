#!/usr/bin/env bash
# Step 2B2C3F7: read-only saved GetSettings per-credential custody/TLS *reference*
# metadata. NEVER GetSecrets, stat/open reference files, read private keys, or
# grant permission to import, start VPNs, or change firewall.

ubs24op_auth_audit_reset() {
    UBS24OP_AUTH_METHOD=unassessed
    UBS24OP_AUTH_PASSWORD=unassessed
    UBS24OP_AUTH_CERT_PASS=unassessed
    UBS24OP_AUTH_PROXY_PASSWORD=unassessed
    UBS24OP_AUTH_OTHER_FLAGS=unassessed
    UBS24OP_AUTH_CA=unassessed
    UBS24OP_AUTH_CLIENT=unassessed
    UBS24OP_AUTH_CONTROL=unassessed
    UBS24OP_AUTH_STATE=unverified
}

ubs24op_auth_audit() {
    ubs24op_auth_audit_reset
    (( $# == 1 )) || return 1
    local file=$1 summary=''
    [[ -f $file && ! -L $file && -O $file && $(stat -c %a:%h -- "$file") == 600:1 ]] || return 1
    # No values of secret/path/name/identity fields reach stdout, stderr or
    # status variables. Only fixed labels are produced by jq. Missing flags
    # do NOT establish that a secret is available; GetSettings omits secrets.
    # Integer flags are bitfields. Mixed states must never silently default
    # to NM-owned / reusable custody.
    summary=$(jq -er '
        def status:
            if . == null then "unreported"
            elif type != "string" then "unsupported"
            elif . == "0" then "nm-owned-unverified"
            elif . == "1" then "agent-owned"
            elif . == "2" then "not-saved"
            elif . == "3" then "agent-and-not-saved"
            elif . == "4" then "not-required"
            elif . == "5" or . == "6" or . == "7" then "mixed-not-required"
            else "unsupported" end;
        ((.type == "a{sa{sv}}") and
        (.data|type == "array" and length == 1) and
        (.data[0].vpn.data.type == "a{ss}") and
        (.data[0].vpn.data.data|type == "object") and
        (.data[0].vpn | has("secrets") | not)) as $valid |
        if $valid | not then error("invalid typed GetSettings") else . end |
        .data[0].vpn.data.data as $d |
        [
          (if ($d["connection-type"] == "password" or $d["connection-type"] == "password-tls" or
               $d["connection-type"] == "tls" or $d["connection-type"] == "static-key")
           then $d["connection-type"] else "other-or-unspecified" end),
          ($d["password-flags"] | status),
          ($d["cert-pass-flags"] | status),
          ($d["http-proxy-password-flags"] | status),
          (if ([$d|keys[]|select(endswith("-flags") and . != "password-flags" and
                                     . != "cert-pass-flags" and . != "http-proxy-password-flags")]|length)>0
           then "present" else "none" end),
          (if $d|has("ca") then "present" else "absent" end),
          (if ($d|has("pkcs12")) then
             if ($d|has("cert") or has("key")) then "pkcs12-plus-other" else "pkcs12" end
           elif ($d|has("cert")) and ($d|has("key")) then "cert-and-key"
           elif ($d|has("cert") or has("key")) then "incomplete-cert-key"
           else "none" end),
          (if ($d|has("tls-auth")) and ($d|has("tls-crypt")) then "both"
           elif $d|has("tls-auth") then "tls-auth"
           elif $d|has("tls-crypt") then "tls-crypt"
           else "none" end)
        ] | join("|")
    ' -- "$file" 2>/dev/null) || return 1
    local method pw cp proxy other ca client control extra
    IFS='|' read -r method pw cp proxy other ca client control extra <<< "$summary"
    [[ -z ${extra:-} && -n $control ]] || return 1
    case $method in password|password-tls|tls|static-key|other-or-unspecified) ;; *) return 1 ;; esac
    case $pw:$cp:$proxy in
        * )
            local value
            for value in "$pw" "$cp" "$proxy"; do
                case $value in unreported|unsupported|nm-owned-unverified|agent-owned|not-saved|agent-and-not-saved|not-required|mixed-not-required) ;; *) return 1 ;; esac
            done ;;
    esac
    [[ $other == none || $other == present ]] || return 1
    [[ $ca == present || $ca == absent ]] || return 1
    case $client in pkcs12|pkcs12-plus-other|cert-and-key|incomplete-cert-key|none) ;; *) return 1 ;; esac
    case $control in both|tls-auth|tls-crypt|none) ;; *) return 1 ;; esac
    UBS24OP_AUTH_METHOD=$method
    UBS24OP_AUTH_PASSWORD=$pw
    UBS24OP_AUTH_CERT_PASS=$cp
    UBS24OP_AUTH_PROXY_PASSWORD=$proxy
    UBS24OP_AUTH_OTHER_FLAGS=$other
    UBS24OP_AUTH_CA=$ca
    UBS24OP_AUTH_CLIENT=$client
    UBS24OP_AUTH_CONTROL=$control
    UBS24OP_AUTH_STATE=read-only-references-only
}

ubs24op_auth_audit_authorize_nm_write() { return 1; }
ubs24op_auth_audit_authorize_activation() { return 1; }
ubs24op_auth_audit_authorize_nft() { return 1; }

# C8B: report ONLY extra OpenVPN `*-flags` field NAMES to diagnose an
# otherwise non-admitting source profile. Never inspect/return any flag values.
# Limit counts and character set before returning strings sourced from NM.
# A name on this list does NOT make that flag safe or supported for activation.
ubs24op_auth_extra_flag_names() {
    (( $# == 1 )) || return 1
    local file=$1 result
    [[ -f $file && ! -L $file && -O $file &&
       $(stat -c %a:%h -- "$file") == 600:1 ]] || return 1
    result=$(jq -er '
        if .type != "a{sa{sv}}" or (.data|type) != "array" or
           (.data|length) != 1 or .data[0].vpn.data.type != "a{ss}" or
           (.data[0].vpn.data.data|type) != "object" or
           (.data[0].vpn|has("secrets")) then error("bad GetSettings") else . end |
        [.data[0].vpn.data.data | keys[] |
            select(endswith("-flags") and
                   . != "password-flags" and
                   . != "cert-pass-flags" and
                   . != "http-proxy-password-flags")] | sort |
        if (length > 12) or any(.[]; (test("^[a-z][a-z0-9-]{0,55}-flags$")|not)) then
            error("unclassifiable field names")
        elif length == 0 then "none"
        else join(",") end
    ' -- "$file" 2>/dev/null) || return 1
    [[ -n $result ]] || return 1
    UBS24OP_AUTH_EXTRA_FLAG_NAMES=$result
}

# C8B2: classify only the known OpenVPN challenge-response secret-policy bitfield.
# Return a fixed label. This reads GetSettings metadata, NEVER GetSecrets or the
# secret itself; NM-owned (0) is not proof of secret availability, nor does
# not-required (4) establish a future remote will never issue a challenge.
ubs24op_auth_challenge_flag_class() {
    (( $# == 1 )) || return 1
    local file=$1 result
    [[ -f $file && ! -L $file && -O $file &&
       $(stat -c %a:%h -- "$file") == 600:1 ]] || return 1
    result=$(jq -er '
        if .type != "a{sa{sv}}" or (.data|type) != "array" or
           (.data|length) != 1 or .data[0].vpn.data.type != "a{ss}" or
           (.data[0].vpn.data.data|type) != "object" or
           (.data[0].vpn|has("secrets")) then error("bad GetSettings") else . end |
        .data[0].vpn.data.data["challenge-response-flags"] |
        if . == null then "unreported"
        elif . == "0" then "nm-owned-unverified"
        elif . == "1" then "agent-owned"
        elif . == "2" then "not-saved"
        elif . == "3" then "agent-and-not-saved"
        elif . == "4" then "not-required"
        else "unsupported" end
    ' -- "$file" 2>/dev/null) || return 1
    case $result in
        unreported|nm-owned-unverified|agent-owned|not-saved|agent-and-not-saved|not-required|unsupported) ;;
        *) return 1 ;;
    esac
    UBS24OP_AUTH_CHALLENGE_CLASS=$result
}
