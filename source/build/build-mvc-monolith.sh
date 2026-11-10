#!/usr/bin/env bash
# Multi VPN Controller 2.4.1 — deterministic monolith builder.
# Public v2.4.1 release candidate.
# Lifecycle verbs delegate to the audited dispatcher; v2.4.1 physical proof remains pending.
set -euo pipefail
umask 077
export LC_ALL=C

UBS24_BUILD_VERSION='2.4.1'
UBS24_BUILD_CHECKPOINT='MVC_R2_RUNTIME_IDENTITY'
UBS24_BUILD_MANIFEST_REL='source/build/monolith-runtime.manifest'

ubs24_build_die() {
    printf 'build-mvc-monolith: %s\n' "$*" >&2
    exit 1
}

ubs24_build_script=${BASH_SOURCE[0]}
[[ $ubs24_build_script == /* ]] || ubs24_build_script=$PWD/$ubs24_build_script
ubs24_build_dir=$(cd -- "${ubs24_build_script%/*}" && pwd -P) || exit 1
ubs24_project_root=$(cd -- "$ubs24_build_dir/../.." && pwd -P) || exit 1
ubs24_manifest="$ubs24_project_root/$UBS24_BUILD_MANIFEST_REL"

(( $# == 1 )) || ubs24_build_die 'usage: build-mvc-monolith.sh OUTPUT'
ubs24_output=$1
[[ $ubs24_output == /* ]] || ubs24_output=$PWD/$ubs24_output
ubs24_output_dir=${ubs24_output%/*}
ubs24_output_name=${ubs24_output##*/}
[[ -n $ubs24_output_name && $ubs24_output_dir != "$ubs24_output" ]] || ubs24_build_die 'invalid output path'
mkdir -p -- "$ubs24_output_dir"
[[ -d $ubs24_output_dir && ! -L $ubs24_output_dir ]] || ubs24_build_die 'output directory must be a real directory'
ubs24_output_dir=$(cd -- "$ubs24_output_dir" && pwd -P) || exit 1
ubs24_output="$ubs24_output_dir/$ubs24_output_name"

ubs24_build_safe_relpath() {
    (( $# == 1 )) || return 1
    local rel=$1 part current=$ubs24_project_root
    [[ -n $rel && $rel != /* && $rel != *$'\n'* && $rel != *$'\r'* && $rel != *$'\t'* &&
       $rel != *'|'* && $rel != '../'* && $rel != */../* && $rel != */.. &&
       $rel != './'* && $rel != */./* && $rel != */. && $rel != *//* ]] || return 1
    IFS='/' read -r -a ubs24_build_parts <<< "$rel"
    for part in "${ubs24_build_parts[@]}"; do
        [[ -n $part && $part != . && $part != .. ]] || return 1
        current=$current/$part
        [[ ! -L $current ]] || return 1
    done
}

ubs24_build_hash_file() {
    (( $# == 1 )) || return 1
    sha256sum -- "$1" | awk '{print $1}'
}

[[ -f $ubs24_manifest && ! -L $ubs24_manifest ]] || ubs24_build_die 'runtime manifest missing or symlinked'
ubs24_manifest_sha=$(ubs24_build_hash_file "$ubs24_manifest") || exit 1
ubs24_builder_sha=$(ubs24_build_hash_file "$ubs24_build_script") || exit 1

# Parsed manifest state. Every declared input is validated even when its role is
# deferred to a later monolith stage; this makes drift visible immediately.
declare -a UBS24_BUILD_MODULE_PATHS=()
declare -a UBS24_BUILD_MODULE_SHAS=()
declare -a UBS24_BUILD_MODULE_ORDERS=()
declare -A UBS24_BUILD_KEYS=()
declare -A UBS24_BUILD_PATHS=()
declare -A UBS24_BUILD_ASSET_PATH=()
declare -A UBS24_BUILD_ASSET_SHA=()
declare -A UBS24_BUILD_INTEGRATE_PATH=()
declare -A UBS24_BUILD_INTEGRATE_SHA=()
declare -A UBS24_BUILD_RECOVERY_PATH=()
declare -A UBS24_BUILD_RECOVERY_SHA=()
declare -A UBS24_BUILD_KIND_COUNT=()
ubs24_record_count=0
ubs24_module_count=0

while IFS='|' read -r kind key expected_sha rel detail extra; do
    [[ -z ${extra:-} ]] || ubs24_build_die "manifest line has too many fields: $kind|$key"
    [[ -n ${kind:-} ]] || continue
    [[ $kind == \#* ]] && continue
    [[ -n ${key:-} && -n ${expected_sha:-} && -n ${rel:-} && -n ${detail:-} ]] || \
        ubs24_build_die "manifest line is incomplete: $kind|${key:-}"
    case $kind in
        MODULE|ASSET|INTEGRATE|EXTERNAL_RECOVERY|EXCLUDE) ;;
        *) ubs24_build_die "unexpected manifest kind: $kind" ;;
    esac
    [[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || ubs24_build_die "invalid SHA-256 for $kind|$key"
    ubs24_build_safe_relpath "$rel" || ubs24_build_die "unsafe or symlinked manifest path: $rel"
    abs=$ubs24_project_root/$rel
    [[ -f $abs && ! -L $abs ]] || ubs24_build_die "declared input is not a regular non-symlink file: $rel"
    actual_sha=$(ubs24_build_hash_file "$abs") || exit 1
    [[ $actual_sha == "$expected_sha" ]] || ubs24_build_die "SHA-256 mismatch: $rel"
    record_key=$kind:$key
    if [[ $kind != EXCLUDE ]]; then
        [[ -z ${UBS24_BUILD_KEYS[$record_key]+x} ]] || ubs24_build_die "duplicate manifest key: $record_key"
        UBS24_BUILD_KEYS[$record_key]=1
    fi
    [[ -z ${UBS24_BUILD_PATHS[$rel]+x} ]] || ubs24_build_die "duplicate manifest path: $rel"
    UBS24_BUILD_PATHS[$rel]=1
    UBS24_BUILD_KIND_COUNT[$kind]=$(( ${UBS24_BUILD_KIND_COUNT[$kind]:-0} + 1 ))
    ubs24_record_count=$((ubs24_record_count + 1))

    case $kind in
        MODULE)
            [[ $key =~ ^[0-9]{3}$ ]] || ubs24_build_die "invalid MODULE order: $key"
            expected_order=$(printf '%03d' $((ubs24_module_count + 1)))
            [[ $key == "$expected_order" ]] || ubs24_build_die "MODULE order gap/reorder: expected $expected_order, got $key"
            UBS24_BUILD_MODULE_ORDERS+=("$key")
            UBS24_BUILD_MODULE_SHAS+=("$expected_sha")
            UBS24_BUILD_MODULE_PATHS+=("$rel")
            ubs24_module_count=$((ubs24_module_count + 1))
            ;;
        ASSET)
            case $key in
                gvariant-awk|b4-bootstrap-nft) ;;
                *) ubs24_build_die "unexpected ASSET key: $key" ;;
            esac
            UBS24_BUILD_ASSET_PATH[$key]=$rel
            UBS24_BUILD_ASSET_SHA[$key]=$expected_sha
            ;;
        INTEGRATE)
            case $key in
                openvpn-source-preview|verify) ;;
                *) ubs24_build_die "unexpected INTEGRATE key: $key" ;;
            esac
            UBS24_BUILD_INTEGRATE_PATH[$key]=$rel
            UBS24_BUILD_INTEGRATE_SHA[$key]=$expected_sha
            ;;
        EXTERNAL_RECOVERY)
            case $key in
                emergency|dual) ;;
                *) ubs24_build_die "unexpected EXTERNAL_RECOVERY key: $key" ;;
            esac
            UBS24_BUILD_RECOVERY_PATH[$key]=$rel
            UBS24_BUILD_RECOVERY_SHA[$key]=$expected_sha
            ;;
    esac
done < "$ubs24_manifest"

[[ $ubs24_record_count == 57 ]] || ubs24_build_die "manifest record count changed: $ubs24_record_count"
[[ $ubs24_module_count == 49 ]] || ubs24_build_die "MODULE count changed: $ubs24_module_count"
[[ ${UBS24_BUILD_KIND_COUNT[ASSET]:-0} == 2 &&
   ${UBS24_BUILD_KIND_COUNT[INTEGRATE]:-0} == 2 &&
   ${UBS24_BUILD_KIND_COUNT[EXTERNAL_RECOVERY]:-0} == 2 &&
   ${UBS24_BUILD_KIND_COUNT[EXCLUDE]:-0} == 2 ]] || ubs24_build_die 'manifest role counts changed'
[[ ${UBS24_BUILD_ASSET_PATH[gvariant-awk]:-} == source/lib/combined-gvariant-settings-to-json.awk ]] || \
    ubs24_build_die 'gvariant asset path changed'
[[ ${UBS24_BUILD_ASSET_PATH[b4-bootstrap-nft]:-} == source/nftables/vpn-v240-preclone-quarantine-offline.nft ]] || \
    ubs24_build_die 'B4 nft asset path changed'
[[ ${UBS24_BUILD_INTEGRATE_PATH[openvpn-source-preview]:-} == source/tools/check-v240-live-saved-ovpn-readonly.sh ]] || \
    ubs24_build_die 'OpenVPN preview integration path changed'
[[ ${UBS24_BUILD_INTEGRATE_PATH[verify]:-} == source/tools/verify-mvc-state-readonly.sh ]] || \
    ubs24_build_die 'read-only verifier integration path changed'
[[ ${UBS24_BUILD_RECOVERY_PATH[emergency]:-} == source/tools/recover-mvc-host-guard-local.sh ]] || \
    ubs24_build_die 'emergency recovery source path changed'
[[ ${UBS24_BUILD_RECOVERY_PATH[dual]:-} == source/tools/recover-mvc-dual-local.sh ]] || \
    ubs24_build_die 'dual recovery source path changed'

ubs24_tmp=$ubs24_output_dir/.${ubs24_output_name}.tmp.$$
trap 'rm -f -- "$ubs24_tmp"' EXIT
: > "$ubs24_tmp"
chmod 600 "$ubs24_tmp"

ubs24_emit() { printf '%s\n' "$*" >> "$ubs24_tmp"; }

ubs24_emit '#!/usr/bin/env bash'
ubs24_emit '# Multi VPN Controller 2.4.1'
ubs24_emit '# GENERATED RELEASE ARTIFACT — DO NOT EDIT DIRECTLY'
ubs24_emit '# Changes belong in the modular source tree and must be rebuilt.'
ubs24_emit '#'
ubs24_emit '# C24A Stage 3 v2.4.1 operational candidate.'
ubs24_emit '# Generated-runtime equivalence is proven; lifecycle delegates to the audited public dispatcher.'
ubs24_emit "# Source checkpoint: $UBS24_BUILD_CHECKPOINT"
ubs24_emit "# Runtime manifest SHA-256: $ubs24_manifest_sha"
ubs24_emit "# Builder SHA-256: $ubs24_builder_sha"
ubs24_emit "# Ordered runtime modules: $ubs24_module_count"
ubs24_emit '# Embedded resources: 2'
ubs24_emit ''
ubs24_emit 'set -euo pipefail'
ubs24_emit 'umask 077'
ubs24_emit 'export LC_ALL=C'
ubs24_emit "readonly UBS24_MONOLITH_VERSION='$UBS24_BUILD_VERSION'"
ubs24_emit "readonly UBS24_MONOLITH_CHECKPOINT='$UBS24_BUILD_CHECKPOINT'"
ubs24_emit "readonly UBS24_MONOLITH_MANIFEST_SHA256='$ubs24_manifest_sha'"
ubs24_emit "readonly UBS24_MONOLITH_BUILDER_SHA256='$ubs24_builder_sha'"
ubs24_emit "readonly UBS24_MONOLITH_VERIFY_SOURCE_SHA256='${UBS24_BUILD_INTEGRATE_SHA[verify]}'"
ubs24_emit "readonly UBS24_MONOLITH_EMERGENCY_RECOVERY='/root/mvc-emergency-rollback'"
ubs24_emit "readonly UBS24_MONOLITH_EMERGENCY_RECOVERY_SHA256='${UBS24_BUILD_RECOVERY_SHA[emergency]}'"
ubs24_emit "readonly UBS24_MONOLITH_DUAL_RECOVERY='/root/mvc-dual-recovery'"
ubs24_emit "readonly UBS24_MONOLITH_DUAL_RECOVERY_SHA256='${UBS24_BUILD_RECOVERY_SHA[dual]}'"
ubs24_emit ''
ubs24_emit '# ============================================================================'
ubs24_emit '# Embedded deterministic runtime resources'
ubs24_emit '# ============================================================================'

ubs24_build_emit_resource_function() {
    (( $# == 3 )) || return 1
    local name=$1 rel=$2 sha=$3 fn delim
    case $name in
        gvariant-awk) fn=ubs24mon_emit_gvariant_awk ;;
        b4-bootstrap-nft) fn=ubs24mon_emit_b4_bootstrap_nft ;;
        *) return 1 ;;
    esac
    delim="__UBS24_RESOURCE_${sha}__"
    ! grep -Fqx -- "$delim" "$ubs24_project_root/$rel" || ubs24_build_die "resource delimiter collision: $rel"
    ubs24_emit "# Resource: $rel"
    ubs24_emit "# SHA-256: $sha"
    ubs24_emit "$fn() {"
    ubs24_emit "    cat <<'$delim'"
    [[ $(tail -c 1 -- "$ubs24_project_root/$rel" | od -An -t x1 | tr -d ' \n') == 0a ]] || \
        ubs24_build_die "embedded text resource is not newline-terminated: $rel"
    cat -- "$ubs24_project_root/$rel" >> "$ubs24_tmp"
    printf '%s\n' "$delim" >> "$ubs24_tmp"
    ubs24_emit '}'
    ubs24_emit ''
}

ubs24_build_emit_resource_function gvariant-awk \
    "${UBS24_BUILD_ASSET_PATH[gvariant-awk]}" "${UBS24_BUILD_ASSET_SHA[gvariant-awk]}"
ubs24_build_emit_resource_function b4-bootstrap-nft \
    "${UBS24_BUILD_ASSET_PATH[b4-bootstrap-nft]}" "${UBS24_BUILD_ASSET_SHA[b4-bootstrap-nft]}"

cat >> "$ubs24_tmp" <<'BASH_RESOURCE_HELPERS'
ubs24mon_resource_sha256() {
    (( $# == 1 )) || return 1
    case $1 in
        gvariant-awk) printf '%s\n' '__GVARIANT_SHA__' ;;
        b4-bootstrap-nft) printf '%s\n' '__B4_SHA__' ;;
        *) return 1 ;;
    esac
}

ubs24mon_materialize_resource() {
    (( $# == 2 )) || return 1
    local name=$1 dest=$2 dir base tmp expected actual
    [[ $dest == /* && $dest != / && $dest != */ && $dest != *$'\n'* &&
       $dest != *$'\r'* && $dest != *$'\t'* ]] || return 1
    dir=${dest%/*}
    base=${dest##*/}
    [[ -d $dir && ! -L $dir && -n $base ]] || return 1
    expected=$(ubs24mon_resource_sha256 "$name") || return 1
    tmp=$dir/.${base}.ubs24-resource.$$
    rm -f -- "$tmp"
    case $name in
        gvariant-awk) (umask 077; ubs24mon_emit_gvariant_awk > "$tmp") || { rm -f -- "$tmp"; return 1; } ;;
        b4-bootstrap-nft) (umask 077; ubs24mon_emit_b4_bootstrap_nft > "$tmp") || { rm -f -- "$tmp"; return 1; } ;;
        *) return 1 ;;
    esac
    chmod 600 -- "$tmp" || { rm -f -- "$tmp"; return 1; }
    actual=$(sha256sum -- "$tmp" | awk '{print $1}') || { rm -f -- "$tmp"; return 1; }
    [[ $actual == "$expected" ]] || { rm -f -- "$tmp"; return 1; }
    mv -T -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
    [[ -f $dest && ! -L $dest && $(stat -c %a -- "$dest") == 600 ]] || return 1
}

UBS24_MONOLITH_ASSET_DIR=''

ubs24mon_runtime_assets_cleanup() {
    (( $# == 0 )) || return 1
    local dir=${UBS24_MONOLITH_ASSET_DIR:-}
    [[ -n $dir ]] || return 0
    if [[ -d $dir && ! -L $dir && $dir == /dev/shm/mvc-monolith-assets.* ]]; then
        rm -f -- "$dir/gvariant-settings-to-json.awk" "$dir/vpn-v240-preclone-quarantine-offline.nft" 2>/dev/null || :
        rmdir -- "$dir" 2>/dev/null || :
    fi
    UBS24_MONOLITH_ASSET_DIR=''
    export UBS24_MONOLITH_ASSET_DIR
}

ubs24mon_runtime_assets_prepare() {
    (( $# == 0 )) || return 1
    local dir
    if [[ -n ${UBS24_MONOLITH_ASSET_DIR:-} ]]; then
        dir=$UBS24_MONOLITH_ASSET_DIR
        [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == "$EUID:700:2" ]] || return 1
        [[ -f $dir/gvariant-settings-to-json.awk && ! -L $dir/gvariant-settings-to-json.awk &&
           -f $dir/vpn-v240-preclone-quarantine-offline.nft && ! -L $dir/vpn-v240-preclone-quarantine-offline.nft ]] || return 1
        return 0
    fi
    [[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm 2>/dev/null) == tmpfs ]] || return 1
    dir=$(umask 077; mktemp -d /dev/shm/mvc-monolith-assets.XXXXXXXX) || return 1
    chmod 700 -- "$dir" || { rmdir -- "$dir" 2>/dev/null || :; return 1; }
    if ! ubs24mon_materialize_resource gvariant-awk "$dir/gvariant-settings-to-json.awk" ||
       ! ubs24mon_materialize_resource b4-bootstrap-nft "$dir/vpn-v240-preclone-quarantine-offline.nft"; then
        rm -f -- "$dir/gvariant-settings-to-json.awk" "$dir/vpn-v240-preclone-quarantine-offline.nft" 2>/dev/null || :
        rmdir -- "$dir" 2>/dev/null || :
        return 1
    fi
    UBS24_MONOLITH_ASSET_DIR=$dir
    export UBS24_MONOLITH_ASSET_DIR
}

ubs24mon_runtime_asset_dir() {
    (( $# == 0 )) || return 1
    local dir=${UBS24_MONOLITH_ASSET_DIR:-}
    [[ -n $dir && -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == "$EUID:700:2" ]] || return 1
    printf '%s\n' "$dir"
}

ubs24mon_runtime_asset_path() {
    (( $# == 1 )) || return 1
    local dir path expected actual
    dir=$(ubs24mon_runtime_asset_dir) || return 1
    case $1 in
        gvariant-awk) path=$dir/gvariant-settings-to-json.awk ;;
        b4-bootstrap-nft) path=$dir/vpn-v240-preclone-quarantine-offline.nft ;;
        *) return 1 ;;
    esac
    expected=$(ubs24mon_resource_sha256 "$1") || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == "$EUID:600:1" ]] || return 1
    actual=$(sha256sum -- "$path" | awk '{print $1}') || return 1
    [[ $actual == "$expected" ]] || return 1
    printf '%s\n' "$path"
}
BASH_RESOURCE_HELPERS
# Replace deterministic placeholders without depending on source path ordering.
sed -i \
    -e "s/__GVARIANT_SHA__/${UBS24_BUILD_ASSET_SHA[gvariant-awk]}/" \
    -e "s/__B4_SHA__/${UBS24_BUILD_ASSET_SHA[b4-bootstrap-nft]}/" \
    "$ubs24_tmp"
ubs24_emit ''

ubs24_build_emit_module() {
    (( $# == 3 )) || return 1
    local order=$1 sha=$2 rel=$3 abs first line replacement_count=0 expected_replacements=0
    abs=$ubs24_project_root/$rel
    ubs24_emit '# ============================================================================'
    ubs24_emit "# >>> BEGIN MODULE $order: $rel"
    ubs24_emit "# >>> SOURCE SHA-256: $sha"
    ubs24_emit '# ============================================================================'
    IFS= read -r first < "$abs" || first=''
    local start_line=1
    [[ $first == '#!'* ]] && start_line=2
    case $rel in
        source/lib/combined-dbus-gdbus-settings.sh|\
        source/lib/combined-operational-host-guard-transaction.sh|\
        source/lib/combined-operational-c3-held-lifecycle.sh|\
        source/lib/combined-operational-wireguard-protected-v240.sh)
            expected_replacements=1 ;;
    esac
    while IFS= read -r line || [[ -n $line ]]; do
        case "$rel|$line" in
            'source/lib/combined-dbus-gdbus-settings.sh|    decoder=${BASH_SOURCE[0]%/*}/combined-gvariant-settings-to-json.awk')
                line='    decoder=$(ubs24mon_runtime_asset_path gvariant-awk) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-host-guard-transaction.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1')
                line='    base=$(ubs24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-c3-held-lifecycle.sh|    policy=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1')
                line='    policy=$(ubs24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-wireguard-protected-v240.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd) || return 1')
                line='    base=$(ubs24mon_runtime_asset_dir) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
        esac
        printf '%s\n' "$line" >> "$ubs24_tmp"
    done < <(tail -n +"$start_line" -- "$abs")
    [[ $replacement_count == "$expected_replacements" ]] || \
        ubs24_build_die "runtime seam replacement count changed for $rel: expected $expected_replacements got $replacement_count"
    printf '\n' >> "$ubs24_tmp"
    ubs24_emit "# <<< END MODULE $order: $rel"
    ubs24_emit ''
}

# Modules 001..048 are the public composition body. The modular composition
# file also provides three runtime glue functions after loading these modules;
# reproduce only those functions, not its source-loop/loader mechanics.
for ((i=0; i<48; i++)); do
    ubs24_build_emit_module "${UBS24_BUILD_MODULE_ORDERS[$i]}" \
        "${UBS24_BUILD_MODULE_SHAS[$i]}" "${UBS24_BUILD_MODULE_PATHS[$i]}"
done

cat >> "$ubs24_tmp" <<'BASH_MONOLITH_GLUE'
# ============================================================================
# >>> BEGIN MONOLITH COMPOSITION GLUE
# Derived from loader-only combined-operational-public-v240-composition.sh.
# This section intentionally contains runtime glue only; no project-tree source.
# ============================================================================
ubs24pub_session_runtime_root() { printf '%s\n' /run/mvc-public-session; }
ubs24pub_wireguard_runtime_root() { printf '%s\n' /run/mvc-wireguard; }

ubs24pub_process_initialize() {
    (( $# == 0 )) || return 1
    ubs24mon_runtime_assets_prepare || return 1
    local reset
    for reset in \
        ubs24gb1_reset ubs24gb2_reset ubs24gb4_reset \
        ubs24ga_reset ubs24ga2_reset ubs24ga3_reset \
        ubs24gc1_reset ubs24gc3_reset ubs24gc4_reset ubs24gc5_reset ubs24gc6_reset \
        ubs24gc7_reset ubs24gc8_reset ubs24gc14_reset ubs24gc9_reset ubs24gc11_reset \
        ubs24gc13_reset ubs24gc15_reset ubs24gc16_reset ubs24gc17_reset ubs24gc18_reset \
        ubs24gc19_reset ubs24gc23t_reset ubs24gco_reset \
        ubs24gd2_reset ubs24gd3_reset ubs24gd4_reset ubs24gwg_reset ubs24gws_reset ubs24pubr_reset ubs24pube_reset \
        ubs24op_candidate_reset ubs24op_preview_reset ubs24op_qg_reset \
        ubs24pub_reset ubs24pubc_reset ubs24pubd_reset; do
        declare -F "$reset" >/dev/null || return 1
        "$reset" || return 1
    done

    # Monolith-native C4 admission does not use a project source root.
    UBS24GC4_SOURCE_ROOT=

    [[ ${UBS24GD4_TEMP_NAME:-} == vpnks-wg &&
       ${UBS24GD4_RUNTIME:-} == /run/mvc-wireguard &&
       ${UBS24PUBC_STAGE:-} == idle && ${UBS24PUBD_STAGE:-} == idle ]]
}
# <<< END MONOLITH COMPOSITION GLUE

BASH_MONOLITH_GLUE

# Module 049 is the public dispatcher and must remain final in modular function order.
ubs24_build_emit_module "${UBS24_BUILD_MODULE_ORDERS[48]}" \
    "${UBS24_BUILD_MODULE_SHAS[48]}" "${UBS24_BUILD_MODULE_PATHS[48]}"

cat >> "$ubs24_tmp" <<'BASH_STAGE3A_SEAMS'
# ============================================================================
# >>> BEGIN C23BN STAGE-3A MONOLITH RUNTIME SEAMS
# Only project-tree-dependent C4 admission seams are overridden here.
# Lifecycle functions remain the ordered modular definitions above.
# ============================================================================
ubs24mon_recovery_file_identity() {
    (( $# == 2 )) || return 1
    local installed=$1 expected=$2 actual
    [[ $installed == /* && $expected =~ ^[0-9a-f]{64}$ &&
       -f $installed && ! -L $installed && -x $installed ]] || return 1
    [[ $(stat -c '%u:%a:%h' -- "$installed" 2>/dev/null) == '0:700:1' ]] || return 1
    actual=$(sha256sum -- "$installed" 2>/dev/null | awk '{print $1}') || return 1
    [[ $actual == "$expected" ]]
}

ubs24mon_openvpn_source_shape_valid() {
    (( $# == 2 )) || return 1
    local file=$1 expected_uuid=$2
    [[ -f $file && ! -L $file ]] || return 1
    jq -e --arg uuid "$expected_uuid" '
        .type == "a{sa{sv}}" and
        (.data|type) == "array" and (.data|length) == 1 and
        .data[0].connection.uuid == {type:"s", data:$uuid} and
        .data[0].connection.type == {type:"s", data:"vpn"} and
        .data[0].vpn["service-type"] == {type:"s", data:"org.freedesktop.NetworkManager.openvpn"} and
        .data[0].vpn.data.type == "a{ss}" and
        (.data[0].vpn.data.data|type) == "object"
    ' "$file" >/dev/null 2>&1
}

ubs24mon_openvpn_source_preview() {
    (( $# == 1 )) || return 1
    local uuid=$1 initial_owner object first_obj='' second_obj='' side path reply
    local unsaved_before unsaved_after preview_uuid scratch result=1
    local old_lock_set=0 old_lock=''
    local re='^o "(/org/freedesktop/NetworkManager/Settings/[0-9]+)"$'
    local bin
    ubs24_valid_uuid "$uuid" || return 1
    [[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm 2>/dev/null) == tmpfs ]] || return 1
    for bin in gdbus awk jq mktemp cmp stat sha256sum; do
        command -v "$bin" >/dev/null 2>&1 || return 1
    done
    ubs24op_session_nm_identity || return 1
    initial_owner=${UBS24OP_SESSION_NM_IDENTITY:-}
    [[ -n $initial_owner ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs24-monolith-saved-host.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch && $(stat -c %a:%h -- "$scratch") == 700:2 ]] || {
        rm -rf -- "$scratch" 2>/dev/null || :
        return 1
    }
    if [[ ${UBS24S_LOCK_HELD+x} ]]; then
        old_lock_set=1
        old_lock=$UBS24S_LOCK_HELD
    fi
    UBS24S_LOCK_HELD=1

    while :; do
        for side in first second; do
            path=$scratch/$side.json
            (umask 077; set -C; : > "$path") || break 2
            [[ -f $path && ! -L $path && $(stat -c %a:%h -- "$path") == 600:1 ]] || break 2
            reply=$(ubs24g_call_readonly org.freedesktop.NetworkManager \
                /org/freedesktop/NetworkManager/Settings \
                org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || break 2
            [[ $reply =~ $re ]] || break 2
            object=${BASH_REMATCH[1]}
            if [[ $side == first ]]; then first_obj=$object; else second_obj=$object; fi
            unsaved_before=$(ubs24g_get_property org.freedesktop.NetworkManager "$object" \
                org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || break 2
            [[ $unsaved_before == 'b false' ]] || break 2
            ubs24gs_capture_settings "$object" "$path" || break 2
            ubs24mon_openvpn_source_shape_valid "$path" "$uuid" || break 2
            unsaved_after=$(ubs24g_get_property org.freedesktop.NetworkManager "$object" \
                org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || break 2
            [[ $unsaved_after == 'b false' ]] || break 2
            ubs24op_session_nm_identity || break 2
            [[ ${UBS24OP_SESSION_NM_IDENTITY:-} == "$initial_owner" ]] || break 2
        done
        [[ -n $first_obj && $first_obj == "$second_obj" ]] || break
        cmp -s -- "$scratch/first.json" "$scratch/second.json" || break
        ubs24op_session_nm_identity || break
        [[ ${UBS24OP_SESSION_NM_IDENTITY:-} == "$initial_owner" ]] || break
        path=$scratch/preview.json
        (umask 077; set -C; : > "$path") || break
        [[ -f $path && ! -L $path && $(stat -c %a:%h -- "$path") == 600:1 ]] || break
        preview_uuid=$(cat /proc/sys/kernel/random/uuid) || break
        ubs24op_preview_build "$scratch/first.json" "$preview_uuid" "$path" || break
        result=0
        break
    done

    if (( old_lock_set == 1 )); then UBS24S_LOCK_HELD=$old_lock; else unset UBS24S_LOCK_HELD; fi
    rm -f -- "$scratch/first.json" "$scratch/second.json" "$scratch/preview.json" 2>/dev/null || result=1
    rmdir -- "$scratch" 2>/dev/null || result=1
    (( result == 0 ))
}

# Monolith-specific C4 replacements. They retain the original fail-closed C4
# call contract while removing sibling source/tool dependencies.
ubs24gc4_recovery_installed() {
    (( $# == 0 )) || return 1
    ubs24mon_recovery_file_identity "$UBS24_MONOLITH_EMERGENCY_RECOVERY" \
        "$UBS24_MONOLITH_EMERGENCY_RECOVERY_SHA256"
}

ubs24gc4_source_preview() {
    (( $# == 1 )) || return 1
    ubs24mon_openvpn_source_preview "$1"
}
# <<< END C23BN STAGE-3A MONOLITH RUNTIME SEAMS

BASH_STAGE3A_SEAMS

# Integrate only the explicitly marked function block from the audited read-only
# verifier. The standalone executable shell and top-level main call are not
# copied into the monolith.
ubs24_build_emit_verify_functions() {
    (( $# == 0 )) || return 1
    local rel=${UBS24_BUILD_INTEGRATE_PATH[verify]} abs begin end begin_count end_count
    abs=$ubs24_project_root/$rel
    begin='# UBS24_MONOLITH_VERIFY_FUNCTIONS_BEGIN'
    end='# UBS24_MONOLITH_VERIFY_FUNCTIONS_END'
    begin_count=$(grep -Fxc -- "$begin" "$abs") || :
    end_count=$(grep -Fxc -- "$end" "$abs") || :
    [[ $begin_count == 1 && $end_count == 1 ]] || \
        ubs24_build_die 'read-only verifier integration markers changed'
    ubs24_emit '# ============================================================================'
    ubs24_emit '# >>> BEGIN C23BN STAGE-3B READ-ONLY VERIFIER'
    ubs24_emit "# >>> SOURCE: $rel"
    ubs24_emit "# >>> SOURCE SHA-256: ${UBS24_BUILD_INTEGRATE_SHA[verify]}"
    awk -v begin="$begin" -v end="$end" '
        $0 == begin { inside=1; seen_begin++; next }
        $0 == end { inside=0; seen_end++; next }
        inside { print }
        END { if (seen_begin != 1 || seen_end != 1 || inside) exit 7 }
    ' "$abs" >> "$ubs24_tmp" || ubs24_build_die 'failed to extract read-only verifier integration block'
    ubs24_emit '# <<< END C23BN STAGE-3B READ-ONLY VERIFIER'
    ubs24_emit ''
}
ubs24_build_emit_verify_functions

cat >> "$ubs24_tmp" <<'BASH_STAGE5_WRAPPER'

# ============================================================================
# C24A Stage-3 v2.4.1 release wrapper — audited dispatcher, physical proof pending
# ============================================================================
# Monolith-specific verifier status callback. `verify` observes this artifact's
# own read-only status implementation, never a sibling controller.
ubs24v_controller_status() {
    (( $# == 1 )) || return 2
    ubs24pub_status_readonly
}

ubs24v_usage() {
    cat <<'USAGE'
Usage: sudo mvc verify [--no-internet-check]

Print a read-only host-state report suitable after CONNECT or DISCONNECT.
The observed-shape classification is diagnostic only and grants no lifecycle,
cleanup, disconnect, or recovery authority.
USAGE
}

ubs24mon_require_stage5_functions() {
    local fn
    for fn in \
        ubs24_parse_command ubs24e_dispatch ubs24pub_process_initialize \
        ubs24pub_session_runtime_root ubs24pub_wireguard_runtime_root \
        ubs24pub_list_readonly ubs24pub_status_readonly \
        ubs24pubc_connect_once ubs24pubc_connect_openvpn_once \
        ubs24pubc_connect_wireguard_protected_once ubs24pubc_connect_wireguard_split_once \
        ubs24pubd_disconnect_once ubs24gco_start_once ubs24gco_stop_once \
        ubs24gco_complete_once ubs24gd4_start_once ubs24gd4_stop_once \
        ubs24gwg_start_once ubs24gwg_stop_once ubs24gws_stop_once \
        ubs24mon_openvpn_source_preview ubs24mon_recovery_file_identity \
        ubs24mon_runtime_asset_path ubs24v_main ubs24v_controller_status ubs24v_usage; do
        declare -F -- "$fn" >/dev/null || return 1
    done
}

ubs24mon_stage5_help() {
    cat <<'HELP'
Multi VPN Controller 2.4.1 — public identity release candidate

Daily commands:
  version | --version
  version --verbose
  help | -h | --help
  list
  status
  verify [--no-internet-check]
  preflight OPENVPN_PROFILE
  preflight WIREGUARD_PROFILE
  preflight WIREGUARD_PROFILE --split
  preflight WIREGUARD_PROFILE --split OPENVPN_PROFILE
  connect OPENVPN_PROFILE
  connect WIREGUARD_PROFILE
  connect WIREGUARD_PROFILE --split
  connect WIREGUARD_PROFILE --split OPENVPN_PROFILE
  disconnect

Modes:
  OpenVPN-only:
    sudo mvc connect OPENVPN_PROFILE
  Protected WireGuard-only (ordinary Internet kill-switched):
    sudo mvc connect WIREGUARD_PROFILE
  WireGuard-only split (ordinary Internet/DNS remain on the underlay):
    sudo mvc connect WIREGUARD_PROFILE --split
  Combined OpenVPN + split WireGuard:
    sudo mvc connect WIREGUARD_PROFILE --split OPENVPN_PROFILE

Run the matching `preflight` form before CONNECT. `verify` is diagnostic only;
its observed-shape classification never grants cleanup/disconnect/recovery authority.

Independent recovery tools:
  /root/mvc-emergency-rollback
  /root/mvc-dual-recovery

This MVC v2.4.1 candidate has completed offline identity/build regression; physical proof
of this exact hash remains pending controlled live-host validation.

Development/internal diagnostics retained for regression testing:
  --monolith-build-info
  --monolith-resource-selftest DIRECTORY
HELP
}

ubs24mon_stage5_build_info() {
    printf 'version=%s\n' "$UBS24_MONOLITH_VERSION"
    printf 'checkpoint=%s\n' "$UBS24_MONOLITH_CHECKPOINT"
    printf 'authority=audited-dispatch-mvc-v241-candidate-physical-pending\n'
    printf 'manifest_sha256=%s\n' "$UBS24_MONOLITH_MANIFEST_SHA256"
    printf 'builder_sha256=%s\n' "$UBS24_MONOLITH_BUILDER_SHA256"
    printf 'verify_source_sha256=%s\n' "$UBS24_MONOLITH_VERIFY_SOURCE_SHA256"
    printf 'emergency_recovery=%s\n' "$UBS24_MONOLITH_EMERGENCY_RECOVERY"
    printf 'emergency_recovery_sha256=%s\n' "$UBS24_MONOLITH_EMERGENCY_RECOVERY_SHA256"
    printf 'dual_recovery=%s\n' "$UBS24_MONOLITH_DUAL_RECOVERY"
    printf 'dual_recovery_sha256=%s\n' "$UBS24_MONOLITH_DUAL_RECOVERY_SHA256"
}

ubs24mon_stage5_version_verbose() {
    printf 'Multi VPN Controller %s\n' "$UBS24_MONOLITH_VERSION"
    ubs24mon_stage5_build_info
}

ubs24mon_stage5_resource_selftest() {
    (( $# == 1 )) || return 2
    local dir=$1 awk_out nft_out
    [[ $dir == /* && -d $dir && ! -L $dir ]] || return 2
    awk_out=$dir/gvariant-settings-to-json.awk
    nft_out=$dir/preclone-quarantine.nft
    ubs24mon_materialize_resource gvariant-awk "$awk_out" || return 1
    ubs24mon_materialize_resource b4-bootstrap-nft "$nft_out" || return 1
    printf 'gvariant-awk=%s\n' "$(sha256sum -- "$awk_out" | awk '{print $1}')"
    printf 'b4-bootstrap-nft=%s\n' "$(sha256sum -- "$nft_out" | awk '{print $1}')"
}

ubs24mon_stage5_main() {
    ubs24mon_require_stage5_functions || {
        printf '%s\n' 'Multi VPN Controller v2.4.1 candidate monolith is incomplete.' >&2
        return 70
    }
    case ${1:-} in
        version)
            case $# in
                1) ubs24e_dispatch version ;;
                2) [[ $2 == --verbose ]] || return 2; ubs24mon_stage5_version_verbose ;;
                *) return 2 ;;
            esac
            ;;
        --version)
            (( $# == 1 )) || return 2
            ubs24e_dispatch version
            ;;
        help|-h|--help)
            (( $# == 1 )) || return 2
            ubs24mon_stage5_help
            ;;
        verify)
            if (( $# == 1 )); then
                ubs24v_main
            elif (( $# == 2 )); then
                case $2 in
                    --no-internet-check|-h|--help) ubs24v_main "$2" ;;
                    *) ubs24v_usage >&2; return 2 ;;
                esac
            else
                ubs24v_usage >&2
                return 2
            fi
            ;;
        --monolith-build-info)
            (( $# == 1 )) || return 2
            ubs24mon_stage5_build_info
            ;;
        --monolith-resource-selftest)
            (( $# == 2 )) || return 2
            ubs24mon_stage5_resource_selftest "$2"
            ;;
        preflight|list|status|connect|disconnect)
            ubs24e_dispatch "$@"
            ;;
        '')
            ubs24mon_stage5_help >&2
            return 2
            ;;
        *)
            printf 'Multi VPN Controller: unknown command `%s`; use --help.\n' "$1" >&2
            return 2
            ;;
    esac
}

ubs24mon_stage5_main "$@"
BASH_STAGE5_WRAPPER

bash -n "$ubs24_tmp" || ubs24_build_die 'generated artifact failed bash -n'
chmod 755 "$ubs24_tmp"
mv -T -- "$ubs24_tmp" "$ubs24_output"
trap - EXIT
printf '%s  %s\n' "$(ubs24_build_hash_file "$ubs24_output")" "$ubs24_output"
