#!/usr/bin/env bash
# Multi VPN Controller — deterministic monolith builder.
# Release identity is read from the manifest-pinned source/release-version file.
# Lifecycle verbs delegate to the audited dispatcher; validation evidence remains hash-specific.
set -euo pipefail
umask 077
export LC_ALL=C

MVC24_BUILD_MANIFEST_REL='source/build/monolith-runtime.manifest'

mvc24_build_die() {
    printf 'build-mvc-monolith: %s\n' "$*" >&2
    exit 1
}

mvc24_build_require_commands() {
    local bin
    for bin in awk bash cat chmod grep mkdir mktemp mv od rm rmdir sed sha256sum stat tail tr; do
        command -v "$bin" >/dev/null 2>&1 || mvc24_build_die "missing build prerequisite: $bin"
    done
}

mvc24_build_script=${BASH_SOURCE[0]}
[[ $mvc24_build_script == /* ]] || mvc24_build_script=$PWD/$mvc24_build_script
mvc24_build_dir=$(cd -- "${mvc24_build_script%/*}" && pwd -P) || exit 1
mvc24_project_root=$(cd -- "$mvc24_build_dir/../.." && pwd -P) || exit 1
mvc24_manifest="$mvc24_project_root/$MVC24_BUILD_MANIFEST_REL"

(( $# == 1 )) || mvc24_build_die 'usage: build-mvc-monolith.sh OUTPUT'
mvc24_build_require_commands
mvc24_output=$1
[[ $mvc24_output == /* ]] || mvc24_output=$PWD/$mvc24_output
mvc24_output_dir=${mvc24_output%/*}
mvc24_output_name=${mvc24_output##*/}
[[ -n $mvc24_output_name && $mvc24_output_dir != "$mvc24_output" ]] || mvc24_build_die 'invalid output path'
mkdir -p -- "$mvc24_output_dir"
[[ -d $mvc24_output_dir && ! -L $mvc24_output_dir ]] || mvc24_build_die 'output directory must be a real directory'
mvc24_output_dir=$(cd -- "$mvc24_output_dir" && pwd -P) || exit 1
mvc24_output="$mvc24_output_dir/$mvc24_output_name"

mvc24_build_safe_relpath() {
    (( $# == 1 )) || return 1
    local rel=$1 part current=$mvc24_project_root
    [[ -n $rel && $rel != /* && $rel != *$'\n'* && $rel != *$'\r'* && $rel != *$'\t'* &&
       $rel != *'|'* && $rel != '../'* && $rel != */../* && $rel != */.. &&
       $rel != './'* && $rel != */./* && $rel != */. && $rel != *//* ]] || return 1
    IFS='/' read -r -a mvc24_build_parts <<< "$rel"
    for part in "${mvc24_build_parts[@]}"; do
        [[ -n $part && $part != . && $part != .. ]] || return 1
        current=$current/$part
        [[ ! -L $current ]] || return 1
    done
}

mvc24_build_hash_file() {
    (( $# == 1 )) || return 1
    sha256sum -- "$1" | awk '{print $1}'
}

[[ -f $mvc24_manifest && ! -L $mvc24_manifest ]] || mvc24_build_die 'runtime manifest missing or symlinked'
mvc24_manifest_sha=$(mvc24_build_hash_file "$mvc24_manifest") || exit 1
mvc24_builder_sha=$(mvc24_build_hash_file "$mvc24_build_script") || exit 1

# Parsed manifest state. Every declared input is validated even when its role is
# deferred to a later monolith stage; this makes drift visible immediately.
declare -a MVC24_BUILD_MODULE_PATHS=()
declare -a MVC24_BUILD_MODULE_SHAS=()
declare -a MVC24_BUILD_MODULE_ORDERS=()
declare -A MVC24_BUILD_KEYS=()
declare -A MVC24_BUILD_PATHS=()
declare -A MVC24_BUILD_ASSET_PATH=()
declare -A MVC24_BUILD_ASSET_SHA=()
declare -A MVC24_BUILD_INTEGRATE_PATH=()
declare -A MVC24_BUILD_INTEGRATE_SHA=()
declare -A MVC24_BUILD_RECOVERY_PATH=()
declare -A MVC24_BUILD_RECOVERY_SHA=()
declare -A MVC24_BUILD_KIND_COUNT=()
mvc24_record_count=0
mvc24_module_count=0

while IFS='|' read -r kind key expected_sha rel detail extra; do
    [[ -z ${extra:-} ]] || mvc24_build_die "manifest line has too many fields: $kind|$key"
    [[ -n ${kind:-} ]] || continue
    [[ $kind == \#* ]] && continue
    [[ -n ${key:-} && -n ${expected_sha:-} && -n ${rel:-} && -n ${detail:-} ]] || \
        mvc24_build_die "manifest line is incomplete: $kind|${key:-}"
    case $kind in
        MODULE|ASSET|INTEGRATE|EXTERNAL_RECOVERY|EXCLUDE) ;;
        *) mvc24_build_die "unexpected manifest kind: $kind" ;;
    esac
    [[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || mvc24_build_die "invalid SHA-256 for $kind|$key"
    mvc24_build_safe_relpath "$rel" || mvc24_build_die "unsafe or symlinked manifest path: $rel"
    abs=$mvc24_project_root/$rel
    [[ -f $abs && ! -L $abs ]] || mvc24_build_die "declared input is not a regular non-symlink file: $rel"
    actual_sha=$(mvc24_build_hash_file "$abs") || exit 1
    [[ $actual_sha == "$expected_sha" ]] || mvc24_build_die "SHA-256 mismatch: $rel"
    record_key=$kind:$key
    if [[ $kind != EXCLUDE ]]; then
        [[ -z ${MVC24_BUILD_KEYS[$record_key]+x} ]] || mvc24_build_die "duplicate manifest key: $record_key"
        MVC24_BUILD_KEYS[$record_key]=1
    fi
    [[ -z ${MVC24_BUILD_PATHS[$rel]+x} ]] || mvc24_build_die "duplicate manifest path: $rel"
    MVC24_BUILD_PATHS[$rel]=1
    MVC24_BUILD_KIND_COUNT[$kind]=$(( ${MVC24_BUILD_KIND_COUNT[$kind]:-0} + 1 ))
    mvc24_record_count=$((mvc24_record_count + 1))

    case $kind in
        MODULE)
            [[ $key =~ ^[0-9]{3}$ ]] || mvc24_build_die "invalid MODULE order: $key"
            expected_order=$(printf '%03d' $((mvc24_module_count + 1)))
            [[ $key == "$expected_order" ]] || mvc24_build_die "MODULE order gap/reorder: expected $expected_order, got $key"
            MVC24_BUILD_MODULE_ORDERS+=("$key")
            MVC24_BUILD_MODULE_SHAS+=("$expected_sha")
            MVC24_BUILD_MODULE_PATHS+=("$rel")
            mvc24_module_count=$((mvc24_module_count + 1))
            ;;
        ASSET)
            case $key in
                gvariant-awk|b4-bootstrap-nft) ;;
                *) mvc24_build_die "unexpected ASSET key: $key" ;;
            esac
            MVC24_BUILD_ASSET_PATH[$key]=$rel
            MVC24_BUILD_ASSET_SHA[$key]=$expected_sha
            ;;
        INTEGRATE)
            case $key in
                release-version|openvpn-source-preview|verify) ;;
                *) mvc24_build_die "unexpected INTEGRATE key: $key" ;;
            esac
            MVC24_BUILD_INTEGRATE_PATH[$key]=$rel
            MVC24_BUILD_INTEGRATE_SHA[$key]=$expected_sha
            ;;
        EXTERNAL_RECOVERY)
            case $key in
                emergency|dual) ;;
                *) mvc24_build_die "unexpected EXTERNAL_RECOVERY key: $key" ;;
            esac
            MVC24_BUILD_RECOVERY_PATH[$key]=$rel
            MVC24_BUILD_RECOVERY_SHA[$key]=$expected_sha
            ;;
    esac
done < "$mvc24_manifest"

[[ $mvc24_record_count == 58 ]] || mvc24_build_die "manifest record count changed: $mvc24_record_count"
[[ $mvc24_module_count == 49 ]] || mvc24_build_die "MODULE count changed: $mvc24_module_count"
[[ ${MVC24_BUILD_KIND_COUNT[ASSET]:-0} == 2 &&
   ${MVC24_BUILD_KIND_COUNT[INTEGRATE]:-0} == 3 &&
   ${MVC24_BUILD_KIND_COUNT[EXTERNAL_RECOVERY]:-0} == 2 &&
   ${MVC24_BUILD_KIND_COUNT[EXCLUDE]:-0} == 2 ]] || mvc24_build_die 'manifest role counts changed'
[[ ${MVC24_BUILD_ASSET_PATH[gvariant-awk]:-} == source/lib/combined-gvariant-settings-to-json.awk ]] || \
    mvc24_build_die 'gvariant asset path changed'
[[ ${MVC24_BUILD_ASSET_PATH[b4-bootstrap-nft]:-} == source/nftables/mvc-preclone-quarantine-offline.nft ]] || \
    mvc24_build_die 'B4 nft asset path changed'
[[ ${MVC24_BUILD_INTEGRATE_PATH[release-version]:-} == source/release-version ]] || \
    mvc24_build_die 'release-version integration path changed'
mvc24_release_version_file=$mvc24_project_root/${MVC24_BUILD_INTEGRATE_PATH[release-version]}
mapfile -t mvc24_release_version_lines < "$mvc24_release_version_file" || \
    mvc24_build_die 'cannot read release-version'
[[ ${#mvc24_release_version_lines[@]} == 1 ]] || \
    mvc24_build_die 'release-version must contain exactly one line'
MVC24_BUILD_VERSION=${mvc24_release_version_lines[0]}
unset mvc24_release_version_lines
[[ $MVC24_BUILD_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    mvc24_build_die 'release-version must be semantic version X.Y.Z'
MVC24_BUILD_VERSION_ID=${MVC24_BUILD_VERSION//./}
MVC24_BUILD_CHECKPOINT="MVC_V${MVC24_BUILD_VERSION_ID}_RELEASE"
MVC24_BUILD_AUTHORITY="audited-dispatch-mvc-v${MVC24_BUILD_VERSION_ID}-release"
readonly MVC24_BUILD_VERSION MVC24_BUILD_VERSION_ID MVC24_BUILD_CHECKPOINT MVC24_BUILD_AUTHORITY
[[ ${MVC24_BUILD_INTEGRATE_PATH[openvpn-source-preview]:-} == source/tools/check-mvc-live-saved-ovpn-readonly.sh ]] || \
    mvc24_build_die 'OpenVPN preview integration path changed'
[[ ${MVC24_BUILD_INTEGRATE_PATH[verify]:-} == source/tools/verify-mvc-state-readonly.sh ]] || \
    mvc24_build_die 'read-only verifier integration path changed'
[[ ${MVC24_BUILD_RECOVERY_PATH[emergency]:-} == source/tools/recover-mvc-host-guard-local.sh ]] || \
    mvc24_build_die 'emergency recovery source path changed'
[[ ${MVC24_BUILD_RECOVERY_PATH[dual]:-} == source/tools/recover-mvc-dual-local.sh ]] || \
    mvc24_build_die 'dual recovery source path changed'

mvc24_tmp=$mvc24_output_dir/.${mvc24_output_name}.tmp.$$
trap 'rm -f -- "$mvc24_tmp"' EXIT
: > "$mvc24_tmp"
chmod 600 "$mvc24_tmp"

mvc24_emit() { printf '%s\n' "$*" >> "$mvc24_tmp"; }

mvc24_emit '#!/usr/bin/env bash'
mvc24_emit "# Multi VPN Controller $MVC24_BUILD_VERSION"
mvc24_emit '# GENERATED RELEASE ARTIFACT — DO NOT EDIT DIRECTLY'
mvc24_emit '# Changes belong in the modular source tree and must be rebuilt.'
mvc24_emit '#'
mvc24_emit "# Multi VPN Controller $MVC24_BUILD_VERSION operational release."
mvc24_emit '# Generated-runtime equivalence is proven; lifecycle delegates to the audited public dispatcher.'
mvc24_emit "# Source checkpoint: $MVC24_BUILD_CHECKPOINT"
mvc24_emit "# Runtime manifest SHA-256: $mvc24_manifest_sha"
mvc24_emit "# Builder SHA-256: $mvc24_builder_sha"
mvc24_emit "# Ordered runtime modules: $mvc24_module_count"
mvc24_emit '# Embedded resources: 2'
mvc24_emit ''
mvc24_emit 'set -euo pipefail'
mvc24_emit 'umask 077'
mvc24_emit 'export LC_ALL=C'
mvc24_emit "readonly MVC24_RELEASE_VERSION='$MVC24_BUILD_VERSION'"
mvc24_emit "readonly MVC24_RELEASE_CHECKPOINT='$MVC24_BUILD_CHECKPOINT'"
mvc24_emit "readonly MVC24_RELEASE_AUTHORITY='$MVC24_BUILD_AUTHORITY'"
mvc24_emit "readonly MVC24_RELEASE_VERSION_SHA256='${MVC24_BUILD_INTEGRATE_SHA[release-version]}'"
mvc24_emit "readonly MVC24_MONOLITH_MANIFEST_SHA256='$mvc24_manifest_sha'"
mvc24_emit "readonly MVC24_MONOLITH_BUILDER_SHA256='$mvc24_builder_sha'"
mvc24_emit "readonly MVC24_MONOLITH_VERIFY_SOURCE_SHA256='${MVC24_BUILD_INTEGRATE_SHA[verify]}'"
mvc24_emit "readonly MVC24_MONOLITH_EMERGENCY_RECOVERY='/root/mvc-emergency-rollback'"
mvc24_emit "readonly MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256='${MVC24_BUILD_RECOVERY_SHA[emergency]}'"
mvc24_emit "readonly MVC24_MONOLITH_DUAL_RECOVERY='/root/mvc-dual-recovery'"
mvc24_emit "readonly MVC24_MONOLITH_DUAL_RECOVERY_SHA256='${MVC24_BUILD_RECOVERY_SHA[dual]}'"
mvc24_emit ''
mvc24_emit '# ============================================================================'
mvc24_emit '# Embedded deterministic runtime resources'
mvc24_emit '# ============================================================================'

mvc24_build_emit_resource_function() {
    (( $# == 3 )) || return 1
    local name=$1 rel=$2 sha=$3 fn delim
    case $name in
        gvariant-awk) fn=mvc24mon_emit_gvariant_awk ;;
        b4-bootstrap-nft) fn=mvc24mon_emit_b4_bootstrap_nft ;;
        *) return 1 ;;
    esac
    delim="__MVC24_RESOURCE_${sha}__"
    ! grep -Fqx -- "$delim" "$mvc24_project_root/$rel" || mvc24_build_die "resource delimiter collision: $rel"
    mvc24_emit "# Resource: $rel"
    mvc24_emit "# SHA-256: $sha"
    mvc24_emit "$fn() {"
    mvc24_emit "    cat <<'$delim'"
    [[ $(tail -c 1 -- "$mvc24_project_root/$rel" | od -An -t x1 | tr -d ' \n') == 0a ]] || \
        mvc24_build_die "embedded text resource is not newline-terminated: $rel"
    cat -- "$mvc24_project_root/$rel" >> "$mvc24_tmp"
    printf '%s\n' "$delim" >> "$mvc24_tmp"
    mvc24_emit '}'
    mvc24_emit ''
}

mvc24_build_emit_resource_function gvariant-awk \
    "${MVC24_BUILD_ASSET_PATH[gvariant-awk]}" "${MVC24_BUILD_ASSET_SHA[gvariant-awk]}"
mvc24_build_emit_resource_function b4-bootstrap-nft \
    "${MVC24_BUILD_ASSET_PATH[b4-bootstrap-nft]}" "${MVC24_BUILD_ASSET_SHA[b4-bootstrap-nft]}"

cat >> "$mvc24_tmp" <<'BASH_RESOURCE_HELPERS'
mvc24mon_resource_sha256() {
    (( $# == 1 )) || return 1
    case $1 in
        gvariant-awk) printf '%s\n' '__GVARIANT_SHA__' ;;
        b4-bootstrap-nft) printf '%s\n' '__B4_SHA__' ;;
        *) return 1 ;;
    esac
}

mvc24mon_materialize_resource() {
    (( $# == 2 )) || return 1
    local name=$1 dest=$2 dir base tmp expected actual
    [[ $dest == /* && $dest != / && $dest != */ && $dest != *$'\n'* &&
       $dest != *$'\r'* && $dest != *$'\t'* ]] || return 1
    dir=${dest%/*}
    base=${dest##*/}
    [[ -d $dir && ! -L $dir && -n $base ]] || return 1
    expected=$(mvc24mon_resource_sha256 "$name") || return 1
    tmp=$dir/.${base}.mvc24-resource.$$
    rm -f -- "$tmp"
    case $name in
        gvariant-awk) (umask 077; mvc24mon_emit_gvariant_awk > "$tmp") || { rm -f -- "$tmp"; return 1; } ;;
        b4-bootstrap-nft) (umask 077; mvc24mon_emit_b4_bootstrap_nft > "$tmp") || { rm -f -- "$tmp"; return 1; } ;;
        *) return 1 ;;
    esac
    chmod 600 -- "$tmp" || { rm -f -- "$tmp"; return 1; }
    actual=$(sha256sum -- "$tmp" | awk '{print $1}') || { rm -f -- "$tmp"; return 1; }
    [[ $actual == "$expected" ]] || { rm -f -- "$tmp"; return 1; }
    mv -T -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
    [[ -f $dest && ! -L $dest && $(stat -c %a -- "$dest") == 600 ]] || return 1
}

mvc24mon_bootstrap_dependencies() {
    (( $# == 0 )) || return 1
    local bin
    for bin in awk cat chmod mktemp mv rm rmdir sha256sum stat; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            printf 'Multi VPN Controller: missing bootstrap prerequisite: %s\n' "$bin" >&2
            return 1
        fi
    done
}

MVC24_MONOLITH_ASSET_DIR=''

mvc24mon_runtime_assets_cleanup() {
    (( $# == 0 )) || return 1
    local dir=${MVC24_MONOLITH_ASSET_DIR:-}
    [[ -n $dir ]] || return 0
    if [[ -d $dir && ! -L $dir && $dir == /dev/shm/mvc-monolith-assets.* ]]; then
        rm -f -- "$dir/gvariant-settings-to-json.awk" "$dir/mvc-preclone-quarantine-offline.nft" 2>/dev/null || :
        rmdir -- "$dir" 2>/dev/null || :
    fi
    MVC24_MONOLITH_ASSET_DIR=''
    export MVC24_MONOLITH_ASSET_DIR
}

mvc24mon_runtime_assets_prepare() {
    (( $# == 0 )) || return 1
    local dir
    mvc24mon_bootstrap_dependencies || return 1
    if [[ -n ${MVC24_MONOLITH_ASSET_DIR:-} ]]; then
        dir=$MVC24_MONOLITH_ASSET_DIR
        [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == "$EUID:700:2" ]] || return 1
        [[ -f $dir/gvariant-settings-to-json.awk && ! -L $dir/gvariant-settings-to-json.awk &&
           -f $dir/mvc-preclone-quarantine-offline.nft && ! -L $dir/mvc-preclone-quarantine-offline.nft ]] || return 1
        return 0
    fi
    [[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm 2>/dev/null) == tmpfs ]] || return 1
    dir=$(umask 077; mktemp -d /dev/shm/mvc-monolith-assets.XXXXXXXX) || return 1
    chmod 700 -- "$dir" || { rmdir -- "$dir" 2>/dev/null || :; return 1; }
    if ! mvc24mon_materialize_resource gvariant-awk "$dir/gvariant-settings-to-json.awk" ||
       ! mvc24mon_materialize_resource b4-bootstrap-nft "$dir/mvc-preclone-quarantine-offline.nft"; then
        rm -f -- "$dir/gvariant-settings-to-json.awk" "$dir/mvc-preclone-quarantine-offline.nft" 2>/dev/null || :
        rmdir -- "$dir" 2>/dev/null || :
        return 1
    fi
    MVC24_MONOLITH_ASSET_DIR=$dir
    export MVC24_MONOLITH_ASSET_DIR
}

mvc24mon_runtime_asset_dir() {
    (( $# == 0 )) || return 1
    local dir=${MVC24_MONOLITH_ASSET_DIR:-}
    [[ -n $dir && -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir" 2>/dev/null) == "$EUID:700:2" ]] || return 1
    printf '%s\n' "$dir"
}

mvc24mon_runtime_asset_path() {
    (( $# == 1 )) || return 1
    local dir path expected actual
    dir=$(mvc24mon_runtime_asset_dir) || return 1
    case $1 in
        gvariant-awk) path=$dir/gvariant-settings-to-json.awk ;;
        b4-bootstrap-nft) path=$dir/mvc-preclone-quarantine-offline.nft ;;
        *) return 1 ;;
    esac
    expected=$(mvc24mon_resource_sha256 "$1") || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == "$EUID:600:1" ]] || return 1
    actual=$(sha256sum -- "$path" | awk '{print $1}') || return 1
    [[ $actual == "$expected" ]] || return 1
    printf '%s\n' "$path"
}
BASH_RESOURCE_HELPERS
# Replace deterministic placeholders without depending on source path ordering.
sed -i \
    -e "s/__GVARIANT_SHA__/${MVC24_BUILD_ASSET_SHA[gvariant-awk]}/" \
    -e "s/__B4_SHA__/${MVC24_BUILD_ASSET_SHA[b4-bootstrap-nft]}/" \
    "$mvc24_tmp"
mvc24_emit ''

mvc24_build_emit_module() {
    (( $# == 3 )) || return 1
    local order=$1 sha=$2 rel=$3 abs first line replacement_count=0 expected_replacements=0
    abs=$mvc24_project_root/$rel
    mvc24_emit '# ============================================================================'
    mvc24_emit "# >>> BEGIN MODULE $order: $rel"
    mvc24_emit "# >>> SOURCE SHA-256: $sha"
    mvc24_emit '# ============================================================================'
    IFS= read -r first < "$abs" || first=''
    local start_line=1
    [[ $first == '#!'* ]] && start_line=2
    case $rel in
        source/lib/combined-dbus-gdbus-settings.sh|\
        source/lib/combined-operational-host-guard-transaction.sh|\
        source/lib/combined-operational-c3-held-lifecycle.sh|\
        source/lib/combined-operational-wireguard-protected.sh)
            expected_replacements=1 ;;
    esac
    while IFS= read -r line || [[ -n $line ]]; do
        case "$rel|$line" in
            'source/lib/combined-dbus-gdbus-settings.sh|    decoder=${BASH_SOURCE[0]%/*}/combined-gvariant-settings-to-json.awk')
                line='    decoder=$(mvc24mon_runtime_asset_path gvariant-awk) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-host-guard-transaction.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/mvc-preclone-quarantine-offline.nft || return 1')
                line='    base=$(mvc24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-c3-held-lifecycle.sh|    policy=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/mvc-preclone-quarantine-offline.nft || return 1')
                line='    policy=$(mvc24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
            'source/lib/combined-operational-wireguard-protected.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd) || return 1')
                line='    base=$(mvc24mon_runtime_asset_dir) || return 1'
                replacement_count=$((replacement_count + 1))
                ;;
        esac
        printf '%s\n' "$line" >> "$mvc24_tmp"
    done < <(tail -n +"$start_line" -- "$abs")
    [[ $replacement_count == "$expected_replacements" ]] || \
        mvc24_build_die "runtime seam replacement count changed for $rel: expected $expected_replacements got $replacement_count"
    printf '\n' >> "$mvc24_tmp"
    mvc24_emit "# <<< END MODULE $order: $rel"
    mvc24_emit ''
}

# Modules 001..048 are the public composition body. The modular composition
# file also provides three runtime glue functions after loading these modules;
# reproduce only those functions, not its source-loop/loader mechanics.
for ((i=0; i<48; i++)); do
    mvc24_build_emit_module "${MVC24_BUILD_MODULE_ORDERS[$i]}" \
        "${MVC24_BUILD_MODULE_SHAS[$i]}" "${MVC24_BUILD_MODULE_PATHS[$i]}"
done

cat >> "$mvc24_tmp" <<'BASH_MONOLITH_GLUE'
# ============================================================================
# >>> BEGIN MONOLITH COMPOSITION GLUE
# Derived from loader-only combined-operational-public-composition.sh.
# This section intentionally contains runtime glue only; no project-tree source.
# ============================================================================
mvc24pub_session_runtime_root() { printf '%s\n' /run/mvc-public-session; }
mvc24pub_wireguard_runtime_root() { printf '%s\n' /run/mvc-wireguard; }

mvc24pub_process_initialize() {
    (( $# == 0 )) || return 1
    mvc24mon_runtime_assets_prepare || return 1
    local reset
    for reset in \
        mvc24gb1_reset mvc24gb2_reset mvc24gb4_reset \
        mvc24ga_reset mvc24ga2_reset mvc24ga3_reset \
        mvc24gc1_reset mvc24gc3_reset mvc24gc4_reset mvc24gc5_reset mvc24gc6_reset \
        mvc24gc7_reset mvc24gc8_reset mvc24gc14_reset mvc24gc9_reset mvc24gc11_reset \
        mvc24gc13_reset mvc24gc15_reset mvc24gc16_reset mvc24gc17_reset mvc24gc18_reset \
        mvc24gc19_reset mvc24gc23t_reset mvc24gco_reset \
        mvc24gd2_reset mvc24gd3_reset mvc24gd4_reset mvc24gwg_reset mvc24gws_reset mvc24pubr_reset mvc24pube_reset \
        mvc24op_candidate_reset mvc24op_preview_reset mvc24op_qg_reset \
        mvc24pub_reset mvc24pubc_reset mvc24pubd_reset; do
        declare -F "$reset" >/dev/null || return 1
        "$reset" || return 1
    done

    # Monolith-native C4 admission does not use a project source root.
    MVC24GC4_SOURCE_ROOT=

    [[ ${MVC24GD4_TEMP_NAME:-} == vpnks-wg &&
       ${MVC24GD4_RUNTIME:-} == /run/mvc-wireguard &&
       ${MVC24PUBC_STAGE:-} == idle && ${MVC24PUBD_STAGE:-} == idle ]]
}
# <<< END MONOLITH COMPOSITION GLUE

BASH_MONOLITH_GLUE

# Module 049 is the public dispatcher and must remain final in modular function order.
mvc24_build_emit_module "${MVC24_BUILD_MODULE_ORDERS[48]}" \
    "${MVC24_BUILD_MODULE_SHAS[48]}" "${MVC24_BUILD_MODULE_PATHS[48]}"

cat >> "$mvc24_tmp" <<'BASH_STAGE3A_SEAMS'
# ============================================================================
# >>> BEGIN C23BN STAGE-3A MONOLITH RUNTIME SEAMS
# Only project-tree-dependent C4 admission seams are overridden here.
# Lifecycle functions remain the ordered modular definitions above.
# ============================================================================
mvc24mon_recovery_file_identity() {
    (( $# == 2 )) || return 1
    local installed=$1 expected=$2 actual
    [[ $installed == /* && $expected =~ ^[0-9a-f]{64}$ &&
       -f $installed && ! -L $installed && -x $installed ]] || return 1
    [[ $(stat -c '%u:%a:%h' -- "$installed" 2>/dev/null) == '0:700:1' ]] || return 1
    actual=$(sha256sum -- "$installed" 2>/dev/null | awk '{print $1}') || return 1
    [[ $actual == "$expected" ]]
}

mvc24mon_openvpn_source_shape_valid() {
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

mvc24mon_openvpn_source_preview() {
    (( $# == 1 )) || return 1
    local uuid=$1 initial_owner object first_obj='' second_obj='' side path reply
    local unsaved_before unsaved_after preview_uuid scratch result=1
    local old_lock_set=0 old_lock=''
    local re='^o "(/org/freedesktop/NetworkManager/Settings/[0-9]+)"$'
    local bin
    mvc24_valid_uuid "$uuid" || return 1
    [[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm 2>/dev/null) == tmpfs ]] || return 1
    for bin in gdbus awk jq mktemp cmp stat sha256sum; do
        command -v "$bin" >/dev/null 2>&1 || return 1
    done
    mvc24op_session_nm_identity || return 1
    initial_owner=${MVC24OP_SESSION_NM_IDENTITY:-}
    [[ -n $initial_owner ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/mvc24-monolith-saved-host.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch && $(stat -c %a:%h -- "$scratch") == 700:2 ]] || {
        rm -rf -- "$scratch" 2>/dev/null || :
        return 1
    }
    if [[ ${MVC24S_LOCK_HELD+x} ]]; then
        old_lock_set=1
        old_lock=$MVC24S_LOCK_HELD
    fi
    MVC24S_LOCK_HELD=1

    while :; do
        for side in first second; do
            path=$scratch/$side.json
            (umask 077; set -C; : > "$path") || break 2
            [[ -f $path && ! -L $path && $(stat -c %a:%h -- "$path") == 600:1 ]] || break 2
            reply=$(mvc24g_call_readonly org.freedesktop.NetworkManager \
                /org/freedesktop/NetworkManager/Settings \
                org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || break 2
            [[ $reply =~ $re ]] || break 2
            object=${BASH_REMATCH[1]}
            if [[ $side == first ]]; then first_obj=$object; else second_obj=$object; fi
            unsaved_before=$(mvc24g_get_property org.freedesktop.NetworkManager "$object" \
                org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || break 2
            [[ $unsaved_before == 'b false' ]] || break 2
            mvc24gs_capture_settings "$object" "$path" || break 2
            mvc24mon_openvpn_source_shape_valid "$path" "$uuid" || break 2
            unsaved_after=$(mvc24g_get_property org.freedesktop.NetworkManager "$object" \
                org.freedesktop.NetworkManager.Settings.Connection Unsaved b) || break 2
            [[ $unsaved_after == 'b false' ]] || break 2
            mvc24op_session_nm_identity || break 2
            [[ ${MVC24OP_SESSION_NM_IDENTITY:-} == "$initial_owner" ]] || break 2
        done
        [[ -n $first_obj && $first_obj == "$second_obj" ]] || break
        cmp -s -- "$scratch/first.json" "$scratch/second.json" || break
        mvc24op_session_nm_identity || break
        [[ ${MVC24OP_SESSION_NM_IDENTITY:-} == "$initial_owner" ]] || break
        path=$scratch/preview.json
        (umask 077; set -C; : > "$path") || break
        [[ -f $path && ! -L $path && $(stat -c %a:%h -- "$path") == 600:1 ]] || break
        preview_uuid=$(cat /proc/sys/kernel/random/uuid) || break
        mvc24op_preview_build "$scratch/first.json" "$preview_uuid" "$path" || break
        result=0
        break
    done

    if (( old_lock_set == 1 )); then MVC24S_LOCK_HELD=$old_lock; else unset MVC24S_LOCK_HELD; fi
    rm -f -- "$scratch/first.json" "$scratch/second.json" "$scratch/preview.json" 2>/dev/null || result=1
    rmdir -- "$scratch" 2>/dev/null || result=1
    (( result == 0 ))
}

# Monolith-specific C4 replacements. They retain the original fail-closed C4
# call contract while removing sibling source/tool dependencies.
mvc24gc4_recovery_installed() {
    (( $# == 0 )) || return 1
    mvc24mon_recovery_file_identity "$MVC24_MONOLITH_EMERGENCY_RECOVERY" \
        "$MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256"
}

mvc24gc4_source_preview() {
    (( $# == 1 )) || return 1
    mvc24mon_openvpn_source_preview "$1"
}
# <<< END C23BN STAGE-3A MONOLITH RUNTIME SEAMS

BASH_STAGE3A_SEAMS

# Integrate only the explicitly marked function block from the audited read-only
# verifier. The standalone executable shell and top-level main call are not
# copied into the monolith.
mvc24_build_emit_verify_functions() {
    (( $# == 0 )) || return 1
    local rel=${MVC24_BUILD_INTEGRATE_PATH[verify]} abs begin end begin_count end_count
    abs=$mvc24_project_root/$rel
    begin='# MVC24_MONOLITH_VERIFY_FUNCTIONS_BEGIN'
    end='# MVC24_MONOLITH_VERIFY_FUNCTIONS_END'
    begin_count=$(grep -Fxc -- "$begin" "$abs") || :
    end_count=$(grep -Fxc -- "$end" "$abs") || :
    [[ $begin_count == 1 && $end_count == 1 ]] || \
        mvc24_build_die 'read-only verifier integration markers changed'
    mvc24_emit '# ============================================================================'
    mvc24_emit '# >>> BEGIN C23BN STAGE-3B READ-ONLY VERIFIER'
    mvc24_emit "# >>> SOURCE: $rel"
    mvc24_emit "# >>> SOURCE SHA-256: ${MVC24_BUILD_INTEGRATE_SHA[verify]}"
    awk -v begin="$begin" -v end="$end" '
        $0 == begin { inside=1; seen_begin++; next }
        $0 == end { inside=0; seen_end++; next }
        inside { print }
        END { if (seen_begin != 1 || seen_end != 1 || inside) exit 7 }
    ' "$abs" >> "$mvc24_tmp" || mvc24_build_die 'failed to extract read-only verifier integration block'
    mvc24_emit '# <<< END C23BN STAGE-3B READ-ONLY VERIFIER'
    mvc24_emit ''
}
mvc24_build_emit_verify_functions

cat >> "$mvc24_tmp" <<'BASH_STAGE5_WRAPPER'

# ============================================================================
# Multi VPN Controller release wrapper — audited dispatcher
# ============================================================================
# Monolith-specific verifier status callback. `verify` observes this artifact's
# own read-only status implementation, never a sibling controller.
mvc24v_controller_status() {
    (( $# == 1 )) || return 2
    mvc24pub_status_readonly
}

mvc24v_usage() {
    cat <<'USAGE'
Usage: sudo mvc verify [--no-internet-check]

Print a read-only host-state report suitable after CONNECT or DISCONNECT.
The observed-shape classification is diagnostic only and grants no lifecycle,
cleanup, disconnect, or recovery authority.
USAGE
}

mvc24mon_require_stage5_functions() {
    local fn
    for fn in \
        mvc24_parse_command mvc24e_dispatch mvc24pub_process_initialize \
        mvc24pub_session_runtime_root mvc24pub_wireguard_runtime_root \
        mvc24pub_list_readonly mvc24pub_status_readonly \
        mvc24pubc_connect_once mvc24pubc_connect_openvpn_once \
        mvc24pubc_connect_wireguard_protected_once mvc24pubc_connect_wireguard_split_once \
        mvc24pubd_disconnect_once mvc24gco_start_once mvc24gco_stop_once \
        mvc24gco_complete_once mvc24gd4_start_once mvc24gd4_stop_once \
        mvc24gwg_start_once mvc24gwg_stop_once mvc24gws_stop_once \
        mvc24mon_openvpn_source_preview mvc24mon_recovery_file_identity \
        mvc24mon_runtime_asset_path mvc24v_main mvc24v_controller_status mvc24v_usage; do
        declare -F -- "$fn" >/dev/null || return 1
    done
}

mvc24mon_stage5_help() {
    printf 'Multi VPN Controller %s\n\n' "$MVC24_RELEASE_VERSION"
    cat <<'HELP'
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
HELP
    printf '\nThis is the deterministic MVC v%s release artifact. Validation evidence is\n' "$MVC24_RELEASE_VERSION"
    cat <<'HELP'
hash-specific; verify the exact artifact identity used for deployment.

Development/internal diagnostics retained for regression testing:
  --monolith-build-info
  --monolith-resource-selftest DIRECTORY
HELP
}

mvc24mon_stage5_build_info() {
    printf 'version=%s\n' "$MVC24_RELEASE_VERSION"
    printf 'checkpoint=%s\n' "$MVC24_RELEASE_CHECKPOINT"
    printf 'authority=%s\n' "$MVC24_RELEASE_AUTHORITY"
    printf 'release_version_sha256=%s\n' "$MVC24_RELEASE_VERSION_SHA256"
    printf 'manifest_sha256=%s\n' "$MVC24_MONOLITH_MANIFEST_SHA256"
    printf 'builder_sha256=%s\n' "$MVC24_MONOLITH_BUILDER_SHA256"
    printf 'verify_source_sha256=%s\n' "$MVC24_MONOLITH_VERIFY_SOURCE_SHA256"
    printf 'emergency_recovery=%s\n' "$MVC24_MONOLITH_EMERGENCY_RECOVERY"
    printf 'emergency_recovery_sha256=%s\n' "$MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256"
    printf 'dual_recovery=%s\n' "$MVC24_MONOLITH_DUAL_RECOVERY"
    printf 'dual_recovery_sha256=%s\n' "$MVC24_MONOLITH_DUAL_RECOVERY_SHA256"
}

mvc24mon_stage5_version_verbose() {
    printf 'Multi VPN Controller %s\n' "$MVC24_RELEASE_VERSION"
    mvc24mon_stage5_build_info
}

mvc24mon_stage5_resource_selftest() {
    (( $# == 1 )) || return 2
    local dir=$1 awk_out nft_out
    [[ $dir == /* && -d $dir && ! -L $dir ]] || return 2
    awk_out=$dir/gvariant-settings-to-json.awk
    nft_out=$dir/preclone-quarantine.nft
    mvc24mon_materialize_resource gvariant-awk "$awk_out" || return 1
    mvc24mon_materialize_resource b4-bootstrap-nft "$nft_out" || return 1
    printf 'gvariant-awk=%s\n' "$(sha256sum -- "$awk_out" | awk '{print $1}')"
    printf 'b4-bootstrap-nft=%s\n' "$(sha256sum -- "$nft_out" | awk '{print $1}')"
}

mvc24mon_stage5_main() {
    mvc24mon_require_stage5_functions || {
        printf 'Multi VPN Controller v%s monolith is incomplete.\n' "$MVC24_RELEASE_VERSION" >&2
        return 70
    }
    case ${1:-} in
        version)
            case $# in
                1) mvc24e_dispatch version ;;
                2) [[ $2 == --verbose ]] || return 2; mvc24mon_stage5_version_verbose ;;
                *) return 2 ;;
            esac
            ;;
        --version)
            (( $# == 1 )) || return 2
            mvc24e_dispatch version
            ;;
        help|-h|--help)
            (( $# == 1 )) || return 2
            mvc24mon_stage5_help
            ;;
        verify)
            if (( $# == 1 )); then
                mvc24v_main
            elif (( $# == 2 )); then
                case $2 in
                    --no-internet-check|-h|--help) mvc24v_main "$2" ;;
                    *) mvc24v_usage >&2; return 2 ;;
                esac
            else
                mvc24v_usage >&2
                return 2
            fi
            ;;
        --monolith-build-info)
            (( $# == 1 )) || return 2
            mvc24mon_stage5_build_info
            ;;
        --monolith-resource-selftest)
            (( $# == 2 )) || return 2
            mvc24mon_stage5_resource_selftest "$2"
            ;;
        preflight|list|status|connect|disconnect)
            mvc24e_dispatch "$@"
            ;;
        '')
            mvc24mon_stage5_help >&2
            return 2
            ;;
        *)
            printf 'Multi VPN Controller: unknown command `%s`; use --help.\n' "$1" >&2
            return 2
            ;;
    esac
}

trap 'mvc24mon_runtime_assets_cleanup' EXIT
mvc24mon_stage5_main "$@"
BASH_STAGE5_WRAPPER

bash -n "$mvc24_tmp" || mvc24_build_die 'generated artifact failed bash -n'
chmod 755 "$mvc24_tmp"
mv -T -- "$mvc24_tmp" "$mvc24_output"
trap - EXIT
printf '%s  %s\n' "$(mvc24_build_hash_file "$mvc24_output")" "$mvc24_output"
