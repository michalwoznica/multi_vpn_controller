#!/usr/bin/env bash
# C23BN Stage 4 — structural/runtime equivalence proof for generated dist/ubs-vpn.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
MONOLITH=$ROOT/dist/ubs-vpn
BUILDER=$ROOT/source/build/build-v240-monolith.sh
MANIFEST=$ROOT/source/build/monolith-runtime.manifest
PASS=0
FAIL=0
ok(){ printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

# The checked-in artifact must still be exactly reproducible before any
# equivalence claim is made about it.
"$BUILDER" "$TMP/rebuilt-ubs-vpn" >/dev/null
if cmp -s -- "$MONOLITH" "$TMP/rebuilt-ubs-vpn"; then
    ok 'checked-in monolith is byte-identical to a fresh deterministic build'
else
    bad 'checked-in monolith is byte-identical to a fresh deterministic build'
fi

# Independently reproduce the builder's four approved path-seam rewrites and
# compare every generated module payload with its audited modular source.
module_total=0
module_equal=0
while IFS='|' read -r kind order sha rel detail; do
    [[ $kind == MODULE ]] || continue
    module_total=$((module_total+1))
    src=$ROOT/$rel
    raw=$TMP/module-$order.raw
    payload=$TMP/module-$order.payload
    expected=$TMP/module-$order.expected
    begin="# >>> BEGIN MODULE $order: $rel"
    end="# <<< END MODULE $order: $rel"

    if ! grep -Fqx -- "# >>> SOURCE SHA-256: $sha" "$MONOLITH"; then
        bad "module $order carries the manifest source SHA marker"
        continue
    fi
    awk -v begin="$begin" -v end="$end" '
        $0 == begin { inside=1; seen_begin++; next }
        $0 == end { inside=0; seen_end++; exit }
        inside { print }
        END { if (seen_begin != 1 || seen_end != 1 || inside) exit 7 }
    ' "$MONOLITH" > "$raw" || { bad "module $order section is uniquely extractable"; continue; }
    # Drop the generated SOURCE-SHA/separator header and the one builder-added
    # blank line after the copied source payload.
    tail -n +3 -- "$raw" | head -n -1 > "$payload"

    : > "$expected"
    first=$(head -n 1 -- "$src")
    start_line=1
    [[ $first == '#!'* ]] && start_line=2
    while IFS= read -r line || [[ -n $line ]]; do
        case "$rel|$line" in
            'source/lib/combined-dbus-gdbus-settings.sh|    decoder=${BASH_SOURCE[0]%/*}/combined-gvariant-settings-to-json.awk')
                line='    decoder=$(ubs24mon_runtime_asset_path gvariant-awk) || return 1'
                ;;
            'source/lib/combined-operational-host-guard-transaction.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1')
                line='    base=$(ubs24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                ;;
            'source/lib/combined-operational-c3-held-lifecycle.sh|    policy=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd)/vpn-v240-preclone-quarantine-offline.nft || return 1')
                line='    policy=$(ubs24mon_runtime_asset_path b4-bootstrap-nft) || return 1'
                ;;
            'source/lib/combined-operational-wireguard-protected-v240.sh|    base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../nftables" && pwd) || return 1')
                line='    base=$(ubs24mon_runtime_asset_dir) || return 1'
                ;;
        esac
        printf '%s\n' "$line" >> "$expected"
    done < <(tail -n +"$start_line" -- "$src")

    if cmp -s -- "$expected" "$payload"; then
        module_equal=$((module_equal+1))
    else
        bad "module $order payload matches source plus only approved seam rewrite"
    fi
done < "$MANIFEST"
if [[ $module_total == 49 && $module_equal == 49 ]]; then
    ok 'all 49 generated module payloads equal modular sources plus only four approved seam rewrites'
else
    bad 'all 49 generated module payloads equal modular sources plus only four approved seam rewrites'
fi

# The generated artifact must contain no executable project-tree source calls.
if ! grep -Eq '^[[:space:]]*source[[:space:]]+' "$MONOLITH" &&
   ! grep -Eq '^[[:space:]]*\.[[:space:]]+["$/{A-Za-z_]' "$MONOLITH"; then
    ok 'generated artifact has no runtime source/dot-source dependency'
else
    bad 'generated artifact has no runtime source/dot-source dependency'
fi

# Dynamic final-function parity: compare every function defined by the 49
# runtime modules after final modular composition vs the generated artifact.
# Six functions are intentionally different: four embedded-resource seam
# rewrites plus the two monolith-native C4 project-tree replacements.
FUNCTIONS=$TMP/functions
COMPARE=$TMP/functions-compare
: > "$FUNCTIONS"
while IFS='|' read -r kind order sha rel detail; do
    [[ $kind == MODULE ]] || continue
    { grep -E '^(function[[:space:]]+)?ubs24[A-Za-z0-9_]+[[:space:]]*\(\)[[:space:]]*\{' "$ROOT/$rel" || true; } |
        sed -E 's/^(function[[:space:]]+)?(ubs24[A-Za-z0-9_]+)[[:space:]]*\(\).*/\2/' >> "$FUNCTIONS"
done < "$MANIFEST"
sort -u "$FUNCTIONS" -o "$FUNCTIONS"
grep -Ev '^(ubs24gs_capture_settings|ubs24gb2_batch_valid|ubs24gc3_execute_once|ubs24gwg_policy_file|ubs24gc4_recovery_installed|ubs24gc4_source_preview)$' "$FUNCTIONS" > "$COMPARE"
mkdir -m 700 "$TMP/modular-functions" "$TMP/generated-functions"
ROOT="$ROOT" LIST="$COMPARE" OUT="$TMP/modular-functions" bash -c '
    set -e
    export UBS24E_CODE_ROOT="$ROOT/source"
    source "$ROOT/source/lib/combined-operational-public-v240-composition.sh"
    source "$ROOT/source/lib/combined-controller-entry.sh"
    while IFS= read -r fn; do
        declare -F "$fn" >/dev/null || exit 3
        declare -f "$fn" > "$OUT/$fn"
    done < "$LIST"
' || bad 'modular final function set is loadable'
ROOT="$ROOT" LIST="$COMPARE" OUT="$TMP/generated-functions" bash -c '
    set -e
    set -- --help
    source "$ROOT/dist/ubs-vpn" >/dev/null
    while IFS= read -r fn; do
        declare -F "$fn" >/dev/null || exit 3
        declare -f "$fn" > "$OUT/$fn"
    done < "$LIST"
' || bad 'generated final function set is loadable'
function_total=$(wc -l < "$COMPARE")
function_equal=0
while IFS= read -r fn; do
    cmp -s -- "$TMP/modular-functions/$fn" "$TMP/generated-functions/$fn" && function_equal=$((function_equal+1))
done < "$COMPARE"
if [[ $function_total == 753 && $function_equal == 753 ]]; then
    ok '753 production functions are byte-equivalent after final Bash definition resolution'
else
    bad "final function parity expected 753/753, observed $function_equal/$function_total"
fi

# Explicitly verify the 18 intentional override chains terminate at the audited
# final module owner. Module-payload parity above then proves the generated
# artifact has that same final definition owner/content.
cat > "$TMP/override-owners" <<'OWNERS'
ubs24ga2_capture_readback|combined-operational-ovpn-guarded-prepare.sh
ubs24ga2_guard_witness|combined-operational-ovpn-guarded-prepare.sh
ubs24ga2_source_witness|combined-operational-ovpn-guarded-prepare.sh
ubs24ga_live_guard_witness|combined-operational-ovpn-guarded-prepare.sh
ubs24ga_nm_source_witness|combined-operational-ovpn-guarded-prepare.sh
ubs24ga_postclone_identity_hook|combined-operational-public-v240-connect.sh
ubs24ga_preclone_intent_hook|combined-operational-public-v240-connect.sh
ubs24gc13_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc17_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc19_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc23t_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc3_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc5_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc7_admission_witness|combined-operational-openvpn-composition.sh
ubs24gc9_admission_witness|combined-operational-openvpn-composition.sh
ubs24gco_enabled|combined-operational-public-v240-disconnect.sh
ubs24gd4_authority_witness|combined-operational-public-v240-disconnect.sh
ubs24gd4_post_openvpn_cleanup_witness|combined-operational-public-v240-disconnect.sh
OWNERS
owner_ok=0
owner_total=0
while IFS='|' read -r fn expected_owner; do
    owner_total=$((owner_total+1))
    last_owner=
    while IFS='|' read -r kind order sha rel detail; do
        [[ $kind == MODULE ]] || continue
        if grep -Eq "^${fn}[[:space:]]*\\(\\)[[:space:]]*\\{" "$ROOT/$rel"; then
            last_owner=${rel##*/}
        fi
    done < "$MANIFEST"
    [[ $last_owner == "$expected_owner" ]] && owner_ok=$((owner_ok+1))
done < "$TMP/override-owners"
if [[ $owner_total == 18 && $owner_ok == 18 ]]; then
    ok 'all 18 intentional override chains resolve to the audited final owner'
else
    bad "intentional override owners expected 18/18, observed $owner_ok/$owner_total"
fi

# Critical lifecycle/public entrypoints must be among the exact-parity set.
critical_ok=1
for fn in \
    ubs24e_dispatch ubs24pubc_connect_once ubs24pubc_connect_openvpn_once \
    ubs24pubc_connect_wireguard_protected_once ubs24pubc_connect_wireguard_split_once \
    ubs24pubd_disconnect_once ubs24gco_start_once ubs24gco_stop_once ubs24gco_complete_once \
    ubs24gd4_start_once ubs24gd4_stop_once ubs24gwg_start_once ubs24gwg_stop_once \
    ubs24gws_start_once ubs24gws_stop_once; do
    [[ -f $TMP/generated-functions/$fn && -f $TMP/modular-functions/$fn ]] || critical_ok=0
done
(( critical_ok == 1 )) && ok 'critical dispatcher/coordinator/vertical entrypoints are included in exact final-function parity' || bad 'critical dispatcher/coordinator/vertical entrypoints are included in exact final-function parity'

# The artifact must remain usable for non-lifecycle commands when copied alone,
# with no sibling project tree.
mkdir -m 700 "$TMP/isolated" "$TMP/isolated/resources"
cp -- "$MONOLITH" "$TMP/isolated/ubs-vpn"
chmod 755 "$TMP/isolated/ubs-vpn"
if [[ $($TMP/isolated/ubs-vpn version) == 'UBS VPN Controller 2.4.1' ]] &&
   "$TMP/isolated/ubs-vpn" --help | grep -Fq 'WireGuard-only split' &&
   "$TMP/isolated/ubs-vpn" --monolith-resource-selftest "$TMP/isolated/resources" >/dev/null &&
   cmp -s -- "$TMP/isolated/resources/gvariant-settings-to-json.awk" "$ROOT/source/lib/combined-gvariant-settings-to-json.awk" &&
   cmp -s -- "$TMP/isolated/resources/preclone-quarantine.nft" "$ROOT/source/nftables/vpn-v240-preclone-quarantine-offline.nft"; then
    ok 'isolated monolith needs no sibling lib/tools/nftables tree for metadata/help/embedded resources'
else
    bad 'isolated monolith needs no sibling lib/tools/nftables tree for metadata/help/embedded resources'
fi

printf 'RESULT: C23BN Stage-4 monolith structural equivalence %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
