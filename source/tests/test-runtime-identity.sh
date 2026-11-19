#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

P=0
F=0

pass() {
    printf 'PASS: %s\n' "$1"
    P=$((P + 1))
}

fail() {
    printf 'FAIL: %s\n' "$1"
    F=$((F + 1))
}

rg --no-config -q '/run/mvc-public-session' \
    "$ROOT/source/lib/combined-operational-public-composition.sh" &&
    rg --no-config -q '/run/mvc-wireguard' \
        "$ROOT/source/lib/combined-operational-d4-wireguard-parallel-live.sh" &&
    pass 'production session roots use MVC namespace' ||
    fail 'production session roots use MVC namespace'

rg --no-config -q 'mvc_preclone_quarantine' \
    "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft" &&
    rg --no-config -q 'mvc_preclone_bridge' \
        "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft" &&
    rg --no-config -q 'mvc_preclone_underlay' \
        "$ROOT/source/lib/combined-operational-host-guard-transaction.sh" &&
    pass 'B4 nftables tables use MVC namespace' ||
    fail 'B4 nftables tables use MVC namespace'

installer=$ROOT/source/tools/install-mvc.sh
roots=(controller activation output-transition disconnect completion wireguard public-session)
missing=0
for r in "${roots[@]}"; do
    rg --no-config -Fq "/run/mvc-$r" "$installer" || missing=$((missing + 1))
done
[[ $missing -eq 0 ]] &&
    pass 'installer quiescence guard covers all MVC runtime roots' ||
    fail 'installer quiescence guard covers all MVC runtime roots'

# Build the retired helper prefixes without embedding predecessor product literals
# in this public fixture.
old_lower=$(printf '%s%s%s' 'ub' 's' '24')
old_upper=$(printf '%s%s%s' 'UB' 'S' '24')

# Namespace assertions apply to the current production/build/install shell
# surface, not to retired historical helper files that remain in the source tree.
manifest=$ROOT/source/build/monolith-runtime.manifest

mapfile -t production_shell_relpaths < <(
    awk -F'|' '
        ($1 == "MODULE" ||
         $1 == "INTEGRATE" ||
         $1 == "EXTERNAL_RECOVERY" ||
         $1 == "EXCLUDE") &&
        $4 ~ /\.sh$/ {
            print $4
        }
    ' "$manifest"
)

production_shell_relpaths+=(
    source/build/build-mvc-monolith.sh
    source/tools/install-mvc.sh
)

production_shell_files=()
for rel in "${production_shell_relpaths[@]}"; do
    production_shell_files+=("$ROOT/$rel")
done

if rg --no-config -q 'mvc24pub' \
       "$ROOT/source/lib/combined-operational-public-connect.sh" &&
   ! rg --no-config -n \
       "^(function[[:space:]]+)?${old_lower}[A-Za-z0-9_]+[[:space:]]*\\(\\)" \
       -- "${production_shell_files[@]}" >/dev/null; then
    pass 'lowercase internal function namespace is MVC-native'
else
    fail 'lowercase internal function namespace is MVC-native'
fi

if grep -Fq 'MVC ROUTE PROTOCOLS' "$ROOT/source/tools/verify-mvc-state-readonly.sh" &&
   grep -Fq 'MVC NFT TABLES' "$ROOT/source/tools/verify-mvc-state-readonly.sh"; then
    pass 'verifier headings are MVC-native'
else
    fail 'verifier headings are MVC-native'
fi

if ! rg --no-config -n \
       "${old_upper}[A-Za-z0-9_]*" \
       -- "${production_shell_files[@]}" >/dev/null; then
    pass 'uppercase internal variable/constant namespace is MVC-native'
else
    fail 'uppercase internal variable/constant namespace is MVC-native'
fi

printf 'RESULT: MVC internal runtime identity %d/%d checks passed\n' "$P" "$((P + F))"
(( F == 0 ))
