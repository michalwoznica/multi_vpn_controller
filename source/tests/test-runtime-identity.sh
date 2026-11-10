#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1"; F=$((F+1)); }

rg -q '/run/mvc-public-session' "$ROOT/source/lib/combined-operational-public-composition.sh" &&
  rg -q '/run/mvc-wireguard' "$ROOT/source/lib/combined-operational-d4-wireguard-parallel-live.sh" &&
  pass 'production session roots use MVC namespace' || fail 'production session roots use MVC namespace'

rg -q 'mvc_preclone_quarantine' "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft" &&
  rg -q 'mvc_preclone_bridge' "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft" &&
  rg -q 'mvc_preclone_underlay' "$ROOT/source/lib/combined-operational-host-guard-transaction.sh" &&
  pass 'B4 nftables tables use MVC namespace' || fail 'B4 nftables tables use MVC namespace'

installer=$ROOT/source/tools/install-mvc.sh
roots=(controller activation output-transition disconnect completion wireguard public-session)
missing=0
for r in "${roots[@]}"; do rg -Fq "/run/mvc-$r" "$installer" || missing=$((missing+1)); done
[[ $missing -eq 0 ]] && pass 'installer quiescence guard covers all MVC runtime roots' || fail 'installer quiescence guard covers all MVC runtime roots'

# Build the retired helper prefixes without embedding predecessor product literals in this public fixture.
old_lower=$(printf '%s%s%s' 'ub' 's' '24')
old_upper=$(printf '%s%s%s' 'UB' 'S' '24')
if rg -q 'mvc24pub' "$ROOT/source/lib/combined-operational-public-connect.sh" &&
   ! rg -n --glob '*.sh' "^(function[[:space:]]+)?${old_lower}[A-Za-z0-9_]+[[:space:]]*\\(\\)" "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" >/dev/null; then
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

if ! rg -n --glob '*.sh' "${old_upper}[A-Za-z0-9_]*" "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" >/dev/null; then
  pass 'uppercase internal variable/constant namespace is MVC-native'
else
  fail 'uppercase internal variable/constant namespace is MVC-native'
fi

printf 'RESULT: MVC internal runtime identity %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
