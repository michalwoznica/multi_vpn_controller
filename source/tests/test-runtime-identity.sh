#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1"; F=$((F+1)); }

# Public/runtime-visible namespace must be MVC-native. The installer is allowed
# to mention legacy /run/ubs-v240-* roots solely to refuse package maintenance
# during migration from the physically proven predecessor.
legacy_hits=$(
  cd "$ROOT"
  rg -n --hidden --glob '!.handoff/**' --glob '!dist/**' --glob '!source/tests/test-runtime-identity.sh' \
    '/run/ubs-v240-|vpn_v240_preclone_|ubs-v240-prepared-|/dev/shm/ubs-v240-monolith-assets' . || :
)
if [[ -z $legacy_hits ]] || ! grep -vE '^\./source/tools/install-mvc\.sh:.*\/run\/ubs-v240-' <<<"$legacy_hits" | grep -q .; then
  pass 'runtime-visible namespace contains no legacy UBS paths/tables outside installer migration guard'
else
  printf '%s\n' "$legacy_hits" >&2
  fail 'runtime-visible namespace contains no legacy UBS paths/tables outside installer migration guard'
fi

rg -q '/run/mvc-public-session' "$ROOT/source/lib/combined-operational-public-v240-composition.sh" &&
  rg -q '/run/mvc-wireguard' "$ROOT/source/lib/combined-operational-d4-wireguard-parallel-live.sh" &&
  pass 'production session roots use mvc namespace' || fail 'production session roots use mvc namespace'

rg -q 'mvc_preclone_quarantine' "$ROOT/source/nftables/vpn-v240-preclone-quarantine-offline.nft" &&
  rg -q 'mvc_preclone_bridge' "$ROOT/source/nftables/vpn-v240-preclone-quarantine-offline.nft" &&
  rg -q 'mvc_preclone_underlay' "$ROOT/source/lib/combined-operational-host-guard-transaction.sh" &&
  pass 'B4 nftables tables use mvc namespace' || fail 'B4 nftables tables use mvc namespace'

rg -q '/run/ubs-v240-controller' "$ROOT/source/tools/install-mvc.sh" &&
  rg -q '/run/mvc-controller' "$ROOT/source/tools/install-mvc.sh" &&
  pass 'installer refuses both legacy and MVC runtime roots during migration' || fail 'installer refuses both legacy and MVC runtime roots during migration'

rg -q 'ubs24pub' "$ROOT/source/lib/combined-operational-public-v240-connect.sh" &&
  pass 'internal ubs24 function namespace intentionally retained' || fail 'internal ubs24 function namespace intentionally retained'

if ! grep -q 'UBS ROUTE PROTOCOLS\|UBS NFT TABLES' "$ROOT/source/tools/verify-mvc-state-readonly.sh"; then
  pass 'verifier headings are MVC-native'
else
  fail 'verifier headings are MVC-native'
fi

printf 'RESULT: MVC-R2 runtime identity %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
