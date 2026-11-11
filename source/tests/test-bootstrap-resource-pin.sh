#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

RESOURCE=$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft
PLAN=$ROOT/source/lib/combined-operational-host-guard-plan.sh
TXN=$ROOT/source/lib/combined-operational-host-guard-transaction.sh
MANIFEST=$ROOT/source/build/monolith-runtime.manifest
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
TEST_UNDERLAY=test-wlan0
actual=$(sha256sum -- "$RESOURCE" | awk '{print $1}')
manifest=$(awk -F'|' '$1=="ASSET" && $2=="b4-bootstrap-nft" {print $3}' "$MANIFEST")

if [[ -n $actual && $actual == "$manifest" ]]; then
  pass 'manifest B4 asset hash matches current nft resource'
else
  fail 'manifest B4 asset hash matches current nft resource'
fi

for f in "$PLAN" "$TXN"; do
  if grep -Fq "$actual" "$f"; then
    pass "security pin matches current nft resource in ${f##*/}"
  else
    fail "security pin matches current nft resource in ${f##*/}"
  fi
done

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
: > "$TMP/batch"
chmod 600 "$TMP/batch"
# shellcheck disable=SC1090
source "$PLAN"
if mvc24gb1_render "$TEST_UNDERLAY" "$RESOURCE" "$TMP/batch" &&
   [[ $(grep -c '^add ' "$TMP/batch") == 9 ]]; then
  pass 'real B1 render accepts current resource and emits nine-rule batch'
else
  fail 'real B1 render accepts current resource and emits nine-rule batch'
fi

# shellcheck disable=SC1090
source "$TXN"
if mvc24gb2_batch_valid "$TEST_UNDERLAY" "$TMP/batch"; then
  pass 'real B2 batch validator accepts B1 output against current resource'
else
  fail 'real B2 batch validator accepts B1 output against current resource'
fi

"$BUILDER" "$TMP/mvc" >/dev/null
mkdir "$TMP/assets"
"$TMP/mvc" --monolith-resource-selftest "$TMP/assets" >/dev/null
if cmp -s -- "$TMP/assets/preclone-quarantine.nft" "$RESOURCE"; then
  pass 'generated monolith materializes the same pinned nft resource'
else
  fail 'generated monolith materializes the same pinned nft resource'
fi

info=$("$TMP/mvc" --monolith-build-info)
if grep -Fxq 'checkpoint=MVC_V242_RELEASE' <<<"$info"; then
  pass 'generated release retains repaired bootstrap resource path'
else
  fail 'generated release retains repaired bootstrap resource path'
fi

printf 'RESULT: MVC v2.4.2 bootstrap resource pin regression %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
