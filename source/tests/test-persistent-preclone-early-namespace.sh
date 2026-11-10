#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }
TMP=$(mktemp -d /tmp/mvc-r5b.XXXXXXXX)
trap 'rm -rf -- "$TMP"' EXIT

fixed_new=(
  mvc-public-preclone-intent-v1
  mvc-public-preclone-binding-v1
  mvc-public-preclone-delete-v1
  mvc-public-preclone-release-v1
  mvc-public-preclone-retire-v1
  mvc-public-early-openvpn-cleanup-v1
  mvc-public-early-handback-v1
  mvc-public-early-guard-release-v1
  mvc-public-early-retire-v1
)

# Every fixed schema magic must be present in the active producer/validator pair.
missing=0
for sig in "${fixed_new[@]}"; do
  count=$(rg -F "$sig" \
    "$ROOT/source/lib/combined-operational-public-connect.sh" \
    "$ROOT/source/lib/combined-operational-public-openvpn-early-reconcile.sh" | wc -l)
  (( count >= 2 )) || { printf 'missing producer/validator pair: %s count=%s\n' "$sig" "$count" >&2; missing=1; }
done
if (( missing == 0 )); then pass 'fixed R5B producer/validator magics use MVC namespace'; else fail 'fixed R5B producer/validator magics use MVC namespace'; fi


# The generic early-intent producer/validator emits two additional persistent
# schemas that a literal-only inventory cannot enumerate: stop and clone-delete.
source "$ROOT/source/lib/combined-operational-public-openvpn-early-reconcile.sh"
TEST_RUNTIME=$TMP/runtime
mkdir -m 700 "$TEST_RUNTIME"
printf 'plan\n' > "$TEST_RUNTIME/early-plan"
chmod 400 "$TEST_RUNTIME/early-plan"
mvc24pube_runtime(){ printf '%s\n' "$TEST_RUNTIME"; }
mvc24pube_plan_path(){ printf '%s\n' "$TEST_RUNTIME/early-plan"; }
mvc24pube_sha(){ sha256sum "$1" | awk '{print $1}'; }
MVC24PUBE_SOURCE_UUID=11111111-1111-4111-8111-111111111111
MVC24PUBE_CLONE_UUID=22222222-2222-4222-8222-222222222222
MVC24PUBE_NM_OWNER=':1.9|123|0'

for kind in stop clone-delete; do
  path=$TEST_RUNTIME/early-${kind}-intent
  if mvc24pube_publish_simple_intent "$kind" "$path" &&
     [[ $(head -n 1 "$path") == "mvc-public-early-${kind}-v1" ]] &&
     mvc24pube_simple_intent_valid "$kind" "$path"; then
    pass "dynamic $kind intent emits and accepts MVC magic"
  else
    fail "dynamic $kind intent emits and accepts MVC magic"
  fi
  sed -i "1cinvalid-public-early-${kind}-v0" "$path"
  chmod 400 "$path"
  if mvc24pube_simple_intent_valid "$kind" "$path"; then
    fail "dynamic $kind intent rejects synthetic invalid magic"
  else
    pass "dynamic $kind intent rejects synthetic invalid magic"
  fi
  rm -f -- "$path"
done


printf 'RESULT: MVC-R5B preclone/early record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
