#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

CONN=$ROOT/source/lib/combined-operational-public-connect.sh
DISC=$ROOT/source/lib/combined-operational-public-disconnect.sh

# Central ownership records move as one trust domain: producer and every current
# live/completed-session consumer must agree on the same schema magic.
if [[ $(rg -F 'mvc-public-transaction-v1' "$CONN" | wc -l) -ge 1 ]] &&
   [[ $(rg -F 'mvc-public-transaction-v1' "$DISC" | wc -l) -ge 2 ]]; then
  pass 'public transaction producer and disconnect consumers use MVC magic'
else
  fail 'public transaction producer and disconnect consumers use MVC magic'
fi

if [[ $(rg -F 'mvc-public-active-v1' "$CONN" | wc -l) -ge 3 ]] &&
   [[ $(rg -F 'mvc-public-active-v1' "$DISC" | wc -l) -ge 2 ]]; then
  pass 'public active producer/finalizer and disconnect consumers use MVC magic'
else
  fail 'public active producer/finalizer and disconnect consumers use MVC magic'
fi


# Exercise the real transaction parser with the current schema and a synthetic
# invalid schema. The prepared state avoids any dependency on live tunnel journals.
export MVC24E_CODE_ROOT=$ROOT/source
source "$ROOT/source/lib/combined-operational-public-composition.sh"
T=$(mktemp -d /tmp/mvc-r5e.XXXXXXXX)
trap 'rm -rf -- "$T"' EXIT
TEST_RUNTIME=$T/public
mkdir -m 700 "$TEST_RUNTIME"
mvc24pub_session_runtime_root(){ printf '%s\n' "$TEST_RUNTIME"; }
boot=$(cat /proc/sys/kernel/random/boot_id)
userns=$(readlink /proc/self/ns/user); netns=$(readlink /proc/self/ns/net); mntns=$(readlink /proc/self/ns/mnt)
write_tx(){
  local magic=$1
  cat > "$TEST_RUNTIME/transaction" <<EOF2
$magic
state=prepared-before-mutation
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=11111111-1111-4111-8111-111111111111
ovpn_clone_uuid=-
wg_source_uuid=22222222-2222-4222-8222-222222222222
wg_temp_uuid=33333333-3333-4333-8333-333333333333
underlay=f15ra
controller_prepare_sha=-
controller_transition_sha=-
activation_sha=-
output_sha=-
d4_intent_sha=-
EOF2
  chmod 400 "$TEST_RUNTIME/transaction"
}
write_tx mvc-public-transaction-v1
mvc24pubd_reset
if mvc24pubd_parse_transaction_marker && [[ $MVC24PUBD_TRANSACTION_STATE == prepared-before-mutation ]]; then
  pass 'real transaction parser accepts MVC public transaction magic'
else
  fail 'real transaction parser accepts MVC public transaction magic'
fi
write_tx invalid-public-transaction-v0
mvc24pubd_reset
if ! mvc24pubd_parse_transaction_marker; then
  pass 'real transaction parser rejects synthetic invalid public transaction magic'
else
  fail 'real transaction parser rejects synthetic invalid public transaction magic'
fi


printf 'RESULT: MVC-R5E public-session record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
