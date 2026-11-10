#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

C19=$ROOT/source/lib/combined-operational-c19-protected-openvpn-stop.sh
C23T=$ROOT/source/lib/combined-operational-c23t-session-finalize.sh
DISC=$ROOT/source/lib/combined-operational-public-disconnect.sh

# C19 has two authenticated variants: normal stop and truthful already-absent stop.
if [[ $(rg -F 'mvc-c19-openvpn-stop-v1' "$C19" | wc -l) -ge 3 ]] &&
   [[ $(rg -F 'mvc-c24a-openvpn-absent-stop-v1' "$C19" | wc -l) -ge 3 ]]; then
  pass 'C19 normal and absent-stop producer/validators use MVC magic'
else
  fail 'C19 normal and absent-stop producer/validators use MVC magic'
fi


# C23T release -> clone-delete -> archive-plan is one hash-linked completion chain.
for sig in mvc-c23t-release-intent-v1 mvc-c23t-clone-delete-intent-v1 mvc-c23t-archive-plan-v1; do
  count=$(rg -F "$sig" "$C23T" | wc -l)
  if (( count >= 2 )); then pass "$sig producer/validator pair present"; else fail "$sig producer/validator pair present"; fi
done


# Normal disconnect independently authenticates the archived completion plan.
if rg -Fq '== mvc-c23t-archive-plan-v1' "$DISC"; then
  pass 'public disconnect archived-session validator uses current MVC archive magic'
else
  fail 'public disconnect archived-session validator uses current MVC archive magic'
fi


printf 'RESULT: MVC-R5D disconnect/finalization record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
