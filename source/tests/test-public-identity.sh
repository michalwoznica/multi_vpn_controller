#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)

pass=0
fail=0
ok(){ printf 'PASS: %s\n' "$1"; pass=$((pass+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; fail=$((fail+1)); }

public_docs=(
  "$ROOT/README.md" "$ROOT/BUILDING.md" "$ROOT/INSTALL.md" "$ROOT/OPERATIONS.md"
  "$ROOT/CHANGELOG.md" "$ROOT/docs/ARCHITECTURE.md" "$ROOT/docs/BUILD_ARCHITECTURE.md"
  "$ROOT/docs/SECURITY_MODEL.md" "$ROOT/docs/TESTING.md"
)

if ! grep -HnE 'UBS VPN Controller|sudo[[:space:]]+ubs-vpn|/usr/local/sbin/ubs-vpn|/root/ubs-v240-(emergency|dual)' "${public_docs[@]}"; then
    ok 'public documentation contains only MVC product/command/recovery identity'
else
    bad 'legacy public identity leaked into public documentation'
fi

for path in \
    "$ROOT/source/tools/mvc" \
    "$ROOT/source/tools/install-mvc.sh" \
    "$ROOT/source/tools/verify-mvc-state-readonly.sh" \
    "$ROOT/source/tools/recover-mvc-host-guard-local.sh" \
    "$ROOT/source/tools/recover-mvc-dual-local.sh" \
    "$ROOT/source/build/build-mvc-monolith.sh"; do
    [[ -f $path && ! -L $path ]] || { bad "expected MVC public tool exists: ${path#$ROOT/}"; continue; }
    ok "expected MVC public tool exists: ${path#$ROOT/}"
done

old_public=(
  "$ROOT/source/tools/vpn-v240"
  "$ROOT/source/tools/install-v240-monolith.sh"
  "$ROOT/source/tools/install-v241-monolith.sh"
  "$ROOT/source/tools/verify-v240-state-readonly.sh"
  "$ROOT/source/tools/recover-v240-host-guard-local.sh"
  "$ROOT/source/tools/recover-v240-dual-local.sh"
  "$ROOT/source/build/build-v240-monolith.sh"
)
old_found=0
for path in "${old_public[@]}"; do
    if [[ -e $path || -L $path ]]; then
        printf 'LEGACY PUBLIC PATH: %s\n' "${path#$ROOT/}" >&2
        old_found=1
    fi
done
(( old_found == 0 )) && ok 'legacy public tool filenames are absent' || bad 'legacy public tool filenames remain'

[[ -x $ROOT/dist/mvc ]] && ok 'generated public artifact is dist/mvc' || bad 'generated public artifact is dist/mvc'
[[ ! -e $ROOT/dist/ubs-vpn && ! -L $ROOT/dist/ubs-vpn ]] && ok 'legacy generated artifact name is absent' || bad 'legacy generated artifact name remains'

if [[ $($ROOT/dist/mvc version) == 'Multi VPN Controller 2.4.1' ]] &&
   $ROOT/dist/mvc --help | grep -Fq 'Multi VPN Controller 2.4.1' &&
   $ROOT/dist/mvc --help | grep -Fq 'sudo mvc connect'; then
    ok 'generated artifact reports and documents MVC identity'
else
    bad 'generated artifact reports and documents MVC identity'
fi

info=$($ROOT/dist/mvc --monolith-build-info)
if grep -Fxq 'checkpoint=MVC_R6A_DEAD_COMBINED_STATE_REMOVAL' <<<"$info" &&
   grep -Fxq 'emergency_recovery=/root/mvc-emergency-rollback' <<<"$info" &&
   grep -Fxq 'dual_recovery=/root/mvc-dual-recovery' <<<"$info"; then
    ok 'generated provenance exposes MVC checkpoint and recovery paths'
else
    bad 'generated provenance exposes MVC checkpoint and recovery paths'
fi

printf 'RESULT: MVC public identity %d/%d checks passed\n' "$pass" "$((pass+fail))"
(( fail == 0 ))
