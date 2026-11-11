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

if grep -Hq 'Multi VPN Controller' "${public_docs[@]}"; then
    ok 'public documentation identifies Multi VPN Controller'
else
    bad 'public documentation identifies Multi VPN Controller'
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

[[ -x $ROOT/dist/mvc ]] && ok 'generated public artifact is dist/mvc' || bad 'generated public artifact is dist/mvc'

if [[ $($ROOT/dist/mvc version) == 'Multi VPN Controller 2.4.2' ]] &&
   $ROOT/dist/mvc --help | grep -Fq 'Multi VPN Controller 2.4.2' &&
   $ROOT/dist/mvc --help | grep -Fq 'sudo mvc connect'; then
    ok 'generated artifact reports and documents MVC identity'
else
    bad 'generated artifact reports and documents MVC identity'
fi

info=$($ROOT/dist/mvc --monolith-build-info)
if grep -Fxq 'checkpoint=MVC_242_R1_DEPENDENCY_PREFLIGHT_CLEANUP' <<<"$info" &&
   grep -Fxq 'emergency_recovery=/root/mvc-emergency-rollback' <<<"$info" &&
   grep -Fxq 'dual_recovery=/root/mvc-dual-recovery' <<<"$info"; then
    ok 'generated provenance exposes standalone MVC checkpoint and recovery paths'
else
    bad 'generated provenance exposes standalone MVC checkpoint and recovery paths'
fi

printf 'RESULT: MVC public identity %d/%d checks passed\n' "$pass" "$((pass+fail))"
(( fail == 0 ))
