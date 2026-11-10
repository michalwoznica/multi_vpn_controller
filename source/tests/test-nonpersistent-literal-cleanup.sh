#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

# Standalone verifier defaults to the current modular controller entrypoint.
if rg -Fq 'controller=${MVC24V_CONTROLLER:-"$tool_root/mvc"}' "$ROOT/source/tools/verify-mvc-state-readonly.sh"; then
  pass 'standalone verifier defaults to source/tools/mvc'
else
  fail 'standalone verifier defaults to source/tools/mvc'
fi

# Modular C4 admission authenticates the MVC recovery installation.
if rg -Fq 'local installed=/root/mvc-emergency-rollback' "$ROOT/source/lib/combined-operational-c4-local-admission.sh" &&
   rg -Fq '/tools/recover-mvc-host-guard-local.sh' "$ROOT/source/lib/combined-operational-c4-local-admission.sh"; then
  pass 'modular C4 recovery identity uses MVC recovery path/tool'
else
  fail 'modular C4 recovery identity uses MVC recovery path/tool'
fi

# Local confirmation strings are operator-facing and use current identity.
if rg -Fq 'PREPARE MVC GUARDED OPENVPN' "$ROOT/source/lib/combined-operational-c4-local-admission.sh" &&
   rg -Fq 'INSTALL MVC DENY ALL' "$ROOT/source/lib/combined-operational-host-guard-acceptance.sh" &&
   rg -Fq 'RELEASE MVC DENY ALL' "$ROOT/source/lib/combined-operational-host-guard-acceptance.sh"; then
  pass 'interactive confirmation phrases use MVC identity'
else
  fail 'interactive confirmation phrases use MVC identity'
fi

# Fixed-root underlay inspection uses the current controller root.
if rg -Fq '/run/mvc-controller/controller.lock' "$ROOT/source/lib/combined-operational-session-underlay-binding.sh" &&
   rg -Fq 'mvc24e_runtime_root_valid /run/mvc-controller 0' "$ROOT/source/lib/combined-controller-entry.sh"; then
  pass 'fixed-root underlay inspection seam uses /run/mvc-controller'
else
  fail 'fixed-root underlay inspection seam uses /run/mvc-controller'
fi

if ! rg -n 'Multi VPN Controller' "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" "$ROOT/source/nftables" >/dev/null; then
  fail 'production source exposes current product identity'
else
  pass 'production source exposes current product identity'
fi

[[ -f $ROOT/source/tests/test-persistent-foundation-namespace.sh ]] && pass 'persistent record namespace has dedicated regression coverage' || fail 'persistent record namespace has dedicated regression coverage'

installer=$ROOT/source/tools/install-mvc.sh
if rg -Fq '/usr/local/sbin/mvc' "$installer" && rg -Fq '/root/mvc-emergency-rollback' "$installer" && rg -Fq '/root/mvc-dual-recovery' "$installer"; then
  pass 'installer manages only current MVC destinations'
else
  fail 'installer manages only current MVC destinations'
fi

printf 'RESULT: MVC non-persistent identity cleanup %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
