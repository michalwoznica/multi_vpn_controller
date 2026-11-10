#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

# Public/operator messages must no longer direct users to the retired command.
if ! rg -n 'use vpn-v240|Run vpn-v240|Usage: vpn-v240' \
    "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" "$ROOT/source/nftables" >/dev/null; then
  pass 'operator-facing controller messages use mvc command'
else
  fail 'operator-facing controller messages still mention vpn-v240'
fi

# Standalone verifier must default to the current modular controller entrypoint.
if rg -Fq 'controller=${MVC24V_CONTROLLER:-"$tool_root/mvc"}' "$ROOT/source/tools/verify-mvc-state-readonly.sh"; then
  pass 'standalone verifier defaults to source/tools/mvc'
else
  fail 'standalone verifier defaults to source/tools/mvc'
fi

# Modular C4 admission must authenticate the MVC recovery installation, not the retired path.
if rg -Fq 'local installed=/root/mvc-emergency-rollback' "$ROOT/source/lib/combined-operational-c4-local-admission.sh" &&
   rg -Fq '/tools/recover-mvc-host-guard-local.sh' "$ROOT/source/lib/combined-operational-c4-local-admission.sh"; then
  pass 'modular C4 recovery identity uses MVC recovery path/tool'
else
  fail 'modular C4 recovery identity uses MVC recovery path/tool'
fi

# Explicit local confirmation strings are operator-facing and must use MVC wording.
if rg -Fq 'PREPARE MVC GUARDED OPENVPN' "$ROOT/source/lib/combined-operational-c4-local-admission.sh" &&
   rg -Fq 'INSTALL MVC DENY ALL' "$ROOT/source/lib/combined-operational-host-guard-acceptance.sh" &&
   rg -Fq 'RELEASE MVC DENY ALL' "$ROOT/source/lib/combined-operational-host-guard-acceptance.sh" &&
   ! rg -n 'PREPARE UBS V240|INSTALL UBS V240|RELEASE UBS V240' "$ROOT/source/lib" >/dev/null; then
  pass 'interactive confirmation phrases use MVC identity'
else
  fail 'interactive confirmation phrases use MVC identity'
fi

# The older fixed-root underlay inspection seam must now target the current MVC controller root.
if ! rg -n '/run/ubs-vpn-controller-v240' "$ROOT/source/lib" >/dev/null &&
   rg -Fq '/run/mvc-controller/controller.lock' "$ROOT/source/lib/combined-operational-session-underlay-binding.sh" &&
   rg -Fq 'mvc24e_runtime_root_valid /run/mvc-controller 0' "$ROOT/source/lib/combined-controller-entry.sh"; then
  pass 'fixed-root underlay inspection seam uses /run/mvc-controller'
else
  fail 'fixed-root underlay inspection seam uses /run/mvc-controller'
fi

# Scratch/temp names are not authenticated protocol records and should not carry retired UBS naming.
legacy_scratch=$(cd "$ROOT" && rg -n \
  --glob '!source/tests/test-nonpersistent-literal-cleanup.sh' \
  --glob '!source/tests/test-runtime-identity.sh' \
  '/dev/shm/ubs24|/dev/shm/ubs-v24[01]|/tmp/ubs-|\.ubs24-resource\.|\.ubs-vpn-state\.|\.ubs-nm\.|\.ubs-v240-c1-verify\.' source || :)
if [[ -z $legacy_scratch ]]; then
  pass 'transient scratch names use MVC namespace'
else
  printf '%s\n' "$legacy_scratch" >&2
  fail 'transient scratch names use MVC namespace'
fi

# Retired product wording must not remain in production comments/source text.
if ! rg -n 'UBS VPN Controller' "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" "$ROOT/source/nftables" >/dev/null; then
  pass 'production source comments use Multi VPN Controller identity'
else
  fail 'production source comments use Multi VPN Controller identity'
fi

# R4 deliberately freezes authenticated journal/signature formats for R5.
signature_set=$(cd "$ROOT" && rg -o --no-filename --glob '!source/tests/test-nonpersistent-literal-cleanup.sh' \
  'ubs-v24[01]-[A-Za-z0-9._-]+-v[0-9]+|ubs-vpn-state-v4-draft' source | sort -u)
signature_sha=$(printf '%s\n' "$signature_set" | sha256sum | awk '{print $1}')
signature_count=$(cd "$ROOT" && rg -o --no-filename --glob '!source/tests/test-nonpersistent-literal-cleanup.sh' \
  'ubs-v24[01]-[A-Za-z0-9._-]+-v[0-9]+|ubs-vpn-state-v4-draft' source | wc -l)
if [[ $signature_sha == 9d17676190a036ba7baef655cff8795f7df6ffdc5de835df36adb5f67781f88c && $signature_count == 59 ]]; then
  pass 'authenticated persistent record signatures remain frozen for R5'
else
  fail 'authenticated persistent record signatures remain frozen for R5'
fi

# Legacy installed names remain only as deliberate installer/test migration compatibility.
legacy_install_hits=$(cd "$ROOT" && rg -n --glob '!source/tests/test-nonpersistent-literal-cleanup.sh' \
  '/usr/local/sbin/ubs-vpn|/root/ubs-v240-(emergency-rollback|dual-recovery)' source || :)
if [[ -n $legacy_install_hits ]] &&
   ! grep -vE '^source/(tools/install-mvc\.sh|tests/test-installer\.sh|tests/test-public-identity\.sh):' <<<"$legacy_install_hits" | grep -q .; then
  pass 'legacy installed names remain only in migration compatibility/tests'
else
  printf '%s\n' "$legacy_install_hits" >&2
  fail 'legacy installed names remain only in migration compatibility/tests'
fi

printf 'RESULT: MVC-R4 non-persistent literal cleanup %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
