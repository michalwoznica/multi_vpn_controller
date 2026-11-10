#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

D4=$ROOT/source/lib/combined-operational-d4-wireguard-parallel-live.sh
DISC=$ROOT/source/lib/combined-operational-public-v240-disconnect.sh
REC=$ROOT/source/tools/recover-mvc-dual-local.sh
PROT=$ROOT/source/lib/combined-operational-wireguard-protected-v240.sh
MAN=$ROOT/source/build/monolith-runtime.manifest

# The D4 ownership record must move as one trust domain: writer, normal disconnect,
# and the independent recovery tool must all accept the same current magic.
if [[ $(rg -F 'mvc-c23ai-wireguard-intent-v1' "$D4" | wc -l) -ge 1 ]] &&
   [[ $(rg -F 'mvc-c23ai-wireguard-intent-v1' "$DISC" | wc -l) -ge 1 ]] &&
   [[ $(rg -F 'mvc-c23ai-wireguard-intent-v1' "$REC" | wc -l) -ge 1 ]]; then
  pass 'D4 intent writer, normal disconnect, and independent recovery use MVC magic'
else
  fail 'D4 intent writer, normal disconnect, and independent recovery use MVC magic'
fi

if ! rg -F 'ubs-v240-c23ai-wireguard-intent-v1' "$ROOT/source/lib" "$ROOT/source/tools" >/dev/null; then
  pass 'retired D4 ownership magic absent from production runtime and recovery source'
else
  fail 'retired D4 ownership magic absent from production runtime and recovery source'
fi

# Protected-WG release is self-contained but authenticated by the D4 intent hash.
if [[ $(rg -F 'mvc-wireguard-protected-release-v1' "$PROT" | wc -l) -eq 2 ]] &&
   ! rg -F 'ubs-v240-wireguard-protected-release-v1' "$PROT" >/dev/null; then
  pass 'protected-WG release producer and validator use MVC magic'
else
  fail 'protected-WG release producer and validator use MVC magic'
fi

if rg -Fq 'd4_intent=$(mvc24gd4_hash_file "$runtime/intent")' "$PROT"; then
  pass 'protected-WG release remains hash-bound to D4 ownership intent'
else
  fail 'protected-WG release remains hash-bound to D4 ownership intent'
fi

# The independent recovery source identity is a manifest/provenance boundary.
rec_sha=$(sha256sum "$REC" | awk '{print $1}')
man_sha=$(awk -F'|' '$1=="EXTERNAL_RECOVERY" && $2=="dual" {print $3}' "$MAN")
if [[ $rec_sha == "$man_sha" ]]; then
  pass 'manifest pins current independent dual-recovery source identity'
else
  printf 'recovery=%s manifest=%s\n' "$rec_sha" "$man_sha" >&2
  fail 'manifest pins current independent dual-recovery source identity'
fi

# Only dormant combined-state magic remains frozen after R5E.
remaining=$(cd "$ROOT" && rg -o --no-filename \
  'ubs-v24[01]-[A-Za-z0-9._-]+-v[0-9]+|ubs-vpn-state-v4-draft' \
  source/lib source/tools source/build source/nftables | sort -u || true)
if [[ -z $remaining ]]; then
  pass 'no retired persistent UBS magic remains in production source'
else
  printf '%s\n' "$remaining" >&2
  fail 'no retired persistent UBS magic remains in production source'
fi

# The exact current D4 parser path must reject retired magic. Use the normal
# disconnect module's literal gate as an independent current consumer assertion.
if rg -Fq '== mvc-c23ai-wireguard-intent-v1' "$DISC" &&
   ! rg -Fq '== ubs-v240-c23ai-wireguard-intent-v1' "$DISC"; then
  pass 'normal disconnect parser rejects retired D4 magic by exact current gate'
else
  fail 'normal disconnect parser rejects retired D4 magic by exact current gate'
fi

printf 'RESULT: MVC-R5C WireGuard/recovery record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
