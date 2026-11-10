#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

D4=$ROOT/source/lib/combined-operational-d4-wireguard-parallel-live.sh
DISC=$ROOT/source/lib/combined-operational-public-disconnect.sh
REC=$ROOT/source/tools/recover-mvc-dual-local.sh
PROT=$ROOT/source/lib/combined-operational-wireguard-protected.sh
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


# Protected-WG release is self-contained but authenticated by the D4 intent hash.
if [[ $(rg -F 'mvc-wireguard-protected-release-v1' "$PROT" | wc -l) -eq 2 ]]; then
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


# The normal disconnect path must authenticate the exact current D4 schema.
if rg -Fq '== mvc-c23ai-wireguard-intent-v1' "$DISC"; then
  pass 'normal disconnect parser authenticates the exact current D4 magic'
else
  fail 'normal disconnect parser authenticates the exact current D4 magic'
fi

printf 'RESULT: MVC-R5C WireGuard/recovery record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
