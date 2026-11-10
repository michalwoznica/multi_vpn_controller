#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

modules=(
  combined-operational-public-composition.sh
  combined-operational-public-connect.sh
  combined-operational-public-disconnect.sh
  combined-operational-public-openvpn-early-reconcile.sh
  combined-operational-public-readonly.sh
  combined-operational-public-reconcile.sh
  combined-operational-wireguard-protected.sh
  combined-operational-wireguard-split.sh
)

missing=0
for f in "${modules[@]}"; do
  [[ -f $ROOT/source/lib/$f ]] || { printf 'missing: %s\n' "$f" >&2; missing=1; }
done
(( missing == 0 )) && pass 'all eight version-neutral runtime module filenames exist' || fail 'all eight version-neutral runtime module filenames exist'

manifest=$ROOT/source/build/monolith-runtime.manifest
manifest_count=$(grep -Ec 'source/lib/(combined-operational-public-(composition|connect|disconnect|openvpn-early-reconcile|readonly|reconcile)|combined-operational-wireguard-(protected|split))\.sh' "$manifest" || true)
[[ $manifest_count -eq 8 ]] && pass 'runtime manifest references exactly eight version-neutral runtime modules' || fail 'runtime manifest references exactly eight version-neutral runtime modules'

loader=$ROOT/source/lib/combined-operational-public-composition.sh
if rg -Fq 'combined-operational-public-connect' "$loader" &&
   rg -Fq 'combined-operational-public-disconnect' "$loader" &&
   rg -Fq 'combined-operational-wireguard-protected' "$loader" &&
   rg -Fq 'combined-operational-wireguard-split' "$loader"; then
  pass 'modular loader references version-neutral runtime module filenames'
else
  fail 'modular loader references version-neutral runtime module filenames'
fi

if ! find "$ROOT/source/lib" -maxdepth 1 -type f \
  \( -name 'combined-operational-public-*-v[0-9]*.sh' -o -name 'combined-operational-wireguard-*-v[0-9]*.sh' \) \
  -print -quit | grep -q .; then
  pass 'targeted public/WireGuard runtime module filenames are version-neutral'
else
  fail 'targeted public/WireGuard runtime module filenames are version-neutral'
fi

if rg -Fq '/run/mvc-controller' "$ROOT/source/tools/install-mvc.sh"; then
  pass 'installer is bound to MVC runtime namespace'
else
  fail 'installer is bound to MVC runtime namespace'
fi

printf 'RESULT: MVC runtime-module filenames %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
