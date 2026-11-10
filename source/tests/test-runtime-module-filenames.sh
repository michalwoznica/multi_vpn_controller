#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

new=(
  combined-operational-public-composition.sh
  combined-operational-public-connect.sh
  combined-operational-public-disconnect.sh
  combined-operational-public-openvpn-early-reconcile.sh
  combined-operational-public-readonly.sh
  combined-operational-public-reconcile.sh
  combined-operational-wireguard-protected.sh
  combined-operational-wireguard-split.sh
)
old=(
  combined-operational-public-v240-composition.sh
  combined-operational-public-v240-connect.sh
  combined-operational-public-v240-disconnect.sh
  combined-operational-public-v240-openvpn-early-reconcile.sh
  combined-operational-public-v240-readonly.sh
  combined-operational-public-v240-reconcile.sh
  combined-operational-wireguard-protected-v240.sh
  combined-operational-wireguard-split-v240.sh
)

missing=0
for f in "${new[@]}"; do
  [[ -f $ROOT/source/lib/$f ]] || { printf 'missing: %s\n' "$f" >&2; missing=1; }
done
(( missing == 0 )) && pass 'all eight version-neutral runtime module filenames exist' || fail 'all eight version-neutral runtime module filenames exist'

present_old=0
for f in "${old[@]}"; do
  [[ ! -e $ROOT/source/lib/$f ]] || { printf 'retired file remains: %s\n' "$f" >&2; present_old=1; }
done
(( present_old == 0 )) && pass 'all eight retired v240 runtime module filenames are absent' || fail 'all eight retired v240 runtime module filenames are absent'

refs=$(rg -l 'combined-operational-(public-v240|wireguard-(protected|split)-v240).*\.sh' \
  "$ROOT/source/build" "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/nftables" || true)
[[ -z $refs ]] && pass 'production/build source has no retired runtime-module path references' || { printf '%s\n' "$refs" >&2; fail 'production/build source has no retired runtime-module path references'; }

manifest=$ROOT/source/build/monolith-runtime.manifest
manifest_new=$(grep -Ec 'source/lib/(combined-operational-public-(composition|connect|disconnect|openvpn-early-reconcile|readonly|reconcile)|combined-operational-wireguard-(protected|split))\.sh' "$manifest" || true)
[[ $manifest_new -eq 8 ]] && pass 'runtime manifest references exactly eight renamed runtime modules' || fail 'runtime manifest references exactly eight renamed runtime modules'

manifest_old=$(grep -Ec 'source/lib/.*v240.*\.sh' "$manifest" || true)
[[ $manifest_old -eq 0 ]] && pass 'runtime manifest contains no v240 runtime-module filename' || fail 'runtime manifest contains no v240 runtime-module filename'

loader=$ROOT/source/lib/combined-operational-public-composition.sh
if rg -Fq 'combined-operational-public-connect' "$loader" && \
   rg -Fq 'combined-operational-public-disconnect' "$loader" && \
   rg -Fq 'combined-operational-wireguard-protected' "$loader" && \
   rg -Fq 'combined-operational-wireguard-split' "$loader"; then
  pass 'modular loader references version-neutral runtime module filenames'
else
  fail 'modular loader references version-neutral runtime module filenames'
fi

if rg -q '/usr/local/sbin/ubs-vpn|/root/ubs-v240-|/run/ubs-v240-' "$ROOT/source/tools/install-mvc.sh"; then
  pass 'legacy installed UBS migration compatibility remains intact'
else
  fail 'legacy installed UBS migration compatibility remains intact'
fi

if ! find "$ROOT/source/lib" -maxdepth 1 -type f -name '*v240*' -print -quit | grep -q .; then
  pass 'source/lib has no v240 filename remaining'
else
  fail 'source/lib has no v240 filename remaining'
fi

printf 'RESULT: MVC-R6C runtime-module filename migration %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
