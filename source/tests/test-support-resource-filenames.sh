#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

NFT=$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft
PROBE=$ROOT/source/tools/check-mvc-live-saved-ovpn-readonly.sh
MANIFEST=$ROOT/source/build/monolith-runtime.manifest

[[ -f $NFT && ! -L $NFT ]] && pass 'MVC nftables support resource exists as regular file' || fail 'MVC nftables support resource exists as regular file'
[[ -f $PROBE && ! -L $PROBE && -x $PROBE ]] && pass 'MVC OpenVPN read-only helper exists and is executable' || fail 'MVC OpenVPN read-only helper exists and is executable'

nft_sha=$(sha256sum "$NFT" | awk '{print $1}')
probe_sha=$(sha256sum "$PROBE" | awk '{print $1}')
if grep -Fxq "ASSET|b4-bootstrap-nft|$nft_sha|source/nftables/mvc-preclone-quarantine-offline.nft|embed-as-deterministic-runtime-resource" "$MANIFEST"; then
  pass 'manifest pins MVC nftables support filename and content hash'
else
  fail 'manifest pins MVC nftables support filename and content hash'
fi
if grep -Fxq "INTEGRATE|openvpn-source-preview|$probe_sha|source/tools/check-mvc-live-saved-ovpn-readonly.sh|internalize-only-controller-required-preview-derivative-path;do-not-bundle-unused-diagnostic-actions" "$MANIFEST"; then
  pass 'manifest pins MVC OpenVPN helper filename and content hash'
else
  fail 'manifest pins MVC OpenVPN helper filename and content hash'
fi

if rg -Fq '/run/mvc-controller' "$ROOT/source/tools/install-mvc.sh"; then
  pass 'installer maintenance guard uses MVC runtime namespace'
else
  fail 'installer maintenance guard uses MVC runtime namespace'
fi

printf 'RESULT: MVC support/resource filenames %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
