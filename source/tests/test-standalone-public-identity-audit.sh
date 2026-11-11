#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

# Construct predecessor tokens at runtime so this public regression can forbid
# them without embedding the obsolete product identity in the repository.
old_brand=$(printf '%s%s' 'ub' 's')
old_version=$(printf 'v%s' '240')
old_command="${old_brand}-vpn"
old_release="${old_brand}-${old_version}"
old_lower_prefix="${old_brand}24"
old_upper_prefix=$(printf '%s%s%s' 'UB' 'S' '24')
old_upper_brand=$(printf '%s%s' 'UB' 'S')
legacy_re="${old_command}|${old_release}|${old_lower_prefix}|${old_upper_prefix}|(^|[^[:alnum:]_])${old_version}([^[:alnum:]_]|$)|(^|[^[:alnum:]_])${old_upper_brand}([^[:alnum:]_]|$)"

hits=$(cd "$ROOT" && rg -n -i "$legacy_re" --glob '!.handoff/**' --glob '!dist/**' . || :)
if [[ -z $hits ]]; then
  pass 'Git-facing text contains no predecessor product identity'
else
  printf '%s\n' "$hits" >&2
  fail 'Git-facing text contains no predecessor product identity'
fi

name_hits=$(find "$ROOT" \
  -path "$ROOT/.handoff" -prune -o \
  -path "$ROOT/dist" -prune -o \
  -type f -printf '%f\n' | grep -Ei "${old_command}|${old_release}|${old_version}|${old_brand}" || :)
if [[ -z $name_hits ]]; then
  pass 'Git-facing filenames contain no predecessor product identity'
else
  printf '%s\n' "$name_hits" >&2
  fail 'Git-facing filenames contain no predecessor product identity'
fi

installer=$ROOT/source/tools/install-mvc.sh
for item in /usr/local/sbin/mvc /root/mvc-emergency-rollback /root/mvc-dual-recovery \
            /run/mvc-controller /run/mvc-activation /run/mvc-output-transition \
            /run/mvc-disconnect /run/mvc-completion /run/mvc-wireguard /run/mvc-public-session; do
  if grep -Fq "$item" "$installer"; then :; else fail "installer current MVC path present: $item"; fi
done
pass 'installer contains the complete current MVC path set'

if ! rg -q -i 'predecessor.*migrat|migrat.*predecessor|pre-mvc' "$installer"; then
  pass 'public installer has no predecessor migration contract'
else
  fail 'public installer has no predecessor migration contract'
fi

if rg -Fq 'checkpoint=MVC_R8_BOOTSTRAP_RESOURCE_PIN_REPAIR' < <("$ROOT/dist/mvc" --monolith-build-info); then
  pass 'generated artifact carries standalone-public checkpoint identity'
else
  fail 'generated artifact carries standalone-public checkpoint identity'
fi

if rg -Fq 'check-mvc-live-saved-ovpn-readonly' "$ROOT/source/tests/test-runtime-seams.sh"; then
  pass 'runtime-seams regression tracks the current MVC helper name'
else
  fail 'runtime-seams regression tracks the current MVC helper name'
fi

if grep -Fxq '/.handoff/' "$ROOT/.gitignore" && grep -Fxq '/dist/' "$ROOT/.gitignore"; then
  pass 'private handoff and generated dist remain outside the public Git surface'
else
  fail 'private handoff and generated dist remain outside the public Git surface'
fi

printf 'RESULT: MVC-R8 standalone public identity audit %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
