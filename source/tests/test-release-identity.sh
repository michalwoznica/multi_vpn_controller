#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
# shellcheck source=release-identity-fixture.sh
source "$HERE/release-identity-fixture.sh"
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

if [[ $(cat "$ROOT/source/release-version") == "$MVC_TEST_RELEASE_VERSION" ]]; then
  pass 'release-version is the current release identity source'
else
  fail 'release-version is the current release identity source'
fi

# The current version literal belongs only in source/release-version. Changelog
# history may naturally contain version numbers and is outside source/.
current_hits=$(rg -l -F "$MVC_TEST_RELEASE_VERSION" "$ROOT/source" --glob '!release-version' || :)
if [[ -z $current_hits ]]; then
  pass 'current release version literal is not duplicated under source/'
else
  printf '%s\n' "$current_hits" >&2
  fail 'current release version literal is not duplicated under source/'
fi

release_sha=$(sha256sum "$ROOT/source/release-version" | awk '{print $1}')
if grep -Fxq "INTEGRATE|release-version|${release_sha}|source/release-version|release-identity-data" "$ROOT/source/build/monolith-runtime.manifest"; then
  pass 'runtime manifest pins release-version content identity'
else
  fail 'runtime manifest pins release-version content identity'
fi

info=$($ROOT/dist/mvc --monolith-build-info)
if [[ $($ROOT/dist/mvc version) == "$MVC_TEST_RELEASE_BANNER" ]] &&
   [[ $($ROOT/source/tools/mvc version) == "$MVC_TEST_RELEASE_BANNER" ]] &&
   grep -Fxq "checkpoint=$MVC_TEST_RELEASE_CHECKPOINT" <<<"$info" &&
   grep -Fxq "authority=$MVC_TEST_RELEASE_AUTHORITY" <<<"$info" &&
   grep -Fxq "release_version_sha256=$release_sha" <<<"$info"; then
  pass 'modular and generated controllers derive one release identity'
else
  fail 'modular and generated controllers derive one release identity'
fi

printf 'RESULT: MVC %s release identity %d/%d checks passed\n' "$MVC_TEST_RELEASE_VERSION" "$P" "$((P+F))"
(( F == 0 ))
