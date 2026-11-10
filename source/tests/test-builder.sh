#!/usr/bin/env bash
# C23BN Stage 2 — deterministic monolith builder contract.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
MANIFEST=$ROOT/source/build/monolith-runtime.manifest
PASS=0
FAIL=0

ok() { printf 'PASS: %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL + 1)); }
need() { "$@" && ok "$*" || bad "$*"; }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/a" "$TMP/b" "$TMP/resources"

"$BUILDER" "$TMP/a/mvc" >/dev/null
"$BUILDER" "$TMP/b/mvc" >/dev/null
A=$TMP/a/mvc
B=$TMP/b/mvc

if cmp -s -- "$A" "$B"; then ok 'independent builds are byte-identical'; else bad 'independent builds are byte-identical'; fi
sha_a=$(sha256sum -- "$A" | awk '{print $1}')
sha_b=$(sha256sum -- "$B" | awk '{print $1}')
if [[ $sha_a == "$sha_b" ]]; then ok 'independent build SHA-256 values are identical'; else bad 'independent build SHA-256 values are identical'; fi
if [[ $(stat -c %a -- "$A") == 755 ]]; then ok 'generated artifact mode is 0755'; else bad 'generated artifact mode is 0755'; fi
if bash -n "$A"; then ok 'generated artifact passes bash -n'; else bad 'generated artifact passes bash -n'; fi

if [[ $($A version) == 'Multi VPN Controller 2.4.1' ]]; then ok 'generated version identity is exact'; else bad 'generated version identity is exact'; fi
if $A --help | grep -Fq 'public identity release candidate'; then ok 'current generated help identifies v2.4.1 candidate'; else bad 'current generated help identifies v2.4.1 candidate'; fi
info=$($A --monolith-build-info)
manifest_sha=$(sha256sum -- "$MANIFEST" | awk '{print $1}')
builder_sha=$(sha256sum -- "$BUILDER" | awk '{print $1}')
if grep -Fxq "checkpoint=MVC_R6C_RUNTIME_MODULE_FILENAMES" <<< "$info" &&
   grep -Fxq "manifest_sha256=$manifest_sha" <<< "$info" &&
   grep -Fxq "builder_sha256=$builder_sha" <<< "$info"; then
    ok 'build-info provenance matches source manifest and builder'
else
    bad 'build-info provenance matches source manifest and builder'
fi

if grep -Fq 'preflight|list|status|connect|disconnect)' "$A" &&
   grep -Fq 'mvc24e_dispatch "$@"' "$A" &&
   ! grep -Fq 'mvc24mon_stage3b_refuse_lifecycle' "$A"; then
    ok 'v2.4.1 wrapper promotes lifecycle only through audited dispatcher'
else
    bad 'v2.4.1 wrapper promotes lifecycle only through audited dispatcher'
fi

$A --monolith-resource-selftest "$TMP/resources" >"$TMP/resources.out"
if cmp -s -- "$TMP/resources/gvariant-settings-to-json.awk" "$ROOT/source/lib/combined-gvariant-settings-to-json.awk"; then
    ok 'embedded GVariant AWK resource is byte-identical'
else
    bad 'embedded GVariant AWK resource is byte-identical'
fi
if cmp -s -- "$TMP/resources/preclone-quarantine.nft" "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft"; then
    ok 'embedded B4 nft resource is byte-identical'
else
    bad 'embedded B4 nft resource is byte-identical'
fi
if [[ $(stat -c %a -- "$TMP/resources/gvariant-settings-to-json.awk") == 600 &&
      $(stat -c %a -- "$TMP/resources/preclone-quarantine.nft") == 600 ]]; then
    ok 'materialized embedded resources are mode 0600'
else
    bad 'materialized embedded resources are mode 0600'
fi

module_starts=$(grep -c '^# >>> BEGIN MODULE [0-9][0-9][0-9]:' "$A")
if [[ $module_starts == 49 ]]; then ok 'generated artifact contains exactly 49 ordered module sections'; else bad 'generated artifact contains exactly 49 ordered module sections'; fi
if grep -Fq '# >>> BEGIN MONOLITH COMPOSITION GLUE' "$A" &&
   grep -Fq 'mvc24pub_process_initialize()' "$A" &&
   grep -Fq 'mvc24pub_session_runtime_root()' "$A"; then
    ok 'runtime-only composition glue is present'
else
    bad 'runtime-only composition glue is present'
fi
if ! grep -Fq 'mvc24pub_source_module()' "$A" && ! grep -Fq 'mvc24pub_openvpn_manifest_before_final()' "$A"; then
    ok 'loader-only dynamic source-loop functions are absent'
else
    bad 'loader-only dynamic source-loop functions are absent'
fi
line48=$(grep -n '^# >>> BEGIN MODULE 048:' "$A" | cut -d: -f1)
lineglue=$(grep -n '^# >>> BEGIN MONOLITH COMPOSITION GLUE' "$A" | cut -d: -f1)
line49=$(grep -n '^# >>> BEGIN MODULE 049:' "$A" | cut -d: -f1)
if [[ $line48 =~ ^[0-9]+$ && $lineglue =~ ^[0-9]+$ && $line49 =~ ^[0-9]+$ && $line48 -lt $lineglue && $lineglue -lt $line49 ]]; then
    ok 'composition glue is positioned between modules 048 and 049'
else
    bad 'composition glue is positioned between modules 048 and 049'
fi

# Builder rejection tests use one private copied tree so the authoritative tree
# is never modified. Each case restores its mutation before the next one.
COPY=$TMP/project-copy
cp -a -- "$ROOT" "$COPY"
CB=$COPY/source/build/build-mvc-monolith.sh
CM=$COPY/source/build/monolith-runtime.manifest
ORIG_MANIFEST=$TMP/original.manifest
cp -- "$CM" "$ORIG_MANIFEST"
expect_build_failure() {
    local label=$1
    set +e
    "$CB" "$TMP/rejected-$PASS" >"$TMP/reject.stdout" 2>"$TMP/reject.stderr"
    local rr=$?
    set -e
    if (( rr != 0 )); then ok "$label"; else bad "$label"; fi
}

# Unexpected kind.
sed '0,/^ASSET|/{s/^ASSET|/BOGUS|/}' "$ORIG_MANIFEST" > "$CM"
expect_build_failure 'builder rejects an unexpected manifest kind'
cp -- "$ORIG_MANIFEST" "$CM"

# Duplicate/reordered MODULE slot.
sed 's/^MODULE|002|/MODULE|001|/' "$ORIG_MANIFEST" > "$CM"
expect_build_failure 'builder rejects duplicate/reordered MODULE slots'
cp -- "$ORIG_MANIFEST" "$CM"

# Missing declared input.
asset=$COPY/source/lib/combined-gvariant-settings-to-json.awk
mv -- "$asset" "$asset.missing"
expect_build_failure 'builder rejects a missing declared input'
mv -- "$asset.missing" "$asset"

# Symlinked declared input.
mv -- "$asset" "$asset.real"
ln -s -- combined-gvariant-settings-to-json.awk.real "$asset"
expect_build_failure 'builder rejects a symlinked declared input'
rm -- "$asset"
mv -- "$asset.real" "$asset"

# Hash mismatch.
printf '\n# deliberate test drift\n' >> "$asset"
expect_build_failure 'builder rejects a declared-input SHA mismatch'

printf 'RESULT: C23BN deterministic monolith builder regression %d/%d checks passed\n' "$PASS" "$((PASS + FAIL))"
(( FAIL == 0 ))
