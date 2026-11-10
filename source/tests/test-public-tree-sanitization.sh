#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)

fail=0
pass() { printf 'PASS: %s\n' "$1"; }
fail_msg() { printf 'FAIL: %s\n' "$1" >&2; fail=$((fail + 1)); }

# Public releases deliberately keep generated artifacts and private development
# continuity outside Git. Verify those repository boundaries remain explicit.
if grep -Fxq '/.handoff/' "$ROOT/.gitignore"; then
    pass '.handoff is ignored by Git'
else
    fail_msg '.handoff ignore rule missing'
fi

if grep -Fxq '/dist/' "$ROOT/.gitignore"; then
    pass 'dist is ignored by Git'
else
    fail_msg 'dist ignore rule missing'
fi

# Agent/checkpoint-only documents belong under .handoff, never in the public
# project tree. This test intentionally uses only generic filenames; exact
# private environment identifiers are checked by the ignored handoff audit.
leaked=0
while IFS= read -r path; do
    printf 'LEAKED PRIVATE-DEVELOPMENT FILE: %s\n' "$path" >&2
    leaked=1
done < <(find "$ROOT" \
    -path "$ROOT/.handoff" -prune -o \
    -path "$ROOT/dist" -prune -o \
    -type f \( \
      -name 'README_START_HERE.md' -o \
      -name 'HANDOFF.md' -o \
      -name 'COLD_ARCHIVE_REFERENCE.md' -o \
      -name 'PRUNING_SUMMARY.md' -o \
      -name 'SHA256_MANIFEST.txt' \
    \) -print)

if (( leaked == 0 )); then
    pass 'agent/checkpoint files absent from public tree'
else
    fail_msg 'agent/checkpoint files found in public tree'
fi

# Actual secret material must never be present in tracked public files.
secret_tmp=$(mktemp)
trap 'rm -f "$secret_tmp"' EXIT
if grep -RInE --binary-files=without-match \
    --exclude-dir=.git --exclude-dir=.handoff --exclude-dir=dist \
    -- 'BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY' "$ROOT" >"$secret_tmp" 2>/dev/null; then
    cat "$secret_tmp" >&2
    fail_msg 'private-key PEM material found in public tree'
else
    pass 'no private-key PEM material in public tree'
fi

if (( fail != 0 )); then
    printf 'RESULT: public-tree sanitization FAILED (%d findings)\n' "$fail" >&2
    exit 1
fi

echo 'RESULT: public-tree sanitization PASS'
