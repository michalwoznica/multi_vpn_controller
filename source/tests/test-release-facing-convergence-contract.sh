#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
PROJECT=$(cd -- "$SOURCE/.." && pwd -P)

pass=0
fail=0
ok() { printf 'PASS: %s\n' "$1"; pass=$((pass+1)); }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=$((fail+1)); }

entry=$SOURCE/lib/combined-controller-entry.sh
disc=$SOURCE/lib/combined-operational-public-disconnect.sh

if ! grep -Fq 'SAME-BOOT FRESH SESSION ELIGIBLE' "$entry"; then
    ok 'disconnect success text does not overclaim fresh admission eligibility'
else
    bad 'disconnect success text does not overclaim fresh admission eligibility'
fi

if grep -Fq 'MVC OWNED STATE RETIRED' "$entry"; then
    ok 'disconnect success text reports owned-state retirement'
else
    bad 'disconnect success text reports owned-state retirement'
fi

if grep -Fq 'normal convergence could not prove a safe final state' "$entry"; then
    ok 'disconnect failure text describes convergence failure'
else
    bad 'disconnect failure text describes convergence failure'
fi

if ! grep -Fq 'emergency B4 disarm can be followed by one authenticated `mvc disconnect`' "$disc"; then
    ok 'production source no longer documents obsolete post-emergency finalizer'
else
    bad 'production source no longer documents obsolete post-emergency finalizer'
fi

if grep -Fq 'current topology will pass a new `connect`' "$PROJECT/OPERATIONS.md" && \
   grep -Fq 'normal strict admission checks again' "$PROJECT/OPERATIONS.md"; then
    ok 'operations separates disconnect success from fresh-connect admission'
else
    bad 'operations separates disconnect success from fresh-connect admission'
fi

if ! grep -Fq 'restoration of the original network state after disconnect' "$PROJECT/README.md"; then
    ok 'README no longer promises original physical topology restoration'
else
    bad 'README no longer promises original physical topology restoration'
fi

if grep -Fq 'clean MVC-free final state' "$PROJECT/docs/RELEASING.md"; then
    ok 'release validation uses MVC-free final-state semantics'
else
    bad 'release validation uses MVC-free final-state semantics'
fi

if (( fail != 0 )); then
    printf 'RESULT: release-facing convergence contract %d passed, %d failed\n' "$pass" "$fail" >&2
    exit 1
fi
printf 'RESULT: release-facing convergence contract %d/%d checks passed\n' "$pass" "$pass"
