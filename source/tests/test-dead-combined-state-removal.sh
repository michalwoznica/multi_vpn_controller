#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }
DUAL=$ROOT/source/lib/dual-session.sh

if ! rg -Fq 'mvc24_write_combined_state()' "$DUAL"; then pass 'dead combined-state writer remains removed'; else fail 'dead combined-state writer remains removed'; fi
if ! rg -Fq 'mvc24_read_combined_state()' "$DUAL"; then pass 'dead combined-state reader remains removed'; else fail 'dead combined-state reader remains removed'; fi

# The surrounding active library API must remain present.
for fn in mvc24_parse_command mvc24_validate_profile_types mvc24_valid_uuid mvc24_valid_ip mvc24_valid_port mvc24_valid_endpoint mvc24_normalize_endpoints; do
  if rg -Fq "$fn()" "$DUAL"; then pass "active helper retained: $fn"; else fail "active helper retained: $fn"; fi
done

# No draft combined-state schema should be reintroduced into current production code.
if ! rg -n 'combined-state.*draft|state.*draft.*combined' "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" "$ROOT/source/nftables" >/dev/null; then
  pass 'draft combined-state schema remains absent from production source'
else
  fail 'draft combined-state schema remains absent from production source'
fi

printf 'RESULT: MVC-R6A dead combined-state API removal %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
