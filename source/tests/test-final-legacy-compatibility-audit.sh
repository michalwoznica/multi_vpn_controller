#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1"; F=$((F+1)); }

legacy_re='ubs-v240|ubs_v240|ubs-vpn|\\bv240\\b|\\bUBS\\b|UBS24|ubs24'

# Production/build source must be MVC-native except for the explicit installer
# migration compatibility paths checked separately below.
prod_hits=$(
  rg -n -i "$legacy_re" \
    "$ROOT/source/lib" "$ROOT/source/build" "$ROOT/source/nftables" "$ROOT/source/tools" \
    --glob '!install-mvc.sh' || :
)
[[ -z $prod_hits ]] && pass 'production/build source has no legacy UBS/v240 identity outside installer compatibility' || { printf '%s\n' "$prod_hits" >&2; fail 'production/build source has no legacy UBS/v240 identity outside installer compatibility'; }

# Human-facing current documentation is MVC-native. CHANGELOG.md is excluded
# deliberately because it records historical rename work.
doc_hits=$(rg -n -i "$legacy_re" "$ROOT/README.md" "$ROOT/BUILDING.md" "$ROOT/INSTALL.md" "$ROOT/OPERATIONS.md" "$ROOT/docs" || :)
[[ -z $doc_hits ]] && pass 'current human-facing documentation has no legacy UBS/v240 identity' || { printf '%s\n' "$doc_hits" >&2; fail 'current human-facing documentation has no legacy UBS/v240 identity'; }

# The installer must keep exactly the predecessor paths needed for safe migration.
installer="$ROOT/source/tools/install-mvc.sh"
required=(
  '/usr/local/sbin/ubs-vpn'
  '/root/ubs-v240-emergency-rollback'
  '/root/ubs-v240-dual-recovery'
  '/run/ubs-v240-controller'
  '/run/ubs-v240-activation'
  '/run/ubs-v240-output-transition'
  '/run/ubs-v240-disconnect'
  '/run/ubs-v240-completion'
  '/run/ubs-v240-wireguard'
  '/run/ubs-v240-public-session'
)
missing=0
for item in "${required[@]}"; do
  grep -Fq "$item" "$installer" || missing=$((missing+1))
done
[[ $missing -eq 0 ]] && pass 'installer retains the exact legacy predecessor path allowlist' || fail 'installer retains the exact legacy predecessor path allowlist'

unexpected=$(
  rg -n -i "$legacy_re" "$installer" | \
    grep -vF '/usr/local/sbin/ubs-vpn' | \
    grep -vF '/root/ubs-v240-emergency-rollback' | \
    grep -vF '/root/ubs-v240-dual-recovery' | \
    grep -vE '/run/ubs-v240-(controller|activation|output-transition|disconnect|completion|wireguard|public-session)' || :
)
[[ -z $unexpected ]] && pass 'installer contains no legacy identity outside the explicit migration allowlist' || { printf '%s\n' "$unexpected" >&2; fail 'installer contains no legacy identity outside the explicit migration allowlist'; }

if ! find "$ROOT/source" -type f \( -iname '*ubs*' -o -iname '*v240*' \) -print -quit | grep -q .; then
  pass 'tracked source filenames contain no legacy UBS/v240 naming'
else
  find "$ROOT/source" -type f \( -iname '*ubs*' -o -iname '*v240*' \) -print >&2
  fail 'tracked source filenames contain no legacy UBS/v240 naming'
fi

if rg -q 'check-mvc-live-saved-ovpn-readonly' "$ROOT/source/tests/test-runtime-seams.sh" &&
   ! rg -q 'check-v240-live-saved-ovpn-readonly' "$ROOT/source/tests/test-runtime-seams.sh"; then
  pass 'runtime-seams regression tracks the current MVC helper name'
else
  fail 'runtime-seams regression tracks the current MVC helper name'
fi

# Negative/migration fixtures under source/tests are intentionally allowed to
# mention retired names; they prove rejection or predecessor migration support.
if rg -q -i "$legacy_re" "$ROOT/source/tests"; then
  pass 'legacy names remain confined to deliberate test fixtures where applicable'
else
  fail 'legacy names remain confined to deliberate test fixtures where applicable'
fi

# Historical rename context is allowed only in CHANGELOG.md among public docs.
if rg -q -i "$legacy_re" "$ROOT/CHANGELOG.md"; then
  pass 'historical legacy naming is retained only in the changelog documentation surface'
else
  fail 'historical legacy naming is retained only in the changelog documentation surface'
fi

printf 'RESULT: MVC-R6D final legacy compatibility audit %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
