#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
export MVC24E_CODE_ROOT=$ROOT
source lib/combined-operational-public-composition.sh

P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
B2=$TMP/b2
mkdir -m 700 -- "$B2"
printf '[]\n' > "$B2/links.json"
printf '[]\n' > "$B2/routes4.json"
printf '[]\n' > "$B2/routes6.json"

# 1. Split teardown delegates final topology policy to the shared post-session
# safety witness rather than reconstructing the original Internet route.
CALLS=()
mvc24gb2_runtime(){ printf '%s\n' "$B2"; }
mvc24gc23t_post_session_safety_witness_dir(){ CALLS+=("$1:$2"); return 0; }
if mvc24gws_final_safety_witness && [[ ${CALLS[*]} == "$B2:no" ]]; then
  pass 'split final-safety witness delegates to shared current-topology policy'
else
  fail 'split final-safety witness delegates to shared current-topology policy'
fi

# 2. Once MVC-owned split-WG network residue is absent, retirement remains
# eligible even if the original-underlay Internet route is no longer true.
CALLS=()
mvc24gwg_temp_profile_inventory_absent(){ CALLS+=(profile-absent); return 0; }
ip(){
  case " $* " in
    *" -4 route show table all proto 186 "*|*" -4 route show table all proto 187 "*) return 0 ;;
    *" link show dev vpnks-wg "*) return 1 ;;
    *) return 1 ;;
  esac
}
wg(){ return 1; }
mvc24gws_no_b4_tables(){ CALLS+=(no-b4); return 0; }
mvc24gws_final_safety_witness(){ CALLS+=(final-safety); return 0; }
mvc24gws_internet_route_observed(){ CALLS+=(legacy-original-route); return 1; }
MVC24GD4_TEMP_NAME=vpnks-wg
if mvc24gws_network_clean_retirement_pending_observed &&
   [[ ${CALLS[*]} == 'profile-absent no-b4 final-safety' ]]; then
  pass 'split runtime retirement ignores original-underlay route after owned cleanup'
else
  fail 'split runtime retirement ignores original-underlay route after owned cleanup'
fi

# 3. The shared final-safety decision remains authoritative: a safety failure
# must still block retirement.
CALLS=()
mvc24gwg_temp_profile_inventory_absent(){ return 0; }
mvc24gws_no_b4_tables(){ CALLS+=(no-b4); return 0; }
mvc24gws_final_safety_witness(){ CALLS+=(final-safety-blocked); return 1; }
if ! mvc24gws_network_clean_retirement_pending_observed &&
   [[ ${CALLS[*]} == 'no-b4 final-safety-blocked' ]]; then
  pass 'split runtime retirement still fails closed on final-safety rejection'
else
  fail 'split runtime retirement still fails closed on final-safety rejection'
fi

# 4. Split mode remains unprotected by B4 during normal operation, so an
# unexpected B4 presence/observation failure still blocks retirement before
# final topology acceptance.
CALLS=()
mvc24gws_no_b4_tables(){ CALLS+=(b4-blocked); return 1; }
mvc24gws_final_safety_witness(){ CALLS+=(unexpected-final-safety); return 0; }
if ! mvc24gws_network_clean_retirement_pending_observed &&
   [[ ${CALLS[*]} == 'b4-blocked' ]]; then
  pass 'unexpected B4 state still blocks split runtime retirement'
else
  fail 'unexpected B4 state still blocks split runtime retirement'
fi

# 5. Connect-time/active-state verification remains strict and still requires
# the admitted original-underlay Internet route.  R8 changes teardown only.
body=$(awk '
  /^mvc24gws_active_observed\(\)/ {inside=1}
  inside {print}
  inside && /^}/ {exit}
' lib/combined-operational-wireguard-split.sh)
[[ $body == *'mvc24gws_internet_route_observed'* ]] &&
  pass 'split connect active-state observation still requires admitted Internet route' ||
  fail 'split connect active-state observation still requires admitted Internet route'

# 6. Retirement code must not regain a hidden dependency on the original
# route helper in future edits.
body=$(awk '
  /^mvc24gws_network_clean_retirement_pending_observed\(\)/ {inside=1}
  inside {print}
  inside && /^}/ {exit}
' lib/combined-operational-wireguard-split.sh)
[[ $body == *'mvc24gws_final_safety_witness'* && $body != *'mvc24gws_internet_route_observed'* ]] &&
  pass 'split retirement source has no original-route dependency' ||
  fail 'split retirement source has no original-route dependency'

printf 'RESULT: split WireGuard final-safety convergence %d/%d checks passed\n' "$P" "$P"
