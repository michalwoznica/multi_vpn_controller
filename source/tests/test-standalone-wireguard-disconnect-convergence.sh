#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
export MVC24E_CODE_ROOT=$ROOT
source lib/combined-operational-public-composition.sh

P=0
pass(){ P=$((P+1)); printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }

MVC24GD4_TEMP_NAME=vpnks-wg
MVC24GD4_TEMP_UUID=11111111-2222-4333-8444-555555555555
MVC24GD4_TEMP_FILE=/tmp/mvc-test-no-keyfile
MVC24GD4_ENDPOINT_IP=198.51.100.10
MVC24GD4_ENDPOINT_PORT=51820
MVC24GD4_UNDERLAY=test-wlan0
MVC24GD4_UNDERLAY_SOURCE=192.0.2.10
MVC24GD4_UNDERLAY_GATEWAY=192.0.2.1

# 1. Fully missing authenticated WG residue is already-clean and succeeds.
nmcli(){
    case " $* " in
      *" connection down "*|*" connection delete "*) return 99 ;;
      *) return 0 ;;
    esac
}
ip(){
    case " $* " in
      *" link show dev vpnks-wg "*) return 1 ;;
      *" -j -N -4 route show table all proto 186 "*) printf '[]\n'; return 0 ;;
      *" -j -N -4 route show exact "*) printf '[]\n'; return 0 ;;
      *" -4 route show table all proto 186 "*) return 0 ;;
      *" link delete "*) return 99 ;;
      *) return 0 ;;
    esac
}
wg(){ return 1; }
rm -f -- "$MVC24GD4_TEMP_FILE"
mvc24gwg_converge_owned_network_once && pass already-absent-standalone-wg-residue-is-clean-poststate || fail absent-residue

# 2. A conflicting profile that merely reuses the authenticated UUID/name is
# foreign/ambiguous and must be refused before cleanup mutation.
nmcli(){
    case " $* " in
      *" -f NAME,UUID,TYPE connection show "*) printf 'vpnks-wg:%s:ethernet\n' "$MVC24GD4_TEMP_UUID"; return 0 ;;
      *" connection down "*|*" connection delete "*) printf 'unexpected mutation\n' >&2; return 99 ;;
      *) return 0 ;;
    esac
}
! mvc24gwg_converge_owned_network_once && pass conflicting-profile-identity-remains-fatal || fail conflicting-profile

# 3. An unexpected proto-186 route cannot be treated as already absent.
nmcli(){ return 0; }
ip(){
    case " $* " in
      *" link show dev vpnks-wg "*) return 1 ;;
      *" -j -N -4 route show table all proto 186 "*) printf '[{"dst":"203.0.113.9","protocol":"186"}]\n'; return 0 ;;
      *) return 0 ;;
    esac
}
wg(){ return 1; }
mvc24gd4_endpoint_route_observed(){ return 1; }
! mvc24gwg_converge_owned_network_once && pass foreign-proto186-route-remains-fatal || fail foreign-route

# 4. Protected WG stop always enters the convergence engine after authority and
# guard authentication; it does not require the old fully-active observation.
LOG=()
mvc24gwg_authority_witness(){ LOG+=(authority); return 0; }
mvc24gwg_guard_exact_now(){ LOG+=(guard); return 0; }
mvc24gwg_owned_tables_absent_now(){ return 1; }
mvc24gwg_converge_owned_network_once(){ LOG+=(converge); return 0; }
mvc24gwg_release_guard_once(){ LOG+=(release); return 0; }
mvc24gwg_retire_runtime_once(){ LOG+=(retire); return 0; }
mvc24gwg_active_observed(){ LOG+=(legacy-active-shape); return 1; }
mvc24gwg_stop_once || fail protected-stop-convergence
[[ ${LOG[*]} == 'authority guard converge release retire' ]] && pass protected-stop-uses-convergence-not-active-shape || fail protected-order

# 5. Ambiguous protected guard state remains fatal before owned cleanup.
LOG=()
mvc24gwg_authority_witness(){ LOG+=(authority); return 0; }
mvc24gwg_guard_exact_now(){ LOG+=(guard-exact-no); return 1; }
mvc24gwg_owned_tables_absent_now(){ LOG+=(guard-absent-no); return 1; }
mvc24gwg_converge_owned_network_once(){ LOG+=(unexpected-mutation); return 0; }
! mvc24gwg_stop_once && [[ ${LOG[*]} == 'authority guard-exact-no guard-absent-no' ]] &&
  pass protected-ambiguous-guard-blocks-before-cleanup || fail protected-guard-refusal

# 6. Split WG stop likewise converges owned residue directly and never requires
# the old active observation.
LOG=()
mvc24gws_authority_witness(){ LOG+=(authority); return 0; }
mvc24gws_no_b4_tables(){ LOG+=(no-b4); return 0; }
mvc24gwg_converge_owned_network_once(){ LOG+=(converge); return 0; }
mvc24gws_retire_runtime_once(){ LOG+=(retire); return 0; }
mvc24gws_active_observed(){ LOG+=(legacy-active-shape); return 1; }
mvc24gws_stop_once || fail split-stop-convergence
[[ ${LOG[*]} == 'authority no-b4 converge retire' ]] && pass split-stop-uses-convergence-not-active-shape || fail split-order

# 7. Public published-session dispatch no longer enumerates active-vs-clean
# standalone WG shapes before calling the convergence-aware stop routines.
body=$(awk '
  /MVC24PUBD_TRANSACTION_STATE:-none.*== wireguard-split / {inside=1}
  inside {print}
  inside && /public-wireguard-split-session-complete-sameboot-ready/ {exit}
' lib/combined-operational-public-disconnect.sh)
[[ $body == *'mvc24gws_stop_once'* && $body != *'mvc24gws_active_observed'* && $body != *'mvc24gws_network_clean_retirement_pending_observed'* ]] &&
  pass split-public-dispatch-no-longer-enumerates-transitional-shapes || fail split-dispatch-shapes

body=$(awk '
  /MVC24PUBD_TRANSACTION_STATE:-none.*== wireguard-protected / {inside=1}
  inside {print}
  inside && /public-wireguard-protected-session-complete-sameboot-ready/ {exit}
' lib/combined-operational-public-disconnect.sh)
[[ $body == *'mvc24gwg_stop_once'* && $body != *'mvc24gwg_active_observed'* && $body != *'mvc24gwg_network_clean_retirement_pending_observed'* ]] &&
  pass protected-public-dispatch-no-longer-enumerates-transitional-shapes || fail protected-dispatch-shapes

printf 'Results: %d passed, 0 failed\n' "$P"
