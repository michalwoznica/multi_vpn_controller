#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }
TMP=$(mktemp -d); trap 'rm -rf -- "$TMP"' EXIT

source "$ROOT/source/lib/combined-operational-c23t-session-finalize.sh"
source "$ROOT/source/lib/combined-operational-public-disconnect.sh"
source "$ROOT/source/lib/combined-controller-entry.sh"

mvc24pubd_reset
if [[ $MVC24PUBD_COMPLETION_DETAIL == unverified ]]; then
  pass 'disconnect diagnostic detail resets to unverified'
else
  fail 'disconnect diagnostic detail resets to unverified'
fi

MVC24GC23T_STAGE=post-stop-b2-topology-not-converged
MVC24GC23T_CONVERGENCE_DETAIL=routes4-not-restored
mvc24pubd_record_completion_failure
if [[ $MVC24PUBD_STAGE == session-completion-failed-post-stop-b2-topology-not-converged &&
      $MVC24PUBD_COMPLETION_DETAIL == routes4-not-restored ]]; then
  pass 'public disconnect retains fixed C23T topology detail without changing stage'
else
  fail 'public disconnect retains fixed C23T topology detail without changing stage'
fi

MVC24GC23T_CONVERGENCE_DETAIL='unexpected detail with spaces'
mvc24pubd_record_completion_failure
if [[ $MVC24PUBD_COMPLETION_DETAIL == unverified ]]; then
  pass 'unexpected completion detail is not exposed'
else
  fail 'unexpected completion detail is not exposed'
fi

count=0
mvc24gc23t_c1_witness_once(){ count=$((count+1)); MVC24GC23T_CONVERGENCE_DETAIL=ipv6-safe-baseline-not-proven; return 1; }
mvc24gc23t_convergence_pause(){ return 0; }
MVC24GC23T_STAGE=unverified
if ! mvc24gc23t_c1_witness && (( count == 20 )) &&
   [[ $MVC24GC23T_STAGE == post-stop-b2-topology-not-converged &&
      $MVC24GC23T_CONVERGENCE_DETAIL == ipv6-safe-baseline-not-proven ]]; then
  pass 'bounded topology convergence preserves the final mismatch category'
else
  fail 'bounded topology convergence preserves the final mismatch category'
fi

mvc24gb2_derive_iface(){ printf '%s\n' test-wlan0; }
cat > "$TMP/saved.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":600},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":600}
]
JSON
cat > "$TMP/penalty.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":20600},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":600}
]
JSON
if mvc24gc23t_routes4_nm_connectivity_penalty_equivalent "$TMP/saved.json" "$TMP/penalty.json"; then
  pass 'existing B2 equivalence accepts only the observed default-route +20000 penalty'
else
  fail 'existing B2 equivalence accepts only the observed default-route +20000 penalty'
fi

cat > "$TMP/replacement.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.254","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":20600},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":600}
]
JSON
if ! mvc24gc23t_routes4_nm_connectivity_penalty_equivalent "$TMP/saved.json" "$TMP/replacement.json"; then
  pass 'existing B2 equivalence rejects replacement-underlay route identity drift'
else
  fail 'existing B2 equivalence rejects replacement-underlay route identity drift'
fi

cat > "$TMP/two-diffs.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":20600},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":20600}
]
JSON
if ! mvc24gc23t_routes4_nm_connectivity_penalty_equivalent "$TMP/saved.json" "$TMP/two-diffs.json"; then
  pass 'existing B2 equivalence rejects multiple route-object changes'
else
  fail 'existing B2 equivalence rejects multiple route-object changes'
fi

mvc24_parse_command(){ return 0; }
mvc24pub_process_initialize(){ return 0; }
mvc24e_c23aw_live_ready(){ return 0; }
mvc24pubd_disconnect_once(){
  MVC24PUBD_STAGE=session-completion-failed-post-stop-b2-topology-not-converged
  MVC24PUBD_COMPLETION_DETAIL=links-not-restored
  return 1
}
set +e
mvc24e_dispatch disconnect 2> "$TMP/completion.err"
rc=$?
set -e
if (( rc == 1 )) && grep -Fq 'completion detail: links-not-restored' "$TMP/completion.err"; then
  pass 'public disconnect error reports fixed convergence detail'
else
  cat "$TMP/completion.err" >&2
  fail 'public disconnect error reports fixed convergence detail'
fi

mvc24pubd_disconnect_once(){
  MVC24PUBD_STAGE=active-session-reconstruction-refused
  MVC24PUBD_COMPLETION_DETAIL=routes4-not-restored
  return 1
}
set +e
mvc24e_dispatch disconnect 2> "$TMP/other.err"
rc=$?
set -e
if (( rc == 1 )) && ! grep -Fq 'completion detail:' "$TMP/other.err"; then
  pass 'non-completion disconnect errors do not expose stale convergence detail'
else
  cat "$TMP/other.err" >&2
  fail 'non-completion disconnect errors do not expose stale convergence detail'
fi

printf 'RESULT: underlay-replacement convergence diagnostics %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
