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

MVC24GC23T_STAGE=post-stop-safety-not-converged
MVC24GC23T_CONVERGENCE_DETAIL=ipv6-safe-baseline-not-proven
mvc24pubd_record_completion_failure
if [[ $MVC24PUBD_STAGE == session-completion-failed-post-stop-safety-not-converged &&
      $MVC24PUBD_COMPLETION_DETAIL == ipv6-safe-baseline-not-proven ]]; then
  pass 'public disconnect retains fixed final-safety detail without changing stage'
else
  fail 'public disconnect retains fixed final-safety detail without changing stage'
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
   [[ $MVC24GC23T_STAGE == post-stop-safety-not-converged &&
      $MVC24GC23T_CONVERGENCE_DETAIL == ipv6-safe-baseline-not-proven ]]; then
  pass 'bounded final-safety convergence retries only the IPv6 safety condition'
else
  fail 'bounded final-safety convergence retries only the IPv6 safety condition'
fi

count=0
mvc24gc23t_c1_witness_once(){ count=$((count+1)); MVC24GC23T_CONVERGENCE_DETAIL=topology-session-journal-changed; return 1; }
MVC24GC23T_STAGE=unverified
if ! mvc24gc23t_c1_witness && (( count == 1 )) && [[ $MVC24GC23T_STAGE == unverified ]]; then
  pass 'journal-integrity failure is fatal and is not converted into a convergence retry'
else
  fail 'journal-integrity failure is fatal and is not converted into a convergence retry'
fi

if ! grep -Fq 'mvc24gc23t_routes4_nm_connectivity_penalty_equivalent' "$ROOT/source/lib/combined-operational-c23t-session-finalize.sh" &&
   ! grep -Eq 'links-not-restored|routes4-not-restored' "$ROOT/source/lib/combined-operational-c23t-session-finalize.sh"; then
  pass 'teardown no longer carries exact old-link/IPv4 restoration policy'
else
  fail 'teardown no longer carries exact old-link/IPv4 restoration policy'
fi

mvc24_parse_command(){ return 0; }
mvc24pub_process_initialize(){ return 0; }
mvc24e_c23aw_live_ready(){ return 0; }
mvc24pubd_disconnect_once(){
  MVC24PUBD_STAGE=session-completion-failed-post-stop-safety-not-converged
  MVC24PUBD_COMPLETION_DETAIL=mvc-managed-routes-remain
  return 1
}
set +e
mvc24e_dispatch disconnect 2> "$TMP/completion.err"
rc=$?
set -e
if (( rc == 1 )) && grep -Fq 'completion detail: mvc-managed-routes-remain' "$TMP/completion.err"; then
  pass 'public disconnect error reports fixed final-safety detail'
else
  cat "$TMP/completion.err" >&2
  fail 'public disconnect error reports fixed final-safety detail'
fi

mvc24pubd_disconnect_once(){
  MVC24PUBD_STAGE=active-session-reconstruction-refused
  MVC24PUBD_COMPLETION_DETAIL=ipv6-safe-baseline-not-proven
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
