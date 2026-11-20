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
B2=$TMP/b2
mkdir -m 700 -- "$B2"

source "$ROOT/source/lib/combined-operational-host-guard-plan.sh"
source "$ROOT/source/lib/combined-operational-c23t-session-finalize.sh"
source "$ROOT/source/lib/combined-operational-wireguard-protected.sh"
source "$ROOT/source/lib/combined-operational-public-openvpn-early-reconcile.sh"

cat > "$B2/links.json" <<'JSON'
[{"ifindex":3,"ifname":"test-wlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500}]
JSON
cat > "$B2/routes4.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":600,"flags":[]},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":600,"flags":[]}
]
JSON
cat > "$B2/routes6.json" <<'JSON'
[
  {"dst":"fe80::/64","dev":"test-wlan0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"},
  {"type":"local","dst":"fe80::1111","dev":"test-wlan0","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"},
  {"type":"multicast","dst":"ff00::/8","dev":"test-wlan0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}
]
JSON
cat > "$TMP/routes6-regenerated.json" <<'JSON'
[
  {"dst":"fe80::/64","dev":"test-wlan0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"},
  {"type":"local","dst":"fe80::2222","dev":"test-wlan0","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"},
  {"type":"multicast","dst":"ff00::/8","dev":"test-wlan0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}
]
JSON
cat > "$TMP/routes6-default.json" <<'JSON'
[
  {"dst":"default","gateway":"fe80::1","dev":"test-wlan0","protocol":"ra","metric":600,"flags":[]},
  {"dst":"fe80::/64","dev":"test-wlan0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"}
]
JSON

if mvc24gb1_routes6_no_default "$TMP/routes6-regenerated.json"; then
  pass 'shared IPv6 safety invariant accepts regenerated link-local topology with no default route'
else
  fail 'shared IPv6 safety invariant accepts regenerated link-local topology with no default route'
fi
if ! mvc24gb1_routes6_no_default "$TMP/routes6-default.json"; then
  pass 'shared IPv6 safety invariant rejects an IPv6 default route'
else
  fail 'shared IPv6 safety invariant rejects an IPv6 default route'
fi
if mvc24gb1_routes_valid test-wlan0 "$B2/routes4.json" "$TMP/routes6-regenerated.json"; then
  pass 'B1 admission uses the same no-IPv6-default safety invariant'
else
  fail 'B1 admission uses the same no-IPv6-default safety invariant'
fi
if ! mvc24gb1_routes_valid test-wlan0 "$B2/routes4.json" "$TMP/routes6-default.json"; then
  pass 'B1 admission still rejects an IPv6 default route'
else
  fail 'B1 admission still rejects an IPv6 default route'
fi

LIVE_R6=$TMP/routes6-regenerated.json
mvc24gb2_runtime(){ printf '%s\n' "$B2"; }
mvc24gb2_derive_iface(){ printf '%s\n' test-wlan0; }
mvc24gb1_capture_links(){ cp -- "$B2/links.json" "$1"; }
mvc24gb1_capture_routes4(){ cp -- "$B2/routes4.json" "$1"; }
mvc24gb1_capture_routes6(){ cp -- "$LIVE_R6" "$1"; }

if mvc24gwg_final_safety_witness; then
  pass 'protected WireGuard teardown accepts changed IPv6 topology when no default route exists'
else
  fail 'protected WireGuard teardown accepts changed IPv6 topology when no default route exists'
fi
LIVE_R6=$TMP/routes6-default.json
if ! mvc24gwg_final_safety_witness; then
  pass 'protected WireGuard teardown remains fail-closed when an IPv6 default route exists'
else
  fail 'protected WireGuard teardown remains fail-closed when an IPv6 default route exists'
fi

LIVE_R6=$TMP/routes6-regenerated.json
if mvc24pube_preclone_safety_witness_dir "$B2"; then
  pass 'OpenVPN early reconciliation accepts changed IPv6 topology when no default route exists'
else
  fail 'OpenVPN early reconciliation accepts changed IPv6 topology when no default route exists'
fi
LIVE_R6=$TMP/routes6-default.json
if ! mvc24pube_preclone_safety_witness_dir "$B2"; then
  pass 'OpenVPN early reconciliation remains fail-closed when an IPv6 default route exists'
else
  fail 'OpenVPN early reconciliation remains fail-closed when an IPv6 default route exists'
fi

if grep -Fq '! cmp -s "$r6" "$dir/routes6.json"' "$ROOT/source/lib/combined-operational-host-guard-transaction.sh" &&
   grep -Fq 'cmp -s "$scratch/routes6.json" "$dir/routes6.json"' "$ROOT/source/lib/combined-operational-c3-held-lifecycle.sh"; then
  pass 'B2 establishment and protected transition still require exact IPv6 snapshot stability'
else
  fail 'B2 establishment and protected transition still require exact IPv6 snapshot stability'
fi

printf 'RESULT: post-session IPv6 safety convergence %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
