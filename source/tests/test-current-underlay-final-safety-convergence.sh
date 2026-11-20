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
[
  {"ifindex":3,"ifname":"test-wlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500}
]
JSON
cat > "$B2/routes4.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":600,"flags":[]},
  {"dst":"192.0.2.0/24","dev":"test-wlan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.20","metric":600,"flags":[]}
]
JSON
cat > "$B2/routes6.json" <<'JSON'
[
  {"dst":"fe80::/64","dev":"test-wlan0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"}
]
JSON
cat > "$TMP/links-switch.json" <<'JSON'
[
  {"ifindex":8,"ifname":"test-eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500}
]
JSON
cat > "$TMP/routes4-switch.json" <<'JSON'
[
  {"dst":"default","gateway":"198.51.100.1","dev":"test-eth0","protocol":"dhcp","prefsrc":"198.51.100.25","metric":100,"flags":[]},
  {"dst":"198.51.100.0/24","dev":"test-eth0","protocol":"kernel","scope":"link","prefsrc":"198.51.100.25","metric":100,"flags":[]}
]
JSON
cat > "$TMP/routes6-switch.json" <<'JSON'
[
  {"dst":"fe80::/64","dev":"test-eth0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"}
]
JSON
cat > "$TMP/links-offline.json" <<'JSON'
[
  {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536}
]
JSON
printf '%s\n' '[]' > "$TMP/routes4-none.json"
printf '%s\n' '[]' > "$TMP/routes6-none.json"
cat > "$TMP/links-multiple.json" <<'JSON'
[
  {"ifindex":3,"ifname":"test-wlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500},
  {"ifindex":8,"ifname":"test-eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500}
]
JSON
cat > "$TMP/routes4-multiple.json" <<'JSON'
[
  {"dst":"default","gateway":"192.0.2.1","dev":"test-wlan0","protocol":"dhcp","prefsrc":"192.0.2.20","metric":600,"flags":[]},
  {"dst":"default","gateway":"198.51.100.1","dev":"test-eth0","protocol":"dhcp","prefsrc":"198.51.100.25","metric":100,"flags":[]}
]
JSON
cat > "$TMP/routes6-default.json" <<'JSON'
[
  {"dst":"default","gateway":"fe80::1","dev":"test-eth0","protocol":"ra","metric":100,"flags":[]},
  {"dst":"fe80::/64","dev":"test-eth0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"}
]
JSON

LIVE_LINKS=$B2/links.json
LIVE_R4=$B2/routes4.json
LIVE_R6=$B2/routes6.json
MANAGED_ROUTES_OK=yes
TRANSITION_OK=yes
mvc24gb2_runtime(){ printf '%s\n' "$B2"; }
mvc24gb1_capture_links(){ cp -- "$LIVE_LINKS" "$1"; }
mvc24gb1_capture_routes4(){ cp -- "$LIVE_R4" "$1"; }
mvc24gb1_capture_routes6(){ cp -- "$LIVE_R6" "$1"; }
mvc24gc23t_managed_routes_absent(){ [[ $MANAGED_ROUTES_OK == yes ]]; }
mvc24gc3_transition_records_valid(){ [[ $TRANSITION_OK == yes ]]; }

mvc24gc23t_reset
if mvc24gc23t_post_session_safety_witness_dir "$B2" yes 2> "$TMP/exact.err" &&
   [[ $MVC24GC23T_TOPOLOGY_DRIFT == no && ! -s $TMP/exact.err ]]; then
  pass 'exact old topology remains a valid final-safety state without warning'
else
  cat "$TMP/exact.err" >&2
  fail 'exact old topology remains a valid final-safety state without warning'
fi

LIVE_LINKS=$TMP/links-switch.json
LIVE_R4=$TMP/routes4-switch.json
LIVE_R6=$TMP/routes6-switch.json
MVC24GC23T_TOPOLOGY_DRIFT_WARNED=no
if mvc24gc23t_post_session_safety_witness_dir "$B2" yes 2> "$TMP/switch.err" &&
   [[ $MVC24GC23T_TOPOLOGY_DRIFT == yes && $MVC24GC23T_CONVERGENCE_DETAIL == safe-current-topology-drift ]] &&
   grep -Fq 'physical-link/IPv4 topology drift' "$TMP/switch.err"; then
  pass 'different interface, address and gateway are warning-only after authenticated teardown'
else
  cat "$TMP/switch.err" >&2
  fail 'different interface, address and gateway are warning-only after authenticated teardown'
fi

LIVE_LINKS=$TMP/links-offline.json
LIVE_R4=$TMP/routes4-none.json
LIVE_R6=$TMP/routes6-none.json
MVC24GC23T_TOPOLOGY_DRIFT_WARNED=no
if mvc24gc23t_post_session_safety_witness_dir "$B2" yes >/dev/null 2> "$TMP/offline.err"; then
  pass 'final safety accepts no IPv4 default when ordinary networking is currently off'
else
  cat "$TMP/offline.err" >&2
  fail 'final safety accepts no IPv4 default when ordinary networking is currently off'
fi

LIVE_LINKS=$TMP/links-multiple.json
LIVE_R4=$TMP/routes4-multiple.json
LIVE_R6=$TMP/routes6-none.json
MVC24GC23T_TOPOLOGY_DRIFT_WARNED=no
if mvc24gc23t_post_session_safety_witness_dir "$B2" yes >/dev/null 2> "$TMP/multiple.err"; then
  pass 'final safety accepts multiple ordinary IPv4 defaults after host topology changed'
else
  cat "$TMP/multiple.err" >&2
  fail 'final safety accepts multiple ordinary IPv4 defaults after host topology changed'
fi

LIVE_R6=$TMP/routes6-default.json
if ! mvc24gc23t_post_session_safety_witness_dir "$B2" yes >/dev/null 2>&1 &&
   [[ $MVC24GC23T_CONVERGENCE_DETAIL == ipv6-safe-baseline-not-proven ]]; then
  pass 'IPv6 default route remains a hard final-safety blocker'
else
  fail 'IPv6 default route remains a hard final-safety blocker'
fi

LIVE_R6=$TMP/routes6-none.json
MANAGED_ROUTES_OK=no
if ! mvc24gc23t_post_session_safety_witness_dir "$B2" yes >/dev/null 2>&1 &&
   [[ $MVC24GC23T_CONVERGENCE_DETAIL == mvc-managed-routes-remain ]]; then
  pass 'MVC-reserved managed routes remain a hard final-safety blocker'
else
  fail 'MVC-reserved managed routes remain a hard final-safety blocker'
fi
MANAGED_ROUTES_OK=yes
TRANSITION_OK=no
if ! mvc24gc23t_post_session_safety_witness_dir "$B2" yes >/dev/null 2>&1 &&
   [[ $MVC24GC23T_CONVERGENCE_DETAIL == topology-session-journal-changed ]]; then
  pass 'combined teardown still requires authenticated transition-journal integrity'
else
  fail 'combined teardown still requires authenticated transition-journal integrity'
fi
TRANSITION_OK=yes

LIVE_LINKS=$TMP/links-switch.json
LIVE_R4=$TMP/routes4-switch.json
LIVE_R6=$TMP/routes6-switch.json
MVC24GC23T_TOPOLOGY_DRIFT_WARNED=no
if mvc24gwg_final_safety_witness >/dev/null 2> "$TMP/wg.err"; then
  pass 'protected standalone WireGuard teardown uses current final-safety policy'
else
  cat "$TMP/wg.err" >&2
  fail 'protected standalone WireGuard teardown uses current final-safety policy'
fi

MVC24GC23T_TOPOLOGY_DRIFT_WARNED=no
if mvc24pube_preclone_safety_witness_dir "$B2" >/dev/null 2> "$TMP/early.err"; then
  pass 'OpenVPN early reconciliation uses current final-safety policy'
else
  cat "$TMP/early.err" >&2
  fail 'OpenVPN early reconciliation uses current final-safety policy'
fi

if ! mvc24gb1_routes_valid test-wlan0 "$TMP/routes4-none.json" "$TMP/routes6-none.json" &&
   ! mvc24gb1_routes_valid test-wlan0 "$TMP/routes4-multiple.json" "$TMP/routes6-none.json"; then
  pass 'connect admission remains strict even though disconnect accepts no or multiple IPv4 defaults'
else
  fail 'connect admission remains strict even though disconnect accepts no or multiple IPv4 defaults'
fi

printf 'RESULT: current-underlay final-safety convergence %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
