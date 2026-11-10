#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }
TMP=$(mktemp -d /tmp/mvc-r5a.XXXXXXXX)
trap 'rm -rf -- "$TMP"' EXIT

OLD=(
  ubs-v240-b2-host-prepare-v1
  ubs-v240-b2-host-commit-attempt-v1
  ubs-v240-c1-transition-attempt-v1
  ubs-v240-c7-openvpn-attempt-v1
  ubs-v240-c13-output-transition-attempt-v1
  ubs-v240-c13-diagnostic-v1
)
NEW=(
  mvc-b2-host-prepare-v1
  mvc-b2-host-commit-attempt-v1
  mvc-c1-transition-attempt-v1
  mvc-c7-openvpn-attempt-v1
  mvc-c13-output-transition-attempt-v1
  mvc-c13-diagnostic-v1
)

# Source-level boundary: all six migrated producer/validator literals exist and old literals are gone from production source.
for sig in "${NEW[@]}"; do
  rg -Fq "$sig" "$ROOT/source/lib" || { fail "new foundation signature present: $sig"; continue; }
done
if ! rg -n 'ubs-v240-(b2-host-(prepare|commit-attempt)|c1-transition-attempt|c7-openvpn-attempt|c13-(output-transition-attempt|diagnostic))-v1' "$ROOT/source/lib" "$ROOT/source/tools" "$ROOT/source/build" "$ROOT/source/nftables" >/dev/null; then
  pass 'six foundation record magics migrated to MVC namespace'
else
  fail 'six foundation record magics migrated to MVC namespace'
fi

# R5A must not silently broaden into later R5 groups.
remaining=$(cd "$ROOT" && rg -o --no-filename \
  'ubs-v24[01]-[A-Za-z0-9._-]+-v[0-9]+|ubs-vpn-state-v4-draft' \
  source/lib source/tools source/build source/nftables | sort -u)
if [[ $remaining == 'ubs-vpn-state-v4-draft' ]]; then
  pass 'only dormant combined-state legacy magic remains frozen'
else
  printf '%s\n' "$remaining" >&2
  fail 'only dormant combined-state legacy magic remains frozen'
fi

boot=$(cat /proc/sys/kernel/random/boot_id)
userns=$(readlink /proc/self/ns/user)
netns=$(readlink /proc/self/ns/net)
mntns=$(readlink /proc/self/ns/mnt)

# B2 reader: new prepare/commit magic accepted; retired magic rejected.
source "$ROOT/source/lib/combined-operational-host-guard-transaction.sh"
b2=$TMP/b2
mkdir -m 700 "$b2"
for f in prestate.json batch.nft links.json routes4.json routes6.json; do printf '%s\n' "$f" > "$b2/$f"; done
mvc24gb2_runtime(){ printf '%s\n' "$b2"; }
mvc24gb2_root_scope(){ return 0; }
mvc24gb2_runtime_shape(){ return 0; }
mvc24gb2_lock_valid(){ return 0; }
mvc24gb1_valid_ifname(){ [[ $1 == test0 ]]; }
mvc24gb2_batch_valid(){ return 0; }
mvc24op_qg_preflight_snapshot(){ return 0; }
mvc24gb2_prestate_netdev_absent(){ return 0; }
mvc24gb1_links_valid(){ return 0; }
mvc24gb1_routes_valid(){ return 0; }
cat > "$b2/prepare-intent" <<B2P
mvc-b2-host-prepare-v1
state=prepared-no-activation
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
underlay=test0
pre=$(sha256sum "$b2/prestate.json" | cut -d' ' -f1)
batch=$(sha256sum "$b2/batch.nft" | cut -d' ' -f1)
links=$(sha256sum "$b2/links.json" | cut -d' ' -f1)
route4=$(sha256sum "$b2/routes4.json" | cut -d' ' -f1)
route6=$(sha256sum "$b2/routes6.json" | cut -d' ' -f1)
B2P
cat > "$b2/commit-attempt" <<B2C
mvc-b2-host-commit-attempt-v1
state=attempted-exactly-once
boot=$boot
prepare=$(sha256sum "$b2/prepare-intent" | cut -d' ' -f1)
B2C
if mvc24gb2_records_valid; then pass 'B2 parser accepts MVC foundation magics'; else fail 'B2 parser accepts MVC foundation magics'; fi
cp "$b2/prepare-intent" "$b2/prepare.good"
sed -i '1s/^mvc-b2-host-prepare-v1$/ubs-v240-b2-host-prepare-v1/' "$b2/prepare-intent"
# commit hash must track the tampered file so rejection is specifically the magic, not digest mismatch.
sed -i "4cprepare=$(sha256sum "$b2/prepare-intent" | cut -d' ' -f1)" "$b2/commit-attempt"
if mvc24gb2_records_valid; then fail 'B2 parser rejects retired prepare magic'; else pass 'B2 parser rejects retired prepare magic'; fi
mv "$b2/prepare.good" "$b2/prepare-intent"
sed -i "4cprepare=$(sha256sum "$b2/prepare-intent" | cut -d' ' -f1)" "$b2/commit-attempt"
cp "$b2/commit-attempt" "$b2/commit.good"
sed -i '1s/^mvc-b2-host-commit-attempt-v1$/ubs-v240-b2-host-commit-attempt-v1/' "$b2/commit-attempt"
if mvc24gb2_records_valid; then fail 'B2 parser rejects retired commit magic'; else pass 'B2 parser rejects retired commit magic'; fi
mv "$b2/commit.good" "$b2/commit-attempt"

# C1/C3 reader: new transition magic accepted and retired magic rejected.
source "$ROOT/source/lib/combined-operational-c1-bootstrap-transition.sh"
source "$ROOT/source/lib/combined-operational-c3-held-lifecycle.sh"
c1=$TMP/c1
mkdir -p "$c1"
printf 'prepare\n' > "$c1/prepare-intent"
printf 'commit\n' > "$c1/commit-attempt"
cat > "$c1/transition.nft" <<'NFT'
line0
line1
line2
add rule inet mvc_preclone_quarantine output_deny oifname "test0" ip saddr 192.0.2.10 ip daddr 198.51.100.20 tcp dport 443 accept
line4
line5
line6
line7
NFT
cat > "$c1/transition-attempt" <<C1
mvc-c1-transition-attempt-v1
state=attempted-once
boot=$boot
prepare=$(sha256sum "$c1/prepare-intent" | cut -d' ' -f1)
commit=$(sha256sum "$c1/commit-attempt" | cut -d' ' -f1)
batch=$(sha256sum "$c1/transition.nft" | cut -d' ' -f1)
C1
mvc24gb2_derive_iface(){ printf '%s\n' test0; }
mvc24gc1_parameters(){ [[ $1 == test0 && $2 == 192.0.2.10 && $3 == 198.51.100.20 && $4 == 443 ]]; }
mvc24gc1_batch_valid(){ return 0; }
if mvc24gc3_transition_payload_valid "$c1"; then pass 'C1 parser accepts MVC transition magic'; else fail 'C1 parser accepts MVC transition magic'; fi
sed -i '1s/^mvc-c1-transition-attempt-v1$/ubs-v240-c1-transition-attempt-v1/' "$c1/transition-attempt"
if mvc24gc3_transition_payload_valid "$c1"; then fail 'C1 parser rejects retired transition magic'; else pass 'C1 parser rejects retired transition magic'; fi
sed -i '1s/^ubs-v240-c1-transition-attempt-v1$/mvc-c1-transition-attempt-v1/' "$c1/transition-attempt"

# C7 reader: new activation magic accepted and retired magic rejected.
source "$ROOT/source/lib/combined-operational-c7-sameboot-activation-reconciliation.sh"
c7=$TMP/c7
mkdir -m 700 "$c7"
printf 'c1-foundation\n' > "$c1/transition-attempt"
source_uuid=11111111-1111-4111-8111-111111111111
clone_uuid=22222222-2222-4222-8222-222222222222
sha1=$(printf source | sha256sum | cut -d' ' -f1)
sha2=$(printf clone | sha256sum | cut -d' ' -f1)
cat > "$c7/attempt" <<C7
mvc-c7-openvpn-attempt-v1
state=attempt-entered-once-activation-uncertain
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
c1=$(sha256sum "$c1/transition-attempt" | cut -d' ' -f1)
source_uuid=$source_uuid
clone_uuid=$clone_uuid
source_sha=$sha1|clone_sha=$sha2
nm_owner=:1.9|123|0
C7
chmod 400 "$c7/attempt"
mvc24gc7_runtime(){ printf '%s\n' "$c7"; }
mvc24gb2_runtime(){ printf '%s\n' "$c1"; }
mvc24gc7_owned_dir(){ [[ $1 == "$c7" ]]; }
mvc24gc7_owned_file(){ [[ $1 == "$c7/attempt" ]]; }
mvc24ga_uuid_valid(){ [[ $1 == "$source_uuid" || $1 == "$clone_uuid" ]]; }
mvc24gc7_nm_owner_valid(){ [[ $1 == ':1.9|123|0' ]]; }
if mvc24gc7_read_intent; then pass 'C7 parser accepts MVC activation magic'; else fail 'C7 parser accepts MVC activation magic'; fi
sed -i '1s/^mvc-c7-openvpn-attempt-v1$/ubs-v240-c7-openvpn-attempt-v1/' "$c7/attempt"
if mvc24gc7_read_intent; then fail 'C7 parser rejects retired activation magic'; else pass 'C7 parser rejects retired activation magic'; fi
sed -i '1s/^ubs-v240-c7-openvpn-attempt-v1$/mvc-c7-openvpn-attempt-v1/' "$c7/attempt"

# C13 uses a deliberately fixed /run root and therefore is not exercised by an
# unprivileged temp-root fixture here. Assert both producer and validator use the
# new magic; an isolated mount-namespace C13 journal test is run during release validation.
c13lib=$ROOT/source/lib/combined-operational-c13-journalled-output-commit.sh
if [[ $(rg -F 'mvc-c13-output-transition-attempt-v1' "$c13lib" | wc -l) -eq 2 ]] &&
   ! rg -Fq 'ubs-v240-c13-output-transition-attempt-v1' "$c13lib"; then
  pass 'C13 producer and validator use MVC output-transition magic'
else
  fail 'C13 producer and validator use MVC output-transition magic'
fi

if rg -Fq 'mvc-c13-diagnostic-v1' "$ROOT/source/lib/combined-operational-c13-journalled-output-commit.sh" &&
   ! rg -Fq 'ubs-v240-c13-diagnostic-v1' "$ROOT/source/lib/combined-operational-c13-journalled-output-commit.sh"; then
  pass 'C13 non-authoritative diagnostic magic uses MVC namespace'
else
  fail 'C13 non-authoritative diagnostic magic uses MVC namespace'
fi

printf 'RESULT: MVC-R5A foundation record namespace %d/%d checks passed\n' "$P" "$((P+F))"
(( F == 0 ))
