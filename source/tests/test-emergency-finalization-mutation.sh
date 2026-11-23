#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
REC=$ROOT/source/tools/recover-mvc-host-guard-local.sh
# shellcheck source=../tools/recover-mvc-host-guard-local.sh
source "$REC"

P=0 F=0
pass(){ printf 'PASS: %s\n' "$1"; P=$((P+1)); }
fail(){ printf 'FAIL: %s\n' "$1" >&2; F=$((F+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
PUB=$TMP/mvc-public-session
CTRL=$TMP/mvc-controller
ACT=$TMP/mvc-activation
OUT=$TMP/mvc-output-transition
DISC=$TMP/mvc-disconnect
COMP=$TMP/mvc-completion
WGRT=$TMP/mvc-wireguard
KEY=$TMP/vpnks-wg.nmconnection
ARCH=$TMP/recovered
STUB=$TMP/stubbin
PROFILE=$TMP/profile-state
DELETE_COUNT=$TMP/delete-count
ARCHIVE_BEFORE_DELETE=$TMP/archive-before-delete
mkdir -p "$STUB"

mvc_er_public_root(){ printf '%s\n' "$PUB"; }
mvc_er_controller_root(){ printf '%s\n' "$CTRL"; }
mvc_er_activation_root(){ printf '%s\n' "$ACT"; }
mvc_er_output_root(){ printf '%s\n' "$OUT"; }
mvc_er_disconnect_root(){ printf '%s\n' "$DISC"; }
mvc_er_completion_root(){ printf '%s\n' "$COMP"; }
mvc_er_wireguard_root(){ printf '%s\n' "$WGRT"; }
mvc_er_archive_root(){ printf '%s\n' "$ARCH"; }
mvc_er_recovery_plan_path(){ printf '%s/recovery-plan\n' "$PUB"; }
mvc_er_controller_prepare_path(){ printf '%s\n' "$CTRL/prepare-intent"; }
mvc_er_controller_transition_path(){ printf '%s\n' "$CTRL/transition-attempt"; }
mvc_er_activation_path(){ printf '%s\n' "$ACT/attempt"; }
mvc_er_output_path(){ printf '%s\n' "$OUT/attempt"; }
mvc_er_d4_intent_path(){ printf '%s\n' "$WGRT/intent"; }
mvc_er_wg_keyfile_path(){ printf '%s\n' "$KEY"; }

# Keep the fixture usable as an unprivileged CI user while production still
# enforces root ownership/modes through the original helpers.
mvc_er_secure_dir(){ [[ -d $1 && ! -L $1 ]]; }
mvc_er_secure_file(){ [[ -f $1 && ! -L $1 ]]; }
mvc_er_tree_safe(){ [[ -d $1 && ! -L $1 ]]; }
mvc_er_root_scope(){ return 0; }
mvc_er_b4_all_absent(){ return 0; }
mvc_er_no_active_vpn_or_tunnel(){ return 0; }
mvc_er_managed_routes_absent(){ return 0; }
mvc_er_ipv6_no_default(){ return 0; }
mvc_er_wireguard_residue_absent(){ return 0; }

uuid_os=11111111-1111-4111-8111-111111111111
uuid_oc=22222222-2222-4222-8222-222222222222
uuid_ws=33333333-3333-4333-8333-333333333333
uuid_wt=44444444-4444-4444-8444-444444444444
underlay=test-wlan0
boot=$(cat /proc/sys/kernel/random/boot_id)
userns=$(readlink /proc/self/ns/user)
netns=$(readlink /proc/self/ns/net)
mntns=$(readlink /proc/self/ns/mnt)

sha(){ sha256sum "$1" | awk '{print $1}'; }
secure_fixture(){
    find "$TMP" -path "$STUB" -prune -o -type d -exec chmod 700 {} + 2>/dev/null || true
    find "$TMP" -path "$STUB" -prune -o -type f -exec chmod 400 {} + 2>/dev/null || true
    [[ ! -f $CTRL/controller.lock ]] || chmod 600 "$CTRL/controller.lock"
    [[ ! -f $PUB/split.lock ]] || chmod 600 "$PUB/split.lock"
    chmod 700 "$STUB" 2>/dev/null || true
    [[ ! -f $STUB/nmcli ]] || chmod 700 "$STUB/nmcli"
}

reset_fixture(){
    rm -rf -- "$PUB" "$CTRL" "$ACT" "$OUT" "$DISC" "$COMP" "$WGRT" "$KEY" "$ARCH"
    rm -f -- "$PROFILE" "$DELETE_COUNT" "$ARCHIVE_BEFORE_DELETE"
    mkdir -p "$PUB" "$CTRL" "$ACT" "$OUT"
    printf 'prepare\n' > "$CTRL/prepare-intent"
    printf 'transition\n' > "$CTRL/transition-attempt"
    printf 'activation\n' > "$ACT/attempt"
    printf 'output\n' > "$OUT/attempt"
    : > "$CTRL/controller.lock"
    MVC_ER_ARCHIVE=
    MVC_ER_REASON=unverified
    MVC_ER_LOCKS_HELD=no
    secure_fixture
}

write_active_combined(){
    local d4_hash
    d4_hash=$(printf 'historical-d4\n' | sha256sum | awk '{print $1}')
    chmod 700 "$PUB" "$CTRL" "$ACT" "$OUT"
    chmod 400 "$CTRL/prepare-intent" "$CTRL/transition-attempt" "$ACT/attempt" "$OUT/attempt"
    chmod 600 "$CTRL/controller.lock"
    cat > "$PUB/active" <<MARKER
mvc-public-active-v1
state=dual-active-published
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=$uuid_os
ovpn_clone_uuid=$uuid_oc
wg_source_uuid=$uuid_ws
wg_temp_uuid=$uuid_wt
underlay=$underlay
controller_prepare_sha=$(sha "$CTRL/prepare-intent")
controller_transition_sha=$(sha "$CTRL/transition-attempt")
activation_sha=$(sha "$ACT/attempt")
output_sha=$(sha "$OUT/attempt")
d4_intent_sha=$d4_hash
MARKER
    chmod 400 "$PUB/active"
}

write_transaction(){
    local state=$1 os=$2 oc=$3 ws=$4 wt=$5 prepare=$6 transition=$7 activation=$8 output=$9 d4=${10}
    cat > "$PUB/transaction" <<MARKER
mvc-public-transaction-v1
state=$state
boot=$boot
userns=$userns
netns=$netns
mntns=$mntns
ovpn_source_uuid=$os
ovpn_clone_uuid=$oc
wg_source_uuid=$ws
wg_temp_uuid=$wt
underlay=$underlay
controller_prepare_sha=$prepare
controller_transition_sha=$transition
activation_sha=$activation
output_sha=$output
d4_intent_sha=$d4
MARKER
    chmod 400 "$PUB/transaction"
}

setup_combined(){ reset_fixture; write_active_combined; }
setup_protected_wg(){
    reset_fixture
    rm -rf -- "$ACT" "$OUT"
    mkdir -p "$WGRT"; printf 'd4-intent\n' > "$WGRT/intent"
    chmod 700 "$WGRT"; chmod 400 "$WGRT/intent" "$CTRL/prepare-intent"; chmod 600 "$CTRL/controller.lock"
    write_transaction wireguard-protected - - "$uuid_ws" "$uuid_wt" "$(sha "$CTRL/prepare-intent")" - - - "$(sha "$WGRT/intent")"
}
setup_split_wg(){
    reset_fixture
    rm -rf -- "$CTRL" "$ACT" "$OUT"
    mkdir -p "$WGRT"; printf 'd4-intent\n' > "$WGRT/intent"; : > "$PUB/split.lock"
    chmod 700 "$WGRT"; chmod 400 "$WGRT/intent"; chmod 600 "$PUB/split.lock"
    write_transaction wireguard-split - - "$uuid_ws" "$uuid_wt" - - - - "$(sha "$WGRT/intent")"
}

mvc_er_nm_profiles(){
    if [[ -f $PROFILE ]]; then
        printf '%s:vpn:vpnks-ovpn\n' "$uuid_oc"
    fi
}

cat > "$STUB/nmcli" <<'NMCLI'
#!/usr/bin/env bash
set -u
printf 'x\n' >> "$MVC_TEST_DELETE_COUNT"
if find "$MVC_TEST_ARCHIVE_ROOT" -mindepth 2 -maxdepth 2 -name recovery-evidence -type f -print -quit 2>/dev/null | grep -q .; then
    : > "$MVC_TEST_ARCHIVE_BEFORE_DELETE"
fi
case ${MVC_TEST_DELETE_BEHAVIOR:-remove0} in
    remove0) rm -f -- "$MVC_TEST_PROFILE"; exit 0 ;;
    remove99) rm -f -- "$MVC_TEST_PROFILE"; exit 99 ;;
    retain99) exit 99 ;;
    *) exit 98 ;;
esac
NMCLI
chmod 700 "$STUB/nmcli"
export MVC_TEST_DELETE_COUNT=$DELETE_COUNT MVC_TEST_ARCHIVE_ROOT=$ARCH MVC_TEST_ARCHIVE_BEFORE_DELETE=$ARCHIVE_BEFORE_DELETE MVC_TEST_PROFILE=$PROFILE
PATH="$STUB:$PATH"
export PATH

# 1. Full combined-session finalization archives evidence before deleting the
# exact inactive clone, retires live authority and produces a recovery result.
setup_combined; : > "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=remove0
if mvc_er_finalize_recovery && mvc_er_fixed_roots_all_absent && [[ ! -e $PROFILE && -f $MVC_ER_ARCHIVE/recovery-result && -f $ARCHIVE_BEFORE_DELETE ]] &&
   [[ $(wc -l < "$DELETE_COUNT") == 1 ]]; then
    pass 'combined recovery finalizes same-boot state with evidence archived before clone deletion'
else
    fail 'combined recovery finalization'
fi

# 2. A nonzero nmcli reply is acceptable only when independent post-state proves
# the authenticated clone is actually absent.
setup_combined; : > "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=remove99
if mvc_er_finalize_recovery && [[ ! -e $PROFILE && $(wc -l < "$DELETE_COUNT") == 1 ]] && mvc_er_fixed_roots_all_absent; then
    pass 'clone deletion accepts nonzero command reply only with proven absent post-state'
else
    fail 'nonzero clone-delete post-state classification'
fi

# 3. Once a clone-delete intent exists, retained clone residue is never retried.
setup_combined; : > "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=retain99
set +e
mvc_er_finalize_recovery; first_rc=$?
first_reason=$MVC_ER_REASON
mvc_er_finalize_recovery; second_rc=$?
second_reason=$MVC_ER_REASON
set -e
if (( first_rc != 0 && second_rc != 0 )) && [[ -f $PROFILE && $(wc -l < "$DELETE_COUNT") == 1 && -d $PUB ]] &&
   [[ $first_reason == openvpn-clone-delete-outcome-not-proven-no-retry && $second_reason == openvpn-clone-delete-attempt-present-residue-remains-no-retry ]]; then
    pass 'ambiguous clone deletion is attempted once and never blindly retried'
else
    fail 'clone-delete no-retry boundary'
fi

# 4. Final safety is checked again after clone cleanup. If it changes, evidence
# and authority remain available and a later safe retry can continue.
setup_combined; : > "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=remove0
IPV6_CALLS=0
mvc_er_ipv6_no_default(){ IPV6_CALLS=$((IPV6_CALLS+1)); (( IPV6_CALLS < 3 )); }
set +e
mvc_er_finalize_recovery; safety_rc=$?
set -e
if (( safety_rc != 0 )) && [[ ! -e $PROFILE && -d $PUB && -n ${MVC_ER_ARCHIVE:-} && -f $MVC_ER_ARCHIVE/recovery-evidence && ! -e $PUB/recovery-plan ]]; then
    pass 'post-mutation safety failure preserves evidence and live authority'
else
    fail 'post-mutation safety refusal'
fi
mvc_er_ipv6_no_default(){ return 0; }
if mvc_er_finalize_recovery && mvc_er_fixed_roots_all_absent; then
    pass 'safe retry resumes from archived evidence after post-mutation refusal'
else
    fail 'post-mutation recovery continuation'
fi

# 6. Once network mutation is complete, a public retirement plan is a fixed
# crash-resume anchor. Missing live journals no longer prevent filesystem-only
# completion because their verified snapshot is already archived.
setup_combined; rm -f -- "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=remove0
mvc_er_finalization_classify
mvc_er_acquire_finalization_locks
mvc_er_finalization_classify
mvc_er_prepare_archive
resume_archive=$MVC_ER_ARCHIVE
mvc_er_publish_network_finalized "$resume_archive"
mvc_er_publish_retirement_plan "$resume_archive"
mvc_er_release_finalization_locks
rm -rf -- "$ACT" "$OUT"
if mvc_er_finalize_recovery && mvc_er_fixed_roots_all_absent && [[ -f $resume_archive/recovery-result ]]; then
    pass 'filesystem-only retirement resumes after journals already disappeared'
else
    fail 'retirement-plan crash resume'
fi

# 7. Tampering with the archived evidence prevents retirement; the live public
# authority remains present and continues to block fresh admission.
setup_combined; rm -f -- "$PROFILE"
mvc_er_finalization_classify
mvc_er_acquire_finalization_locks
mvc_er_finalization_classify
mvc_er_prepare_archive
tamper_archive=$MVC_ER_ARCHIVE
mvc_er_publish_network_finalized "$tamper_archive"
mvc_er_publish_retirement_plan "$tamper_archive"
mvc_er_release_finalization_locks
printf 'tamper\n' >> "$tamper_archive/snapshot/mvc-public-session/active"
set +e
mvc_er_finalize_recovery; tamper_rc=$?
set -e
if (( tamper_rc != 0 )) && [[ -d $PUB && -f $PUB/recovery-plan ]]; then
    pass 'archive-evidence tampering blocks live-authority retirement'
else
    fail 'archive tamper refusal'
fi

# 8. Unsafe live-tree classification stops before archive/profile mutation.
setup_combined; : > "$PROFILE"; export MVC_TEST_DELETE_BEHAVIOR=remove0
mvc_er_all_live_trees_safe(){ return 1; }
set +e
mvc_er_finalize_recovery; unsafe_rc=$?
set -e
if (( unsafe_rc != 0 )) && [[ -f $PROFILE && ! -e $ARCH && ! -e $DELETE_COUNT && $MVC_ER_REASON == unsafe-live-runtime-tree ]]; then
    pass 'unsafe live runtime tree blocks finalization before mutation'
else
    fail 'unsafe runtime-tree refusal'
fi
# Restore the hermetic tree predicate wrapper.
mvc_er_all_live_trees_safe(){
    local path
    while IFS= read -r path; do
        if [[ -e $path || -L $path ]]; then mvc_er_tree_safe "$path" || return 1; fi
    done < <(mvc_er_fixed_root_paths)
}

# 9. Protected WireGuard mature recovery has no OpenVPN mutation; authenticated
# D4 evidence is archived and retired with the same final-safety protocol.
setup_protected_wg; rm -f -- "$PROFILE" "$DELETE_COUNT"
if mvc_er_finalize_recovery && mvc_er_fixed_roots_all_absent && [[ -f $MVC_ER_ARCHIVE/recovery-result && ! -e $DELETE_COUNT ]]; then
    pass 'protected WireGuard recovery finalizes without inventing OpenVPN mutation'
else
    fail 'protected WireGuard finalization'
fi

# 10. Split WireGuard uses its split lock as the live serialization anchor and
# reaches the same clean same-boot end state.
setup_split_wg; rm -f -- "$PROFILE" "$DELETE_COUNT"
if mvc_er_finalize_recovery && mvc_er_fixed_roots_all_absent && [[ -f $MVC_ER_ARCHIVE/recovery-result && ! -e $DELETE_COUNT ]]; then
    pass 'split WireGuard recovery finalizes under authenticated split-lock authority'
else
    fail 'split WireGuard finalization'
fi

# 11. An already-clean baseline needs no invented archive or mutation.
reset_fixture; rm -rf -- "$PUB" "$CTRL" "$ACT" "$OUT"; rm -f -- "$PROFILE" "$DELETE_COUNT"
if mvc_er_finalize_recovery && [[ $MVC_ER_REASON == recovery-already-clean-baseline && ! -e $ARCH && ! -e $DELETE_COUNT ]]; then
    pass 'already-clean baseline is a no-op successful finalization'
else
    fail 'already-clean finalization'
fi

# 12. B4 must already be absent before the finalizer can mutate anything.
setup_combined; : > "$PROFILE"; rm -f -- "$DELETE_COUNT"
mvc_er_b4_all_absent(){ return 1; }
set +e
mvc_er_finalize_recovery; b4_rc=$?
set -e
if (( b4_rc != 0 )) && [[ -f $PROFILE && ! -e $ARCH && ! -e $DELETE_COUNT && $MVC_ER_REASON == b4-still-present-or-unreadable ]]; then
    pass 'finalizer never substitutes for the independent B4 disarm phase'
else
    fail 'B4-before-finalizer boundary'
fi

printf 'Results: %d passed, %d failed\n' "$P" "$F"
(( F == 0 ))
