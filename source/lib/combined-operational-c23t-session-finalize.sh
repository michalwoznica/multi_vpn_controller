#!/usr/bin/env bash
# C23T PRIVATE / DEFAULT-DENY: normal full-session finalization after C19.
#
# Lifecycle:
#   verified C19 stop with exact C1 guard retained
#     -> immutable owned-release intent
#     -> single nft delete attempt, classify by post-state (never blind retry)
#     -> immutable temporary-clone delete intent
#     -> single NM delete attempt, classify by read-only presence (never blind retry)
#     -> immutable archive plan
#     -> archive completed same-boot journals under /run/mvc-completed/<clone>
#     -> close the original controller lock
#
# This module has no public/live admission. The C23R/C23T private composition
# owns the only admission witness. It never exports secrets and never touches
# the saved source profile.

ubs24gc23t_reset() {
    UBS24GC23T_ATTEMPTED=no
    UBS24GC23T_STAGE=unverified
    UBS24GC23T_AUTHORITY=none
    UBS24GC23T_SOURCE_UUID=
    UBS24GC23T_CLONE_UUID=
    UBS24GC23T_NM_OWNER=
    UBS24GC23T_ARCHIVE=
    UBS24GC23T_CONVERGENCE_DETAIL=unverified
    UBS24GC23T_ROUTE4_EQUIVALENCE=unverified
    UBS24GC23T_RECOVERY_DETAIL=unverified
}
ubs24gc23t_admission_witness() { return 1; }
ubs24gc23t_authorize_public_release() { return 1; }
ubs24gc23t_authorize_retry() { return 1; }
ubs24gc23t_authorize_cleanup() { return 1; }
ubs24gc23t_authorize_traffic() { return 1; }
ubs24gc23t_authorize_secret_export() { return 1; }
ubs24gc23t_runtime() { printf '%s\n' /run/mvc-completion; }
ubs24gc23t_archive_root() { printf '%s\n' /run/mvc-completed; }

ubs24gc23t_sha() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    local v
    v=$(sha256sum -- "$1") || return 1
    v=${v%% *}
    [[ $v =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s\n' "$v"
}

ubs24gc23t_owned_tables_absent() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    jq -e '
      def owned($v): ($v|type)=="object" and
        (($v.family=="inet" and ($v.table // $v.name // "")=="mvc_preclone_quarantine") or
         ($v.family=="bridge" and ($v.table // $v.name // "")=="mvc_preclone_bridge") or
         ($v.family=="netdev" and ($v.table // $v.name // "")=="mvc_preclone_underlay"));
      (.nftables|type)=="array" and
      ([.nftables[] | to_entries[] | select(.key!="metainfo" and owned(.value))]|length)==0
    ' -- "$1" >/dev/null 2>&1
}

ubs24gc23t_release_batch_write() {
    (( $# == 1 )) || return 1
    [[ -f $1 && ! -L $1 && -O $1 && ! -s $1 &&
       $(stat -c '%a:%h' -- "$1") == 600:1 ]] || return 1
    printf '%s\n' \
      'delete table inet mvc_preclone_quarantine' \
      'delete table bridge mvc_preclone_bridge' \
      'delete table netdev mvc_preclone_underlay' > "$1"
}

ubs24gc23t_release_batch_valid() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 ]] || return 1
    local -a a=()
    mapfile -t a < "$1" || return 1
    (( ${#a[@]} == 3 )) &&
      [[ ${a[0]} == 'delete table inet mvc_preclone_quarantine' &&
         ${a[1]} == 'delete table bridge mvc_preclone_bridge' &&
         ${a[2]} == 'delete table netdev mvc_preclone_underlay' ]]
}

# Reconstruct the exact C3/C7/C19 identity from immutable same-boot journals.
# This is deliberately usable from a fresh shell after process interruption.
ubs24gc23t_recover_locked_session() {
    (( $# == 0 )) || return 1
    local dir fd
    dir=$(ubs24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller && -d $dir && ! -L $dir ]] || return 1
    if ! ubs24gb2_lock_valid >/dev/null 2>&1; then
        [[ -z ${UBS24GB2_FD:-} && -f $dir/controller.lock && ! -L $dir/controller.lock ]] || return 1
        exec {fd}< "$dir/controller.lock" || return 1
        if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
        UBS24GB2_FD=$fd
    fi
    if ! ubs24gc3_transition_records_valid; then
        UBS24GC23T_RECOVERY_DETAIL=c3-session-journal-unverified
        return 1
    fi
    if ! ubs24gc7_read_intent; then
        UBS24GC23T_RECOVERY_DETAIL=c7-activation-journal-unverified
        return 1
    fi
    # Fresh-process completion recovery has no C11 shell state. Reconstruct
    # the nonsecret tunnel/source identity from C13's immutable journal using
    # the existing C15 loader, which then invokes C13's full same-boot/hash/
    # namespace validator. C19 validation depends on these fields.
    if ! ubs24gc15_load_bound_intent; then
        UBS24GC23T_RECOVERY_DETAIL=c13-bound-tunnel-source-unverified
        return 1
    fi
    if ! ubs24gc19_intent_valid; then
        UBS24GC23T_RECOVERY_DETAIL=c19-stop-journal-unverified
        return 1
    fi
    UBS24GC23T_RECOVERY_DETAIL=locked-session-reconstructed
    UBS24GC23T_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GC23T_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GC23T_NM_OWNER=$UBS24GC7_NM_OWNER
    ubs24ga_uuid_valid "$UBS24GC23T_SOURCE_UUID" &&
      ubs24ga_uuid_valid "$UBS24GC23T_CLONE_UUID" &&
      [[ $UBS24GC23T_SOURCE_UUID != "$UBS24GC23T_CLONE_UUID" ]] &&
      ubs24gc7_nm_owner_valid "$UBS24GC23T_NM_OWNER" &&
      ubs24gb2_lock_valid
}

# C19 may return after NetworkManager reports the VPN inactive while the
# pre-session link/route snapshot is not yet restored. Only that topology
# mismatch is eligible for bounded observation. Session/journal integrity, VPN
# inactivity and the exact C1/foreign-firewall witness are hard prerequisites:
# they are never converted into a generic "wait and try again" condition.
ubs24gc23t_c1_firewall_witness() {
    (( $# == 0 )) || return 1
    local scratch a b good=1
    scratch=$(umask 077; mktemp -d /run/mvc-c23t-c1.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c '%a:%h' -- "$scratch") == 700:2 ]] || good=0
    a=$scratch/first.json
    b=$scratch/second.json
    if (( good == 1 )); then
        ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" &&
          ubs24gc19_kernel_witness c1 "$a" "$b" &&
          ubs24gc19_intent_valid || good=0
    fi
    rm -f -- "$a" "$b" || good=0
    rmdir -- "$scratch" || good=0
    (( good == 1 ))
}

# Accept only the physically observed NetworkManager connectivity-penalty
# transformation on the saved physical default route. This is deliberately
# narrower than ignoring route metrics: array length/order must match, exactly
# one route object may differ, that route must be the B2 underlay default route,
# every field except metric must be identical, and current metric must equal the
# saved integer metric plus exactly 20000. jq bindings MUST remain before the
# parenthesised boolean expression: jq 1.8 changed binding precedence, and
# interleaving `and` with `as $diffs` makes this positive case fail on the
# production Arch host even though jq 1.7 accepts it.
ubs24gc23t_routes4_nm_connectivity_penalty_equivalent() {
    (( $# == 2 )) || return 1
    local saved=$1 current=$2 underlay
    [[ -f $saved && ! -L $saved && -f $current && ! -L $current ]] || return 1
    underlay=$(ubs24gb2_derive_iface) || return 1
    jq -e -n --arg underlay "$underlay" \
      --slurpfile saved "$saved" --slurpfile current "$current" '
        [range(0; ($saved[0]|length)) as $i |
          select($saved[0][$i] != $current[0][$i]) |
          {i:$i, saved:$saved[0][$i], current:$current[0][$i]}
        ] as $diffs |
        (
          ($saved|length)==1 and ($current|length)==1 and
          ($saved[0]|type)=="array" and ($current[0]|type)=="array" and
          ($saved[0]|length)==($current[0]|length) and
          ($diffs|length)==1 and
          ($diffs[0].saved|type)=="object" and
          ($diffs[0].current|type)=="object" and
          ($diffs[0].saved.dst // "") == "default" and
          ($diffs[0].saved.dev // "") == $underlay and
          ($diffs[0].current.dev // "") == $underlay and
          ($diffs[0].saved.metric|type)=="number" and
          ($diffs[0].current.metric|type)=="number" and
          ($diffs[0].saved.metric == ($diffs[0].saved.metric|floor)) and
          ($diffs[0].current.metric == ($diffs[0].current.metric|floor)) and
          ($diffs[0].current.metric == ($diffs[0].saved.metric + 20000)) and
          (($diffs[0].current + {metric:$diffs[0].saved.metric}) == $diffs[0].saved)
        )
      ' >/dev/null 2>&1
}

# Preserve the exact B2 byte-for-byte topology contract but expose which part
# has not yet returned. A capture/parsing/journal failure is NOT convergence.
ubs24gc23t_b2_topology_witness() {
    (( $# == 0 )) || return 1
    local dir scratch links r4 r6 good=1
    dir=$(ubs24gb2_runtime) || {
        UBS24GC23T_CONVERGENCE_DETAIL=topology-runtime-unavailable
        return 1
    }
    [[ $dir == /run/mvc-controller && -d $dir && ! -L $dir ]] || {
        UBS24GC23T_CONVERGENCE_DETAIL=topology-runtime-invalid
        return 1
    }
    scratch=$(umask 077; mktemp -d /run/mvc-c23t-topology.XXXXXXXX) || {
        UBS24GC23T_CONVERGENCE_DETAIL=topology-scratch-create-failed
        return 1
    }
    links=$scratch/links.json
    r4=$scratch/routes4.json
    r6=$scratch/routes6.json
    if ! ubs24gb1_capture_links "$links" ||
       ! ubs24gb1_capture_routes4 "$r4" ||
       ! ubs24gb1_capture_routes6 "$r6"; then
        UBS24GC23T_CONVERGENCE_DETAIL=topology-capture-failed
        good=0
    elif ! cmp -s -- "$links" "$dir/links.json"; then
        UBS24GC23T_CONVERGENCE_DETAIL=links-not-restored
        good=0
    elif ! cmp -s -- "$r4" "$dir/routes4.json"; then
        if ubs24gc23t_routes4_nm_connectivity_penalty_equivalent "$dir/routes4.json" "$r4"; then
            UBS24GC23T_ROUTE4_EQUIVALENCE=nm-connectivity-penalty-plus-20000
        else
            UBS24GC23T_ROUTE4_EQUIVALENCE=not-equivalent
            UBS24GC23T_CONVERGENCE_DETAIL=routes4-not-restored
            good=0
        fi
    else
        UBS24GC23T_ROUTE4_EQUIVALENCE=exact
    fi
    if (( good == 1 )); then
        if ! cmp -s -- "$r6" "$dir/routes6.json"; then
            UBS24GC23T_CONVERGENCE_DETAIL=routes6-not-restored
            good=0
        elif ! ubs24gc3_transition_records_valid; then
            UBS24GC23T_CONVERGENCE_DETAIL=topology-session-journal-changed
            good=0
        elif [[ $UBS24GC23T_ROUTE4_EQUIVALENCE == nm-connectivity-penalty-plus-20000 ]]; then
            UBS24GC23T_CONVERGENCE_DETAIL=topology-restored-nm-connectivity-penalty-equivalent
        else
            UBS24GC23T_CONVERGENCE_DETAIL=topology-restored
        fi
    fi
    rm -f -- "$links" "$r4" "$r6" || {
        UBS24GC23T_CONVERGENCE_DETAIL=topology-scratch-cleanup-failed
        good=0
    }
    rmdir -- "$scratch" || {
        UBS24GC23T_CONVERGENCE_DETAIL=topology-scratch-cleanup-failed
        good=0
    }
    (( good == 1 ))
}

ubs24gc23t_c1_witness_once() {
    (( $# == 0 )) || return 1
    UBS24GC23T_CONVERGENCE_DETAIL=session-reconstruction
    if ! ubs24gc23t_recover_locked_session; then
        UBS24GC23T_STAGE=post-stop-session-journal-or-lock-unverified
        return 1
    fi
    UBS24GC23T_CONVERGENCE_DETAIL=no-active-vpn-before-c1
    if ! ubs24gb4_no_active_vpn; then
        UBS24GC23T_STAGE=post-stop-vpn-inactivity-unverified
        return 1
    fi
    UBS24GC23T_CONVERGENCE_DETAIL=c1-firewall-and-foreign-policy
    if ! ubs24gc23t_c1_firewall_witness; then
        UBS24GC23T_STAGE=post-stop-c1-firewall-or-foreign-policy-unverified
        return 1
    fi
    if ! ubs24gc23t_b2_topology_witness; then
        return 1
    fi
    UBS24GC23T_CONVERGENCE_DETAIL=no-active-vpn-after-topology
    if ! ubs24gb4_no_active_vpn; then
        UBS24GC23T_STAGE=post-stop-vpn-inactivity-unverified
        return 1
    fi
    UBS24GC23T_CONVERGENCE_DETAIL=final-lock
    if ! ubs24gb2_lock_valid; then
        UBS24GC23T_STAGE=post-stop-session-journal-or-lock-unverified
        return 1
    fi
    UBS24GC23T_CONVERGENCE_DETAIL=verified
    return 0
}

ubs24gc23t_convergence_pause() {
    (( $# == 0 )) || return 1
    sleep 1
}

ubs24gc23t_c1_witness() {
    (( $# == 0 )) || return 1
    local attempt max_attempts=20
    for (( attempt=1; attempt<=max_attempts; attempt++ )); do
        if ubs24gc23t_c1_witness_once; then
            return 0
        fi
        case ${UBS24GC23T_CONVERGENCE_DETAIL:-} in
            links-not-restored|routes4-not-restored|routes6-not-restored) ;;
            *) return 1 ;;
        esac
        if (( attempt < max_attempts )); then
            UBS24GC23T_STAGE=waiting-post-stop-b2-topology-convergence
            ubs24gc23t_convergence_pause || {
                UBS24GC23T_STAGE=post-stop-convergence-pause-failed
                return 1
            }
        fi
    done
    UBS24GC23T_STAGE=post-stop-b2-topology-not-converged
    return 1
}

ubs24gc23t_release_post_witness() {
    (( $# == 0 )) || return 1
    ubs24gb4_no_active_vpn || return 1
    local scratch a b before after prestate=/run/mvc-controller/prestate.json
    if [[ ! -f $prestate ]]; then
        local dir clone root
        dir=$(ubs24gc23t_runtime) || return 1
        if [[ -f $dir/archive-plan ]]; then
            UBS24GC23T_SOURCE_UUID=$(sed -n '6s/^source=//p' "$dir/archive-plan") || return 1
        clone=$(sed -n '7s/^clone=//p' "$dir/archive-plan") || return 1
            root=$(ubs24gc23t_archive_root) || return 1
            prestate="$root/$clone/controller/prestate.json"
        fi
    fi
    [[ -f $prestate && ! -L $prestate ]] || return 1
    local scratch a b before after
    scratch=$(umask 077; mktemp -d /run/mvc-c23t-release-observe.XXXXXXXX) || return 1
    a=$scratch/a.json b=$scratch/b.json
    local ok=1
    ubs24gb1_capture_nft "$a" && ubs24gb1_capture_nft "$b" && cmp -s -- "$a" "$b" &&
      ubs24gc23t_owned_tables_absent "$a" && ubs24gc23t_owned_tables_absent "$b" || ok=0
    if (( ok == 1 )); then
        before=$(ubs24gb2_foreign_projection "$prestate") || ok=0
        after=$(ubs24gb2_foreign_projection "$a") || ok=0
        [[ $before == "$after" ]] || ok=0
    fi
    rm -f -- "$a" "$b" || ok=0
    rmdir -- "$scratch" || ok=0
    (( ok == 1 ))
}

ubs24gc23t_release_intent_valid() {
    (( $# == 0 )) || return 1
    local dir boot c19 c1 batch clone owner
    local -a rows=() entries=()
    dir=$(ubs24gc23t_runtime) || return 1
    [[ $dir == /run/mvc-completion && -d $dir && ! -L $dir &&
       $(stat -c '%u:%a' -- "$dir") == 0:700 ]] || return 1
    [[ -f $dir/release-intent && ! -L $dir/release-intent &&
       -f $dir/release.nft && ! -L $dir/release.nft &&
       $(stat -c '%u:%a:%h' -- "$dir/release-intent") == 0:400:1 &&
       $(stat -c '%u:%a:%h' -- "$dir/release.nft") == 0:400:1 ]] || return 1
    mapfile -t rows < "$dir/release-intent" || return 1
    (( ${#rows[@]} == 9 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    c19=$(ubs24gc23t_sha /run/mvc-disconnect/attempt) || return 1
    c1=$(ubs24gc23t_sha /run/mvc-controller/transition-attempt) || return 1
    batch=$(ubs24gc23t_sha "$dir/release.nft") || return 1
    clone=${rows[7]#clone=} owner=${rows[8]#nm_owner=}
    [[ ${rows[0]} == ubs-v240-c23t-release-intent-v1 &&
       ${rows[1]} == state=nft-delete-attempted-once-outcome-uncertain &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "c19=$c19" &&
       ${rows[4]} == "c1=$c1" && ${rows[5]} == "batch=$batch" &&
       ${rows[6]} == "source=${UBS24GC23T_SOURCE_UUID:-}" &&
       ${rows[7]} == clone=* && ${rows[8]} == nm_owner=* ]] || return 1
    ubs24ga_uuid_valid "${UBS24GC23T_SOURCE_UUID:-}" && ubs24ga_uuid_valid "$clone" && ubs24gc7_nm_owner_valid "$owner" &&
      ubs24gc23t_release_batch_valid "$dir/release.nft"
}

ubs24gc23t_publish_release_intent() {
    (( $# == 0 )) || return 1
    local dir tmp boot c19 c1 batch
    ubs24gc23t_c1_witness || return 1
    [[ $(stat -f -c %T /run) == tmpfs ]] || return 1
    dir=$(ubs24gc23t_runtime) || return 1
    [[ ! -e $dir && ! -L $dir ]] || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.release.XXXXXXXX") || return 1
    chmod 600 -- "$tmp" || return 1
    ubs24gc23t_release_batch_write "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/release.nft" || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    c19=$(ubs24gc23t_sha /run/mvc-disconnect/attempt) || return 1
    c1=$(ubs24gc23t_sha /run/mvc-controller/transition-attempt) || return 1
    batch=$(ubs24gc23t_sha "$dir/release.nft") || return 1
    tmp=$(umask 077; mktemp "$dir/.intent.XXXXXXXX") || return 1
    printf '%s\n' ubs-v240-c23t-release-intent-v1 \
      state=nft-delete-attempted-once-outcome-uncertain "boot=$boot" \
      "c19=$c19" "c1=$c1" "batch=$batch" \
      "source=$UBS24GC23T_SOURCE_UUID" "clone=$UBS24GC23T_CLONE_UUID" \
      "nm_owner=$UBS24GC23T_NM_OWNER" > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/release-intent" || return 1
    ubs24gc23t_release_intent_valid
}

ubs24gc23t_nft_check() { nft --check --file "$1" >/dev/null 2>&1; }
ubs24gc23t_nft_commit() { nft --file "$1" >/dev/null 2>&1; }

# Absence/presence proof uses a successful non-secret UUID inventory rather
# than interpreting a failed lookup as "absent". The saved source must remain
# present exactly once, so NM/query failure or malformed output stays unknown.
ubs24gc23t_uuid_inventory() {
    (( $# == 1 )) || return 1
    local out=$1 line source_count=0
    [[ -f $out && ! -L $out && -O $out ]] || return 1
    LC_ALL=C nmcli --wait 10 --terse --fields UUID connection show </dev/null > "$out" 2>/dev/null || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line ]] || continue
        ubs24ga_uuid_valid "$line" || return 1
        [[ $line == "${UBS24GC23T_SOURCE_UUID:-}" ]] && source_count=$((source_count + 1))
    done < "$out"
    (( source_count == 1 ))
}

ubs24gc23t_clone_inventory_count() {
    (( $# == 2 )) || return 1
    local file=$1 uuid=$2 line count=0
    ubs24ga_uuid_valid "$uuid" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == "$uuid" ]] && count=$((count + 1))
    done < "$file"
    printf '%s\n' "$count"
}

ubs24gc23t_clone_present() {
    (( $# == 1 )) && ubs24ga_uuid_valid "$1" && ubs24ga_uuid_valid "${UBS24GC23T_SOURCE_UUID:-}" || return 1
    local tmp count
    tmp=$(umask 077; mktemp /run/mvc-c23t-nm.XXXXXXXX) || return 1
    chmod 600 -- "$tmp" || return 1
    if ! ubs24gc23t_uuid_inventory "$tmp"; then rm -f -- "$tmp"; return 1; fi
    count=$(ubs24gc23t_clone_inventory_count "$tmp" "$1") || { rm -f -- "$tmp"; return 1; }
    rm -f -- "$tmp" || return 1
    (( count == 1 ))
}

ubs24gc23t_clone_absent() {
    (( $# == 1 )) && ubs24ga_uuid_valid "$1" && ubs24ga_uuid_valid "${UBS24GC23T_SOURCE_UUID:-}" || return 1
    local tmp count
    tmp=$(umask 077; mktemp /run/mvc-c23t-nm.XXXXXXXX) || return 1
    chmod 600 -- "$tmp" || return 1
    if ! ubs24gc23t_uuid_inventory "$tmp"; then rm -f -- "$tmp"; return 1; fi
    count=$(ubs24gc23t_clone_inventory_count "$tmp" "$1") || { rm -f -- "$tmp"; return 1; }
    rm -f -- "$tmp" || return 1
    (( count == 0 ))
}

ubs24gc23t_clone_delete_intent_valid() {
    (( $# == 0 )) || return 1
    local dir boot release clone owner
    local -a rows=()
    dir=$(ubs24gc23t_runtime) || return 1
    [[ -f $dir/clone-delete-intent && ! -L $dir/clone-delete-intent &&
       $(stat -c '%u:%a:%h' -- "$dir/clone-delete-intent") == 0:400:1 ]] || return 1
    mapfile -t rows < "$dir/clone-delete-intent" || return 1
    (( ${#rows[@]} == 7 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    release=$(ubs24gc23t_sha "$dir/release-intent") || return 1
    clone=${rows[5]#clone=} owner=${rows[6]#nm_owner=}
    [[ ${rows[0]} == ubs-v240-c23t-clone-delete-intent-v1 &&
       ${rows[1]} == state=nm-delete-attempted-once-outcome-uncertain &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "release=$release" &&
       ${rows[4]} == "source=${UBS24GC23T_SOURCE_UUID:-}" &&
       ${rows[5]} == clone=* && ${rows[6]} == nm_owner=* ]] || return 1
    ubs24ga_uuid_valid "${UBS24GC23T_SOURCE_UUID:-}" && ubs24ga_uuid_valid "$clone" && ubs24gc7_nm_owner_valid "$owner"
}

ubs24gc23t_publish_clone_delete_intent() {
    (( $# == 0 )) || return 1
    local dir tmp boot release
    ubs24gc23t_release_intent_valid && ubs24gc23t_release_post_witness || return 1
    ubs24gc23t_clone_present "$UBS24GC23T_CLONE_UUID" || return 1
    dir=$(ubs24gc23t_runtime) || return 1
    [[ ! -e $dir/clone-delete-intent && ! -L $dir/clone-delete-intent ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    release=$(ubs24gc23t_sha "$dir/release-intent") || return 1
    tmp=$(umask 077; mktemp "$dir/.clone-delete.XXXXXXXX") || return 1
    printf '%s\n' ubs-v240-c23t-clone-delete-intent-v1 \
      state=nm-delete-attempted-once-outcome-uncertain "boot=$boot" \
      "release=$release" "source=$UBS24GC23T_SOURCE_UUID" \
      "clone=$UBS24GC23T_CLONE_UUID" "nm_owner=$UBS24GC23T_NM_OWNER" > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/clone-delete-intent" || return 1
    ubs24gc23t_clone_delete_intent_valid
}

ubs24gc23t_nm_delete() {
    (( $# == 1 )) && ubs24ga_uuid_valid "$1" || return 1
    LC_ALL=C nmcli --wait 35 --colors no --terse connection delete uuid "$1" \
      </dev/null >/dev/null 2>&1
}

ubs24gc23t_archive_move() {
    (( $# == 2 )) || return 1
    mv -T -- "$1" "$2"
}

ubs24gc23t_archive_plan_valid() {
    (( $# == 0 )) || return 1
    local dir boot source clone release del expected archive
    local -a rows=()
    dir=$(ubs24gc23t_runtime) || return 1
    [[ -f $dir/archive-plan && ! -L $dir/archive-plan &&
       $(stat -c '%u:%a:%h' -- "$dir/archive-plan") == 0:400:1 ]] || return 1
    mapfile -t rows < "$dir/archive-plan" || return 1
    (( ${#rows[@]} == 8 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    release=$(ubs24gc23t_sha "$dir/release-intent") || return 1
    del=$(ubs24gc23t_sha "$dir/clone-delete-intent") || return 1
    source=${rows[5]#source=}
    clone=${rows[6]#clone=}
    expected="$(ubs24gc23t_archive_root)/$clone"
    archive=${rows[7]#archive=}
    [[ ${rows[0]} == ubs-v240-c23t-archive-plan-v1 &&
       ${rows[1]} == state=completed-session-archive-pending &&
       ${rows[2]} == "boot=$boot" && ${rows[3]} == "release=$release" &&
       ${rows[4]} == "delete=$del" && ${rows[5]} == source=* &&
       ${rows[6]} == clone=* && ${rows[7]} == "archive=$expected" &&
       $archive == "$expected" ]] || return 1
    ubs24ga_uuid_valid "$source" && ubs24ga_uuid_valid "$clone" && [[ $source != "$clone" ]] || return 1
    UBS24GC23T_SOURCE_UUID=$source
    UBS24GC23T_CLONE_UUID=$clone
    return 0
}

ubs24gc23t_publish_archive_plan() {
    (( $# == 0 )) || return 1
    local dir root archive tmp boot release del
    ubs24gc23t_clone_delete_intent_valid &&
      ubs24gc23t_release_post_witness &&
      ubs24gc23t_clone_absent "$UBS24GC23T_CLONE_UUID" || return 1
    dir=$(ubs24gc23t_runtime) || return 1
    root=$(ubs24gc23t_archive_root) || return 1
    archive="$root/$UBS24GC23T_CLONE_UUID"
    [[ ! -e $dir/archive-plan && ! -L $dir/archive-plan &&
       ! -e $archive && ! -L $archive ]] || return 1
    if [[ ! -e $root ]]; then (umask 077; mkdir -m 700 -- "$root") || return 1; fi
    [[ -d $root && ! -L $root && $(stat -c '%u:%a' -- "$root") == 0:700 ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    release=$(ubs24gc23t_sha "$dir/release-intent") || return 1
    del=$(ubs24gc23t_sha "$dir/clone-delete-intent") || return 1
    tmp=$(umask 077; mktemp "$dir/.archive.XXXXXXXX") || return 1
    printf '%s\n' ubs-v240-c23t-archive-plan-v1 \
      state=completed-session-archive-pending "boot=$boot" \
      "release=$release" "delete=$del" "source=$UBS24GC23T_SOURCE_UUID" \
      "clone=$UBS24GC23T_CLONE_UUID" "archive=$archive" > "$tmp" || return 1
    chmod 400 -- "$tmp" || return 1
    mv -T -- "$tmp" "$dir/archive-plan" || return 1
    ubs24gc23t_archive_plan_valid
}

ubs24gc23t_archive_continue() {
    (( $# == 0 )) || return 1
    local completion root archive clone src name
    completion=$(ubs24gc23t_runtime) || return 1
    root=$(ubs24gc23t_archive_root) || return 1
    if [[ -d $completion && ! -L $completion ]]; then
        ubs24gc23t_archive_plan_valid || return 1
        UBS24GC23T_SOURCE_UUID=$(sed -n '6s/^source=//p' "$completion/archive-plan") || return 1
        clone=$(sed -n '7s/^clone=//p' "$completion/archive-plan") || return 1
        archive="$root/$clone"
    else
        # Completion was already moved last; identify the sole matching archive
        # from the session clone retained in memory by normal execution.
        clone=${UBS24GC23T_CLONE_UUID:-}
        ubs24ga_uuid_valid "$clone" || return 1
        archive="$root/$clone"
        [[ -d $archive/completion && ! -L $archive/completion ]] || return 1
        UBS24GC23T_ARCHIVE=$archive
        ubs24gb2_close
        return 0
    fi
    [[ -d $root && ! -L $root && $(stat -c '%u:%a' -- "$root") == 0:700 ]] || return 1
    if [[ ! -e $archive ]]; then (umask 077; mkdir -m 700 -- "$archive") || return 1; fi
    [[ -d $archive && ! -L $archive && $(stat -c '%u:%a' -- "$archive") == 0:700 ]] || return 1

    # Move fixed session journals in an order that keeps controller.lock at its
    # original path until all other evidence has safely moved.
    for name in activation output-transition disconnect; do
        src="/run/mvc-$name"
        if [[ -e $src || -L $src ]]; then
            [[ -d $src && ! -L $src && ! -e $archive/$name && ! -L $archive/$name ]] || return 1
            ubs24gc23t_archive_move "$src" "$archive/$name" || return 1
        else
            [[ -d $archive/$name && ! -L $archive/$name ]] || return 1
        fi
    done
    src=/run/mvc-controller
    if [[ -e $src || -L $src ]]; then
        [[ -d $src && ! -L $src && ! -e $archive/controller && ! -L $archive/controller ]] || return 1
        ubs24gc23t_archive_move "$src" "$archive/controller" || return 1
    else
        [[ -d $archive/controller && ! -L $archive/controller ]] || return 1
    fi
    # Move the completion record last. A crash before this point leaves a fixed
    # recovery anchor; a crash after it has no remaining network mutation.
    if [[ -e $completion || -L $completion ]]; then
        [[ -d $completion && ! -L $completion && ! -e $archive/completion && ! -L $archive/completion ]] || return 1
        ubs24gc23t_archive_move "$completion" "$archive/completion" || return 1
    fi
    [[ -d $archive/completion && -d $archive/controller && -d $archive/activation &&
       -d $archive/output-transition && -d $archive/disconnect &&
       ! -e /run/mvc-controller && ! -e /run/mvc-activation &&
       ! -e /run/mvc-output-transition && ! -e /run/mvc-disconnect &&
       ! -e /run/mvc-completion ]] || return 1
    UBS24GC23T_ARCHIVE=$archive
    ubs24gb2_close
    return 0
}

# Normal same-process full-session finalizer. Any ambiguous mutation is
# classified immediately by read-only post-state; it is never reissued.
ubs24gc23t_execute_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GC23T_ATTEMPTED:-no} == no ]] || return 1
    UBS24GC23T_ATTEMPTED=yes
    UBS24GC23T_STAGE=refused-or-unverified
    UBS24GC23T_AUTHORITY=none
    ubs24gc23t_admission_witness || return 1
    ubs24gc23t_c1_witness || return 1
    [[ ! -e /run/mvc-completion && ! -L /run/mvc-completion ]] || return 1

    ubs24gc23t_publish_release_intent || return 1
    ubs24gc23t_nft_check /run/mvc-completion/release.nft || return 1
    ubs24gc23t_c1_witness && ubs24gc23t_release_intent_valid || return 1
    UBS24GC23T_STAGE=release-attempted-outcome-uncertain
    local release_rc=0
    ubs24gc23t_nft_commit /run/mvc-completion/release.nft || release_rc=$?
    if ! ubs24gc23t_release_post_witness; then
        UBS24GC23T_STAGE=release-attempt-present-poststate-unverified-no-retry
        return 1
    fi
    # A nonzero reply is acceptable only because independent post-state proves
    # the exact owned tables are absent and foreign policy is unchanged.
    : "$release_rc"
    UBS24GC23T_STAGE=owned-guard-release-observed-clone-delete-pending

    ubs24gc23t_publish_clone_delete_intent || return 1
    UBS24GC23T_STAGE=clone-delete-attempted-outcome-uncertain
    local delete_rc=0
    ubs24gc23t_nm_delete "$UBS24GC23T_CLONE_UUID" || delete_rc=$?
    if ! ubs24gc23t_clone_absent "$UBS24GC23T_CLONE_UUID"; then
        UBS24GC23T_STAGE=clone-delete-intent-present-absence-unproven-no-retry
        return 1
    fi
    : "$delete_rc"
    UBS24GC23T_STAGE=clone-absence-observed-archive-pending

    ubs24gc23t_publish_archive_plan || return 1
    UBS24GC23T_STAGE=archive-in-progress
    ubs24gc23t_archive_continue || return 1
    UBS24GC23T_STAGE=completed-session-archived-sameboot-ready
    return 0
}

# Fresh-process continuation. Network mutations are issued only when their
# corresponding intent does not yet exist. Existing release/delete intents are
# never retried; observation either proves completion and advances or stops.
ubs24gc23t_reconcile_once() {
    (( $# == 0 )) || return 1
    UBS24GC23T_STAGE=reconcile-unverified
    UBS24GC23T_AUTHORITY=none
    ubs24gc23t_admission_witness || return 1
    local dir clone
    dir=$(ubs24gc23t_runtime) || return 1

    if [[ ! -e $dir && ! -L $dir ]]; then
        return 1
    fi

    # Once archive-plan exists, every network mutation is already complete.
    # Recovery is intentionally filesystem-only and therefore does not depend
    # on activation/output/disconnect journals remaining at fixed paths.
    if [[ -f $dir/archive-plan ]]; then
        if ! ubs24gc23t_archive_plan_valid; then
            UBS24GC23T_STAGE=archive-plan-invalid
            return 1
        fi
        UBS24GC23T_SOURCE_UUID=$(sed -n '6s/^source=//p' "$dir/archive-plan") || return 1
        clone=$(sed -n '7s/^clone=//p' "$dir/archive-plan") || return 1
        ubs24ga_uuid_valid "$clone" || return 1
        UBS24GC23T_CLONE_UUID=$clone
        if ! ubs24gc23t_clone_absent "$clone"; then
            UBS24GC23T_STAGE=archive-clone-absence-unproven
            return 1
        fi
        if ! ubs24gc23t_release_post_witness; then
            UBS24GC23T_STAGE=archive-release-poststate-unproven
            return 1
        fi
        UBS24GC23T_STAGE=archive-in-progress
        if ! ubs24gc23t_archive_continue; then
            UBS24GC23T_STAGE=archive-continuation-failed
            return 1
        fi
        UBS24GC23T_STAGE=completed-session-archived-sameboot-ready
        return 0
    fi

    # Before archival begins, all fixed journals remain in place and can be
    # used to reconstruct the exact stopped session under the original lock.
    ubs24gc23t_recover_locked_session || return 1
    [[ -f $dir/release-intent ]] || return 1
    ubs24gc23t_release_intent_valid || return 1
    if ! ubs24gc23t_release_post_witness; then
        UBS24GC23T_STAGE=release-attempt-present-poststate-unverified-no-retry
        return 1
    fi

    if [[ -f $dir/clone-delete-intent ]]; then
        ubs24gc23t_clone_delete_intent_valid || return 1
        if ! ubs24gc23t_clone_absent "$UBS24GC23T_CLONE_UUID"; then
            UBS24GC23T_STAGE=clone-delete-intent-present-absence-unproven-no-retry
            return 1
        fi
    else
        # Release is proven complete and no delete was ever attempted: this is
        # continuation, not retry of an ambiguous delete.
        ubs24gc23t_clone_present "$UBS24GC23T_CLONE_UUID" || return 1
        ubs24gc23t_publish_clone_delete_intent || return 1
        UBS24GC23T_STAGE=clone-delete-attempted-outcome-uncertain
        local rc=0
        ubs24gc23t_nm_delete "$UBS24GC23T_CLONE_UUID" || rc=$?
        if ! ubs24gc23t_clone_absent "$UBS24GC23T_CLONE_UUID"; then
            UBS24GC23T_STAGE=clone-delete-intent-present-absence-unproven-no-retry
            return 1
        fi
        : "$rc"
    fi

    ubs24gc23t_publish_archive_plan || return 1
    UBS24GC23T_STAGE=archive-in-progress
    ubs24gc23t_archive_continue || return 1
    UBS24GC23T_STAGE=completed-session-archived-sameboot-ready
    return 0
}
