#!/usr/bin/env bash
# MVC 2.4.2 R1 — dependency preflight diagnostics and monolith scratch cleanup.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
PASS=0
FAIL=0
ok(){ printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/build"
"$BUILDER" "$TMP/build/mvc" >/dev/null
A=$TMP/build/mvc

asset_inventory() {
    find /dev/shm -maxdepth 1 -type d -name 'mvc-monolith-assets.*' -printf '%f\n' 2>/dev/null | sort
}

link_real() {
    local dest=$1 name=$2 path
    path=$(command -v "$name") || return 1
    ln -s -- "$path" "$dest/$name"
}

# The builder must diagnose a missing build prerequisite before creating the
# requested output directory/file.
BUILD_BIN=$TMP/build-bin
mkdir "$BUILD_BIN"
for b in bash awk cat chmod grep mkdir mktemp mv rm rmdir sed sha256sum stat tail tr; do
    link_real "$BUILD_BIN" "$b"
done
# Deliberately omit od.
set +e
PATH="$BUILD_BIN" "$BUILDER" "$TMP/should-not-exist/mvc" >"$TMP/build-missing.out" 2>&1
rc=$?
set -e
if (( rc != 0 )) && grep -Fq 'missing build prerequisite: od' "$TMP/build-missing.out" && [[ ! -e $TMP/should-not-exist ]]; then
    ok 'builder reports exact missing build prerequisite before output creation'
else
    bad 'builder reports exact missing build prerequisite before output creation'
fi

# Bootstrap tools are checked before embedded assets are materialized.
BOOT_BIN=$TMP/bootstrap-bin
mkdir "$BOOT_BIN"
for b in bash awk cat chmod mv rm rmdir sha256sum stat; do
    link_real "$BOOT_BIN" "$b"
done
# Deliberately omit mktemp.
before=$(asset_inventory)
set +e
PATH="$BOOT_BIN" "$A" preflight wg --split ovpn >"$TMP/bootstrap.out" 2>&1
rc=$?
set -e
after=$(asset_inventory)
if (( rc != 0 )) && grep -Fq 'missing bootstrap prerequisite: mktemp' "$TMP/bootstrap.out" && [[ $before == "$after" ]]; then
    ok 'missing bootstrap prerequisite is named before asset creation and leaves no residue'
else
    bad 'missing bootstrap prerequisite is named before asset creation and leaves no residue'
fi

# Build a PATH that satisfies bootstrap + D4 inventory while replacing network
# commands with marker stubs. A dependency failure must occur before any of
# those network commands are executed, and the EXIT trap must remove assets.
run_missing_runtime_case() {
    local missing=$1
    local case_dir=$TMP/runtime-$missing
    local bin=$case_dir/bin
    local marker=$case_dir/network-command-called
    local b before after rc
    mkdir -p "$bin"
    link_real "$bin" bash
    local -a required=(awk cat chmod cmp cp cut dig dirname find flock gdbus getent grep ip jq ln mkdir mktemp mv nft nmcli pgrep readlink realpath rm rmdir sed sha256sum sleep sort stat tr wc wg)
    for b in "${required[@]}"; do
        [[ $b == "$missing" ]] && continue
        case $b in
            ip|nmcli|wg|nft|gdbus)
                cat > "$bin/$b" <<STUB
#!/usr/bin/env bash
touch '$marker'
exit 99
STUB
                chmod 755 "$bin/$b"
                ;;
            *)
                if command -v "$b" >/dev/null 2>&1; then
                    link_real "$bin" "$b"
                else
                    cat > "$bin/$b" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
                    chmod 755 "$bin/$b"
                fi
                ;;
        esac
    done
    before=$(asset_inventory)
    set +e
    PATH="$bin" "$A" preflight wg --split ovpn >"$case_dir/out" 2>&1
    rc=$?
    set -e
    after=$(asset_inventory)
    if (( rc != 0 )) && grep -Fq "missing prerequisite: $missing" "$case_dir/out" &&
       [[ ! -e $marker && $before == "$after" ]]; then
        return 0
    fi
    cat "$case_dir/out" >&2 || :
    return 1
}

run_missing_runtime_case jq && ok 'missing jq is named before network mutation and EXIT cleanup leaves no asset residue' || bad 'missing jq is named before network mutation and EXIT cleanup leaves no asset residue'
run_missing_runtime_case nft && ok 'missing nft is named before network mutation and EXIT cleanup leaves no asset residue' || bad 'missing nft is named before network mutation and EXIT cleanup leaves no asset residue'
run_missing_runtime_case mkdir && ok 'missing mkdir is named before network mutation and EXIT cleanup leaves no asset residue' || bad 'missing mkdir is named before network mutation and EXIT cleanup leaves no asset residue'
run_missing_runtime_case dig && ok 'missing dig is named before network mutation and EXIT cleanup leaves no asset residue' || bad 'missing dig is named before network mutation and EXIT cleanup leaves no asset residue'

# C4 and D4 must expose the same complete connect-time command inventory.
EXPECTED_RUNTIME='awk cat chmod cmp cp cut dig dirname find flock gdbus getent grep ip jq ln mkdir mktemp mv nft nmcli pgrep readlink realpath rm rmdir sed sha256sum sleep sort stat tr wc wg'
for fn in mvc24gc4_dependencies mvc24gd4_dependencies; do
    log=$TMP/${fn}.commands
    : > "$log"
    set +e
    A="$A" LOG="$log" FN="$fn" bash -c '
set -euo pipefail
source "$A" --help >/dev/null
command() {
    if [[ ${1:-} == -v ]]; then
        printf "%s\\n" "${2:-}" >> "$LOG"
        return 0
    fi
    builtin command "$@"
}
"$FN"
' >"$TMP/${fn}.out" 2>&1
    rc=$?
    set -e
    observed=$(paste -sd' ' "$log")
    if (( rc == 0 )) && [[ $observed == "$EXPECTED_RUNTIME" ]]; then
        ok "$fn checks the complete connect-time command inventory"
    else
        printf 'expected: %s\nobserved: %s\n' "$EXPECTED_RUNTIME" "$observed" >&2
        bad "$fn checks the complete connect-time command inventory"
    fi
done

# C4 keeps an explicit missing-command diagnostic for OpenVPN-only admission too.
set +e
c4_out=$(A="$A" bash -c '
set -euo pipefail
source "$A" --help >/dev/null
command() {
    if [[ ${1:-} == -v ]]; then
        [[ ${2:-} != sleep ]]
        return
    fi
    builtin command "$@"
}
mvc24gc4_dependencies
' 2>&1)
c4_rc=$?
set -e
if (( c4_rc != 0 )) && grep -Fq 'missing prerequisite: sleep' <<<"$c4_out"; then
    ok 'OpenVPN C4 inventory reports the exact missing command'
else
    bad 'OpenVPN C4 inventory reports the exact missing command'
fi

printf 'RESULT: MVC 2.4.2 dependency/preflight cleanup regression %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
