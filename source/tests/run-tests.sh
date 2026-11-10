#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SOURCE=$(cd -- "$HERE/.." && pwd -P)
PROJECT=$(cd -- "$SOURCE/.." && pwd -P)

TESTS=(
  test-builder.sh
  test-runtime-seams.sh
  test-verifier.sh
  test-cli-verify.sh
  test-structural-equivalence.sh
  test-partial-wireguard-reconciliation.sh
  test-incomplete-openvpn-reconciliation.sh
  test-openvpn-dropout-disconnect.sh
  test-wireguard-dropout-disconnect.sh
  test-generated-dropout-disconnect.sh
  test-installer.sh
  test-public-tree-sanitization.sh
  test-public-identity.sh
  test-runtime-identity.sh
  test-nonpersistent-literal-cleanup.sh
)

passed=0
for test_name in "${TESTS[@]}"; do
  printf '\n==> %s\n' "$test_name"
  (cd "$SOURCE" && bash "$HERE/$test_name")
  passed=$((passed + 1))
done
printf '\nRESULT: public regression suite %d/%d tests passed\n' "$passed" "${#TESTS[@]}"
