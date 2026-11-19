# Contributing to Multi VPN Controller

Thank you for considering a contribution to Multi VPN Controller (MVC).

MVC changes Linux routing, firewall and VPN state, so changes are reviewed conservatively. Small, clearly scoped pull requests are preferred over broad refactors.

## Before opening a pull request

1. Start from the current `master` branch and create a topic branch.
2. Keep the change narrowly focused.
3. Do not edit generated `dist/mvc` directly. The maintainable implementation lives under `source/`.
4. If a production input listed in `source/build/monolith-runtime.manifest` changes, update its declared SHA-256 entry deliberately and rebuild the monolith.
5. Run the public regression suite before submitting the pull request.
6. Remove credentials, private keys, hostnames, SSIDs, usernames, host-specific interface names and other private environment information from code, fixtures, logs and documentation.

## Local validation

From the repository root, build the generated executable first:

```bash
mkdir -p dist
./source/build/build-mvc-monolith.sh ./dist/mvc
```

Then run the public regression suite:

```bash
sudo ./source/tests/run-tests.sh
```

The installer regression verifies root ownership inside an isolated fake root, which is why the complete suite is run as root. The tests are designed to be hermetic and must not establish real VPN connections or mutate the host's live network configuration.

For an independent deterministic-build check:

```bash
A=$(mktemp)
B=$(mktemp)
./source/build/build-mvc-monolith.sh "$A"
./source/build/build-mvc-monolith.sh "$B"
cmp "$A" "$B"
cmp "$A" ./dist/mvc
sha256sum "$A" "$B" ./dist/mvc
rm -f "$A" "$B"
```

## Runtime changes

Changes affecting routing, DNS, nftables, NetworkManager, WireGuard, OpenVPN, disconnect/recovery behavior, persistent record formats, or generated runtime composition require additional scrutiny.

Passing the public regression suite is necessary but does not by itself prove live networking behavior. A release containing runtime changes may require explicit physical validation on a real host before it can be promoted as stable.

Do not weaken fail-closed behavior merely to make an unsupported environment pass admission. Compatibility changes should preserve the security properties that the admission checks are intended to prove.

## Generated artifact and manifest

`source/build/monolith-runtime.manifest` is the authoritative ordered composition contract for the generated controller. Module order is runtime-significant because later Bash definitions can intentionally replace earlier definitions.

Do not casually reorder manifest entries. See `BUILDING.md` for the build contract.

## Pull requests

In the pull request, describe:

- what changed and why;
- whether VPN routing, DNS, firewall, installation, disconnect/recovery, or generated `dist/mvc` behavior changes;
- the tests you ran;
- any live-host validation performed, if applicable.

The repository CI runs syntax checks, deterministic monolith construction and the public regression suite. CI does not establish real VPN sessions.

## Security vulnerabilities

Do not disclose suspected security vulnerabilities in a public issue or pull request. Follow `SECURITY.md` and use GitHub private vulnerability reporting instead.

## Releases

Maintainer release procedure is documented in `docs/RELEASING.md`.
