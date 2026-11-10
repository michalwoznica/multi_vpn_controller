# Multi VPN Controller

Multi VPN Controller (MVC) 2.4.x is a Bash-based NetworkManager controller for fail-closed OpenVPN and WireGuard sessions on Linux.

## Supported modes

```bash
sudo mvc connect <openvpn-profile>
sudo mvc connect <wireguard-profile>
sudo mvc connect <wireguard-profile> --split
sudo mvc connect <wireguard-profile> --split <openvpn-profile>
```

The four modes are:

- **OpenVPN only** — ordinary Internet traffic and DNS use OpenVPN.
- **Protected WireGuard only** — WireGuard AllowedIPs use WireGuard and ordinary Internet is blocked while the protected session is active.
- **Split WireGuard only** — WireGuard AllowedIPs use WireGuard while ordinary Internet remains on the physical connection.
- **Combined** — ordinary Internet and DNS use OpenVPN while WireGuard AllowedIPs use WireGuard in parallel.

IPv6 Internet traffic is blocked during protected sessions. MVC uses nftables and authenticated same-boot runtime state to avoid silently falling back to an unprotected path.

## Source and release model

The maintainable implementation lives under `source/`. `dist/mvc` is generated deterministically and is intentionally ignored by Git. Build it with:

```bash
./source/build/build-mvc-monolith.sh ./dist/mvc
```

See [BUILDING.md](BUILDING.md) for the build and release workflow.

## Installation

See [INSTALL.md](INSTALL.md). The release installer manages:

```text
/usr/local/sbin/mvc
/root/mvc-emergency-rollback
/root/mvc-dual-recovery
```

The recovery tools remain independent of the main executable.

## Operations

See [OPERATIONS.md](OPERATIONS.md) for normal use, verification, partial tunnel-loss handling and recovery boundaries.

## Security model

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tests

Run the curated public regression suite from the repository root:

```bash
./source/tests/run-tests.sh
```

The suite is hermetic and does not require live VPN activation.

## Internal compatibility names

The public project identity is **Multi VPN Controller** and the command is `mvc`. Runtime-visible MVC ownership uses `/run/mvc-*` and `mvc_preclone_*`. Internal Bash functions/helpers use the `mvc24*` namespace and internal variables/constants use `MVC24*`. Current authenticated record signatures are MVC-native and runtime module filenames are version-neutral. Explicit recognition of the physically proven pre-MVC installation remains only where required for safe migration compatibility.
