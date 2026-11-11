# Multi VPN Controller

## What is Multi VPN Controller?

**Multi VPN Controller (MVC)** is a Linux command-line tool for securely running WireGuard and OpenVPN connections independently or at the same time.

MVC grew out of a practical problem.

I normally use OpenVPN to route my Internet traffic through a VPN provider. This helps protect traffic on untrusted networks, reduces the amount of information exposed to the local ISP, and makes it possible to use VPN endpoints in different countries when needed.

At the same time, I sometimes need WireGuard to reach a private remote network.

That private network is deliberately configured so that WireGuard clients can access its internal resources but cannot use it as an Internet gateway. This is a useful security property, but it created an inconvenient workflow: while connected to WireGuard I could reach the private network but had no ordinary Internet access. If I needed to research something online, I had to disconnect WireGuard, connect OpenVPN, do the research, disconnect again, and reconnect WireGuard.

MVC was created to remove that limitation without turning the private WireGuard network into an Internet gateway.

In its combined mode, MVC keeps the two VPNs separate:

- private networks explicitly assigned to the WireGuard profile are routed through WireGuard;
- ordinary Internet traffic is routed through OpenVPN;
- the WireGuard endpoint itself remains reachable through the physical network underneath both tunnels.

The result is that a machine can remain connected to a private WireGuard network while simultaneously using an OpenVPN connection for normal Internet access. The OpenVPN profile can also be changed independently, making it possible to use different VPN exit countries without changing how the private network is reached.

## What MVC can do

MVC currently supports four practical connection styles:

- **Combined protected mode** — WireGuard carries only its configured private networks while ordinary Internet traffic goes through OpenVPN.
- **OpenVPN-only protected mode** — ordinary Internet traffic uses OpenVPN with a dedicated kill switch.
- **WireGuard-only protected mode** — only the WireGuard connection is permitted and ordinary Internet access is blocked.
- **WireGuard split mode** — selected private networks use WireGuard while ordinary Internet traffic continues over the normal physical connection.

MVC is intentionally a **CLI application**. It is designed for Linux systems using NetworkManager and integrates directly with the existing OpenVPN and WireGuard connection profiles rather than introducing its own VPN configuration format.

## Security model

MVC does more than bring VPN interfaces up and down. A significant part of the project is concerned with ensuring that traffic cannot silently escape through an unintended path while a protected session is active.

Among its security measures are:

- an nftables-based kill switch protecting both host output and forwarded traffic;
- coordinated firewall state during connection setup, operation, teardown, and failure recovery;
- explicit routing of WireGuard private networks rather than allowing WireGuard to become an unintended default Internet route;
- pinning of VPN endpoints to the physical underlay where necessary so tunnel setup does not recursively route through another tunnel;
- blocking of ordinary IPv6 Internet traffic while protected modes are active;
- protection against traffic bypass through containers or other network namespaces by controlling forwarding as well as host output;
- use of the OpenVPN-provided DNS configuration while an OpenVPN Internet path is active;
- reuse of NetworkManager-managed OpenVPN credentials without copying passwords into MVC or introducing an interactive credential fallback;
- authenticated same-boot session ownership, allowing MVC to distinguish its own runtime state from unrelated networking state before performing teardown;
- fail-closed handling of interrupted or partially lost combined sessions;
- recovery tools kept separately from the normal controller for exceptional failure cases.

MVC also deliberately does **not** implement an automatic VPN watchdog or automatic reconnection policy. If part of a published combined session disappears, the normal `mvc disconnect` path is designed to authenticate the remaining MVC-owned state, clean it up safely, restore baseline networking, and allow a fresh connection in the same boot.

## Scope and operating model

MVC is designed to be explicit rather than always-on.

Starting a protected session is a deliberate user action. After a reboot there is no persistent early-boot kill switch, and normal networking is therefore available until MVC is started again. This behavior is intentional and documented rather than hidden behind an assumption of permanent VPN protection.

The project is built as a readable Bash codebase with a deterministic build process that produces a single `mvc` executable for installation. It uses standard Linux networking tools including NetworkManager, nftables, iproute2, WireGuard, OpenVPN, jq, and AWK.

The current release has been developed and physically validated on Linux with real OpenVPN and WireGuard connections, including simultaneous dual-tunnel operation, kill-switch behavior, tunnel-loss cleanup, same-boot reconnection, deterministic local builds, and restoration of the original network state after disconnect.

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

## Boot policy

MVC is manually activated and does not provide an always-on early-boot guard. After reboot, ordinary networking is not protected by MVC until the operator starts a protected session. Same-boot MVC ownership state under `/run/mvc-*` is intentionally ephemeral.

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

## Security documentation

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tests

Run the curated public regression suite from the repository root:

```bash
./source/tests/run-tests.sh
```

The suite is hermetic and does not require live VPN activation.

## Internal compatibility names

The public project identity is **Multi VPN Controller** and the command is `mvc`. Runtime-visible MVC ownership uses `/run/mvc-*` and `mvc_preclone_*`. Internal Bash functions/helpers use the `mvc24*` namespace and internal variables/constants use `MVC24*`. Current authenticated record signatures are MVC-native and runtime module filenames are version-neutral. The public project contains no predecessor-specific migration compatibility; any private development-host migration is handled outside the Git-facing tree.

## License

Copyright (C) 2026 [michalwoznica](https://github.com/michalwoznica).

Multi VPN Controller is free software licensed under the **GNU General Public License version 3 or any later version** (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the full licence text.
