# Operations

## Boot and activation policy

MVC 2.4.x uses manual activation. There is no always-on early-boot MVC guard and no persistent boot kill switch. After reboot, ordinary networking is therefore unprotected by MVC until a protected session is explicitly started. Runtime ownership records under `/run/mvc-*` are same-boot state and do not persist across reboot.

## Read-only commands

```bash
sudo mvc list
sudo mvc status
sudo mvc verify
sudo mvc verify --no-internet-check
```

`status` is deliberately conservative and does not grant lifecycle authority. `verify` reports observed NetworkManager state, managed links, routes, DNS, guard tables and runtime roots.

## Connecting

```bash
# OpenVPN only
sudo mvc connect <openvpn-profile>

# WireGuard protected
sudo mvc connect <wireguard-profile>

# WireGuard split
sudo mvc connect <wireguard-profile> --split

# Combined OpenVPN + split WireGuard
sudo mvc connect <wireguard-profile> --split <openvpn-profile>
```

Use `preflight` with the same arguments before a connection when you want a read-only admission check.

## Disconnecting

```bash
sudo mvc disconnect
```

Disconnect authenticates exact same-boot ownership from MVC runtime records under `/run/mvc-*` before mutation. Once ownership is established, teardown is convergence-driven: already-missing or degraded MVC-owned tunnel/profile/route state is treated as cleanup input rather than as a reason to demand the historical fully-active shape.

The current physical/IPv4 topology is not a restoration target during disconnect. A different interface, address, gateway or route metric, multiple ordinary IPv4 defaults, or no IPv4 default may all be accepted after MVC-owned state is removed. Teardown still fails closed when MVC cannot authenticate ownership, foreign/ambiguous managed state would need mutation, an IPv6 default route is present, MVC-reserved routes remain, nftables safety cannot be proven, or an owned cleanup/finalization result cannot be classified safely.

A successful disconnect means MVC-owned live state and authority have been retired. It does **not** guarantee that the host's current topology will pass a new `connect`; a fresh same-boot connection attempt runs the normal strict admission checks again.

The intended operator workflow is:

1. run `disconnect` once;
2. if it succeeds, run `verify` if desired and make a fresh connection attempt when needed;
3. if it refuses or fails, treat that as an exceptional convergence failure: do not repeatedly retry or start another session, and inspect the packaged recovery tools first.

No automatic reconnect or watchdog is provided.

## Recovery inspection

```bash
sudo /root/mvc-dual-recovery --inspect
sudo /root/mvc-emergency-rollback --inspect
```

Use a recovery mutation only when its inspector authenticates the corresponding owned residue. The independent recovery tools deliberately have narrower authority than the main controller.

`mvc-emergency-rollback --rollback` is the catastrophic last-resort B4 disarm. In MVC 2.4.4 it does **not** perform full lifecycle retirement: failed-session journals are intentionally retained for evidence, normal `mvc disconnect` must not be used as a post-rollback finalizer, and the host must be rebooted before starting another MVC session. Same-boot reuse after a successful catastrophic recovery is deferred to a later release.

## NetworkManager route refresh

On some NetworkManager configurations a physical default route may temporarily retain a raised metric after a protected session has otherwise been retired. If all MVC-managed state is gone, NetworkManager can be asked to reevaluate connectivity:

```bash
nmcli networking connectivity check
nmcli --colors no -f STATE,CONNECTIVITY general status
ip -4 route show default
```

This refresh is intentionally not performed silently by the read-only `verify` command.
