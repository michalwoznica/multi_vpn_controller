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

`mvc-emergency-rollback --rollback` is the catastrophic last-resort B4 disarm. In the 2.4.5 development line it remains a two-phase recovery operation: phase 1 independently removes only the three MVC B4 tables, then phase 2 attempts authenticated lifecycle finalization. B4 release never depends on the lifecycle journals being valid.

Use `--finalization-inspect` for a read-only lifecycle eligibility check. When B4 is still present, this mode does **not** authorize or perform its removal; it conditionally reports whether the retained MVC lifecycle would be finalizable **after a successful B4 disarm**. `ELIGIBLE AFTER B4 DISARM` therefore means only that the post-disarm lifecycle checks pass. The mutating finalizer still requires B4 to be actually absent. If B4 is already absent and a prior rollback stopped before lifecycle retirement completed, use `--finalize` to resume only the authenticated post-disarm finalization step.

Full emergency-recovery success requires the retained same-boot session marker/journals to authenticate, all live VPN/WireGuard/tunnel and proto-186/proto-187 residue to be absent, no IPv6 default route, and any surviving `vpnks-ovpn` profile to be the exact authenticated inactive MVC clone. Before that clone can be deleted, the tool copies the failed-session evidence into a root-only same-boot archive under `/run/mvc-recovered/<session-marker-sha256>/`. A clone-delete attempt is journalled before mutation and is never blindly retried after an ambiguous outcome. Once managed network residue is independently proven absent, a retirement plan is published and fixed live MVC roots are removed with `/run/mvc-public-session` retired last.

`RESULT: EMERGENCY RECOVERY COMPLETE — MVC OWNED STATE RETIRED` means stale MVC authority no longer blocks a new same-boot attempt. It does **not** bypass normal admission: a later `mvc connect` still starts from the ordinary strict preflight rules. If the tool reports finalization incomplete, the B4 disarm may still have succeeded but retained MVC authority remains blocking. Do not use normal `mvc disconnect` as a post-emergency finalizer; address the reported residue (for example with the independent dual-recovery tool when authenticated WireGuard residue remains), then rerun `--finalize` if appropriate, or reboot as the fallback.

The R2 finalizer intentionally supports only the mature retained-session states classified by R1. Pre-mutation/partial-start emergency finalization remains deferred.

## NetworkManager route refresh

On some NetworkManager configurations a physical default route may temporarily retain a raised metric after a protected session has otherwise been retired. If all MVC-managed state is gone, NetworkManager can be asked to reevaluate connectivity:

```bash
nmcli networking connectivity check
nmcli --colors no -f STATE,CONNECTIVITY general status
ip -4 route show default
```

This refresh is intentionally not performed silently by the read-only `verify` command.
