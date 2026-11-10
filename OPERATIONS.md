# Operations

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

Disconnect authenticates exact same-boot ownership from MVC runtime records under `/run/mvc-*` before mutation.

In 2.4.1, a published combined session can also be reconciled when one tunnel has already disappeared. The intended operator workflow is:

1. run `disconnect` once;
2. if it succeeds, run `verify` and start a fresh session if desired;
3. if it refuses or fails, do not repeatedly retry or start another session—inspect the recovery tools first.

No automatic reconnect or watchdog is provided.

## Recovery inspection

```bash
sudo /root/mvc-dual-recovery --inspect
sudo /root/mvc-emergency-rollback --inspect
```

Use a recovery mutation only when its inspector authenticates the corresponding owned residue. The independent recovery tools deliberately have narrower authority than the main controller.

## NetworkManager route refresh

On some NetworkManager configurations a physical default route may temporarily retain a raised metric after a protected session has otherwise been retired. If all MVC-managed state is gone, NetworkManager can be asked to reevaluate connectivity:

```bash
nmcli networking connectivity check
nmcli --colors no -f STATE,CONNECTIVITY general status
ip -4 route show default
```

This refresh is intentionally not performed silently by the read-only `verify` command.
