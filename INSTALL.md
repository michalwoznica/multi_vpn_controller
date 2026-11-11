# Installation

## Host prerequisites

MVC uses NetworkManager for connection lifecycle and performs a complete connect-time command inventory during read-only admission, before it publishes a transaction or mutates nftables, routes, NetworkManager profiles, or VPN state. The host must provide these commands:

```text
awk cat chmod cmp cp cut dig dirname find flock gdbus getent grep ip jq ln
mkdir mktemp mv nft nmcli pgrep readlink realpath rm rmdir sed sha256sum
sleep sort stat tr wc wg
```

Command names are listed rather than distribution package names because package ownership differs across Linux distributions. Most of the longer list is ordinary base userspace; the explicit inventory exists so MVC can name a missing command before protected activation rather than discover it after mutation. OpenVPN modes additionally require NetworkManager OpenVPN support and a saved NetworkManager OpenVPN profile that MVC can use non-interactively.

The generated monolith also performs a smaller bootstrap check before materializing its private embedded resources in `/dev/shm`. Failed or successful lifecycle commands remove that scratch directory on process exit.

### Validated MVC 2.4.1 environment

MVC does not currently claim these as minimum supported versions. They are the exact versions on the Arch Linux host used for the final MVC 2.4.1 build reproducibility proof and physical release validation on 2026-11-11. If an older or substantially different userspace behaves differently, compare against this reference environment first.

| Runtime/tool | Validated version | Arch package |
| --- | --- | --- |
| Bash | 5.3.20 | `bash 5.3.20-1` |
| nftables (`nft`) | 1.1.7 | `nftables 1:1.1.7-3` |
| jq | 1.8.2 | `jq 1.8.2-1` |
| iproute2 (`ip`) | 7.3.0 | `iproute2 7.3.0-1` |
| NetworkManager (`nmcli`) | 1.58.1 | `networkmanager 1.58.1-2` |
| GLib / `gdbus` | 2.90.1 | `glib2 2.90.1-1` |
| util-linux (`flock`) | 2.42.4 | `util-linux 2.42.4-1` |
| wireguard-tools (`wg`) | 1.0.20260223 | `wireguard-tools 1.0.20260223-1` |
| procps-ng (`pgrep`) | 4.0.7 | `procps-ng 4.0.7-1` |
| GNU coreutils (`sha256sum`, `stat`, `sleep`) | 9.12 | `coreutils 9.12-2` |
| GNU Awk | 5.4.1 | `gawk 5.4.1-1` |
| GNU diffutils (`cmp`) | 3.12 | `diffutils 3.12-2` |
| OpenVPN | 2.7.8 | `openvpn 2.7.8-1` |
| NetworkManager OpenVPN plugin | 1.12.5 | `networkmanager-openvpn 1.12.5-2` |

`gdbus` itself does not expose a `--version` command in this environment; its reference version is therefore the providing `glib2` package version. MVC's AWK code intentionally uses a conservative, portable subset of AWK rather than GNU-only facilities, although the final release was validated with GNU Awk 5.4.1.

The 2.4.1 capture recorded the versions most relevant during release validation, not every base utility later surfaced by the stricter 2.4.2 command inventory. Utilities such as `dig`, `find`, `grep`, `sed`, and `getent` were present on the validated host where their code paths were exercised, but their exact package versions were not separately captured for the 2.4.1 release record.

## Boot policy

MVC 2.4.x is manually activated. It does **not** install an always-on early-boot guard or persistent boot kill switch. After a reboot, ordinary networking follows the host's normal baseline and is unprotected by MVC until the operator starts a protected MVC session. MVC same-boot ownership records under `/run/mvc-*` are intentionally ephemeral across reboot.

Build the controller first:

```bash
./source/build/build-mvc-monolith.sh ./dist/mvc
```

Install MVC:

```bash
sudo ./source/tools/install-mvc.sh install
```

Update an authenticated current or explicitly approved prior MVC installation:

```bash
sudo ./source/tools/install-mvc.sh update
```

Verify the installed file set:

```bash
sudo ./source/tools/install-mvc.sh verify
sudo /usr/local/sbin/mvc version --verbose
```

Remove the managed file set:

```bash
sudo ./source/tools/install-mvc.sh uninstall
```

The installer refuses package maintenance while MVC-managed runtime state or managed VPN links are present. Disconnect the active session first.

The installed files are:

```text
/usr/local/sbin/mvc
/root/mvc-emergency-rollback
/root/mvc-dual-recovery
```

The installer manages MVC installations only. `install` accepts only an absent destination or the exact current package identity. `update` also accepts explicitly approved prior MVC controller identities by exact SHA-256; version/banner strings are not trusted. Unrecognized or locally modified existing files are never overwritten.
