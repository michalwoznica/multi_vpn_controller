# Changelog

## 2.4.1

- Adopt the **Multi VPN Controller** product identity and the `mvc` command.
- Generate the release artifact as `dist/mvc` and install it as `/usr/local/sbin/mvc`.
- Publish independent recovery tools as `/root/mvc-emergency-rollback` and `/root/mvc-dual-recovery`.
- Move same-boot runtime roots to `/run/mvc-*` and MVC-owned B4 nftables tables to the `mvc_preclone_*` namespace.
- Migrate lowercase internal Bash function/helper names from the legacy `ubs24*` namespace to `mvc24*` without changing persistent record formats.
- Migrate uppercase internal Bash variable/constant names from the legacy `UBS24*` namespace to `MVC24*` without changing persistent record formats.
- Allow authenticated `disconnect` to reconcile a published combined session when OpenVPN has disappeared while WireGuard survives.
- Allow authenticated `disconnect` to reconcile the inverse case where WireGuard has disappeared while OpenVPN remains healthy.
- Preserve same-boot ownership authentication and fail-closed behavior; no automatic reconnect or watchdog was added.
- Make the read-only verifier profile-driven instead of probing hard-coded private destinations.
- Keep private development handoff material separate from the Git-facing source tree.

## 2.4.0

- Add OpenVPN-only mode.
- Add protected WireGuard-only mode.
- Add split WireGuard-only mode.
- Add combined OpenVPN + split WireGuard mode.
- Add coordinated nftables protection for protected sessions.
- Add deterministic monolithic release generation and an integrated read-only verifier.
- Add independent emergency and dual-session recovery tools.
