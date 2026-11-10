# Changelog

## 2.4.1

- Allow authenticated `disconnect` to reconcile a published combined session when OpenVPN has disappeared while WireGuard survives.
- Allow authenticated `disconnect` to reconcile the inverse case where WireGuard has disappeared while OpenVPN remains healthy.
- Preserve same-boot ownership authentication and fail-closed behavior; no automatic reconnect or watchdog was added.
- Make the read-only verifier profile-driven instead of probing hard-coded private destinations.
- Add a public-tree sanitization regression and separate private development handoff material from the Git-facing source tree.

## 2.4.0

- Add OpenVPN-only mode.
- Add protected WireGuard-only mode.
- Add split WireGuard-only mode.
- Add combined OpenVPN + split WireGuard mode.
- Add coordinated nftables protection for protected sessions.
- Add deterministic monolithic release generation and an integrated read-only verifier.
- Add independent emergency and dual-session recovery tools.
