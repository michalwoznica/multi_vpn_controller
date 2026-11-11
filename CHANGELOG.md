# Changelog

## MVC 2.4.2 R1 dependency preflight and scratch cleanup

- Add an explicit builder prerequisite inventory that reports the exact missing build tool before creating the requested output path.
- Add a monolith bootstrap prerequisite inventory before embedded runtime resources are materialized in `/dev/shm`.
- Install process-level EXIT cleanup for `/dev/shm/mvc-monolith-assets.*`, removing successful and failed initialization scratch state.
- Expand OpenVPN and WireGuard read-only admission to the same complete connect-time command inventory, including previously implicit utilities such as `dig`, `mkdir`, `cp`, `cut`, `sed`, `sort`, `wc`, and `realpath`.
- Report the exact missing runtime command and reject the connection before MVC publishes a transaction or mutates nftables, routes, NetworkManager profiles, or VPN state.
- Add hermetic regressions for missing bootstrap tools, `jq`, `nft`, `mkdir`, and `dig`, command-inventory completeness, no network-command execution before dependency failure, and no leaked monolith asset directory.
- Keep disconnect authentication/recovery semantics unchanged; the broad connect-time inventory is not imposed as a new prerequisite for authenticated teardown.

## MVC R14 final 2.4.1 release promotion

- Promote the generated controller to stable `MVC_V241_RELEASE` / `audited-dispatch-mvc-v241-release` provenance; the executable no longer self-labels as a candidate or claims that physical validation is pending.
- Keep validation evidence explicitly hash-specific rather than embedding mutable test-status claims in the executable.
- Allow `install-mvc.sh update` to authenticate the exact physically proven R8 controller hash as an approved predecessor, while retaining the existing exact R7 predecessor and refusing unknown or modified controllers.
- Extend installer regression coverage to reconstruct the exact R8 artifact (`594b4f747db4dd6cd7d3efe86994a3027f672c30db80749ffbca0c4113ec2edd`) and prove R8 -> final 2.4.1 promotion through the real update path.
- No VPN lifecycle module, nftables resource, routing/DNS policy, persistent record schema, read-only verifier, or recovery-tool content changed.

## MVC R9 authenticated update path

- Keep the physically proven R8 controller/runtime artifact unchanged.
- Allow `install-mvc.sh update` to replace an explicitly approved prior MVC controller identity by exact SHA-256 while continuing to refuse unknown or modified controllers.
- Keep `install` conservative: an approved prior controller is not silently replaced and must use the explicit `update` action.
- Add deterministic regression coverage that reconstructs the exact R7 artifact, proves its known hash, proves `install` refuses it, and proves `update` atomically promotes it to R8.
- No VPN lifecycle, nftables, routing, DNS, NetworkManager, recovery-tool, persistent-record, or generated-controller bytes changed.

## MVC R8 bootstrap resource pin repair

- Repair the B1/B2 security hash pins so they match the current MVC bootstrap nft resource.
- Add an end-to-end regression that exercises the real B1 render and B2 batch validator against the manifest-declared embedded resource.
- No nft rule semantics or VPN lifecycle policy changed; this repairs a deterministic pre-mutation connect refusal introduced when the resource identity changed during the MVC refactor.

## 2.4.1
- Make the public project standalone: remove predecessor-specific installer migration, hashes, runtime-root checks, and exact historical record fixtures from the Git-facing tree; retain one-time development-host migration details only in ignored handoff material.
- Complete the final identity audit and keep current production/build/docs MVC-native.
- Rename the eight remaining version-tagged runtime/loader module filenames to version-neutral names, updating only manifest/build/loader/test path references.

- Rename the non-module nftables runtime resource and read-only OpenVPN helper to MVC-native filenames without changing their content or runtime behavior.

- Remove the unused draft combined-state serializer/parser and its retired legacy record magic; active dual-session parsing helpers remain unchanged.

- Migrate the central public transaction and active ownership markers to version-independent `mvc-...-v1` magic, keeping the dormant combined-state draft deferred.

- Migrate the C19 normal/already-absent OpenVPN-stop records and the C23T release/clone-delete/archive-plan completion chain to version-independent `mvc-...-v1` magic without changing record fields or lifecycle behavior.

- Migrate the D4 WireGuard ownership intent and protected-WG release record to version-independent `mvc-...-v1` magic, updating normal disconnect and the independent dual-recovery consumer atomically.

- Migrate the public preclone / early OpenVPN reconciliation record family to version-independent `mvc-...-v1` magic, including dynamically generated stop and clone-delete records, without changing record fields or lifecycle behavior.

- Migrate the first authenticated same-boot record chain (B2/C1/C7/C13) to version-independent `mvc-...-v1` record magic while preserving field schemas and downstream behavior.

- Complete MVC-R4 non-persistent legacy literal cleanup: update residual public CLI messages, modular recovery identity, fixed-root seam, confirmation phrases, comments, and transient scratch names without changing authenticated journal signatures or legacy-install migration compatibility.

- Adopt the **Multi VPN Controller** product identity and the `mvc` command.
- Generate the release artifact as `dist/mvc` and install it as `/usr/local/sbin/mvc`.
- Publish independent recovery tools as `/root/mvc-emergency-rollback` and `/root/mvc-dual-recovery`.
- Move same-boot runtime roots to `/run/mvc-*` and MVC-owned B4 nftables tables to the `mvc_preclone_*` namespace.
- Migrate lowercase internal Bash function/helper names from the previous lowercase helper namespace to `mvc24*` without changing persistent record formats.
- Migrate uppercase internal Bash variable/constant names from the previous internal uppercase namespace to `MVC24*` without changing persistent record formats.
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
