## MVC 2.4.5 emergency recovery same-boot reuse — R1 read-only finalization classifier

- Begin the 2.4.5 development line from the exact physically validated and released MVC 2.4.4 runtime baseline.
- Extend the independent emergency recovery tool with a new read-only `--finalization-inspect` mode; the existing B4 `--rollback` mutation remains unchanged and independent of normal controller journals.
- Authenticate retained same-boot recovery state across mature combined, OpenVPN-only, protected-WireGuard and split-WireGuard sessions using the public marker plus the mode-appropriate immutable journal hashes.
- Allow a combined-session marker to retain historical D4 hash evidence after authenticated WireGuard teardown has already retired the live D4 journal; WireGuard-only recovery continues to require live hash-authenticated D4 evidence.
- Classify finalization eligibility only when B4 is absent, no MVC or foreign VPN/tunnel remains active, proto-186/proto-187 routes are absent, no IPv6 default route exists, live runtime roots are safe/unbusy, WireGuard temporary residue is gone, and any surviving OpenVPN temporary clone is the exact authenticated inactive MVC clone.
- Treat an exact inactive authenticated OpenVPN clone as future finalizer cleanup work rather than an eligibility failure; ambiguous clone identity remains blocked.
- Explicitly defer pre-mutation/partial-start finalization in R1 rather than inferring new cleanup authority from incomplete ownership evidence.
- Keep R1 read-only: it does not archive journals, delete profiles, retire live MVC authority, or permit same-boot reuse after emergency rollback yet. Reboot remains required after rollback until a later checkpoint implements authenticated finalization.
- Authorize the exact released MVC 2.4.4 controller and emergency-recovery hashes as authenticated update predecessors for the 2.4.5 package.

# Changelog
## MVC 2.4.4 release-candidate physical validation
- Physically validate the exact integrated 2.4.4 candidate executable SHA-256 `c659143883ddf900ddba4aa4c6cd74edd761b820be5b1d51bb335cdcbf9c31db` on the development host after authenticated update from the earlier 2.4.4 diagnostic candidate. Installation verification and the pre-session baseline were clean.
- Prove a normal protected parallel OpenVPN + split-WireGuard session end-to-end: ordinary Internet and DNS used OpenVPN while configured private destinations remained reachable through WireGuard.
- Reproduce the original same-interface Wi-Fi underlay/profile replacement incident while the combined session was active. OpenVPN disappeared, WireGuard survived, ordinary Internet became unusable under B4 protection, and the host entered the same degraded class that previously stranded teardown.
- Prove the 2.4.4 convergence fix physically: ordinary authenticated `mvc disconnect` logged physical/IPv4 topology drift as a warning, converged the degraded session without either recovery tool, removed all MVC-owned temporary profiles, links, routes, B4 tables and live runtime authority, and restored ordinary connectivity.
- Prove same-boot reuse after successful convergent disconnect: once the host topology again satisfied normal admission, combined preflight passed, a fresh same-boot combined session started successfully, and its ordinary authenticated disconnect returned to a clean MVC-free baseline.
- Final verification after the campaign showed no managed VPN/WireGuard/tun state, no MVC-reserved routes, B4 `0/3`, no fixed live runtime roots, normal DNS/Internet, and both recovery inspectors clean. The exact physically validated executable hash is unchanged from the R11 integrated candidate.
- No emergency recovery was required. Same-boot reuse after catastrophic emergency rollback remains intentionally deferred to MVC 2.4.5; in 2.4.4 emergency rollback remains terminal for the boot.

## MVC 2.4.4 final integration and release-facing convergence contract
- Complete the post-R10 integration audit across OpenVPN-only, protected WireGuard-only, split WireGuard-only and combined teardown. Remaining disconnect hard stops are limited to authenticated ownership/journal failure, foreign or ambiguous managed state, unprovable nftables/final-safety state, or cleanup/finalization outcomes that cannot be safely classified. No additional runtime convergence gap was found.
- Correct release-facing disconnect semantics after the current-underlay policy change: successful teardown now reports that MVC-owned state has been retired rather than claiming a fresh connection is automatically eligible. A later same-boot `connect` attempt must independently pass normal strict admission.
- Clarify that authenticated disconnect converges MVC-owned state without requiring the current physical interface, IPv4 address/gateway/default-route set or route metric to match the pre-connect snapshot. The final safety boundary still rejects IPv6 default routing, residual MVC-reserved routes, foreign/ambiguous managed state and unprovable firewall state.
- Remove the obsolete R3 source comment that described emergency B4 disarm followed by `mvc disconnect`. The MVC 2.4.4 catastrophic-recovery boundary remains: emergency rollback is terminal for the boot and reboot is required before another MVC session.
- Update README, OPERATIONS, architecture, security and release-validation documentation to distinguish MVC-owned cleanup from host-topology restoration and to describe recovery as exceptional rather than part of normal disconnect.
- Add a release-facing contract regression preventing future documentation/CLI drift around fresh-connect eligibility, original-topology restoration and post-emergency finalization.

## MVC 2.4.4 disconnect convergence refactor — stage 6
- Make authenticated OpenVPN teardown convergence-driven when the exact MVC-owned temporary clone is still active but its historical tun/default-route/DNS shape has degraded. The immutable public-session/clone identity remains the ownership authority; degraded routing or DNS is diagnostic rather than a reason to strand cleanup.
- Add an exact owned-active OpenVPN observation that accepts only the authenticated `vpnks-ovpn` clone, optional MVC tun state, and—in combined mode—the authenticated MVC WireGuard survivor. Foreign managed VPN/tap/ppp/WireGuard state remains a hard refusal before mutation.
- For an authenticated active clone, publish the existing C19 normal-stop intent, perform the C11→C1 firewall handback, issue one bounded NetworkManager stop for that exact clone, then judge success from the observed no-active-VPN/C1 post-state rather than from the command exit status alone.
- Generalize combined WireGuard-first reconciliation for degraded OpenVPN sessions: authenticated WG residue is converged to C11 plus private proto-187 holds without requiring the old OpenVPN default-route/DNS shape to remain healthy before the owned OpenVPN clone is stopped.
- Preserve the truthful already-absent OpenVPN path, early OpenVPN-start reconciliation, final C23T safety checks, foreign nftables protection, and the R7 emergency-recovery boundary. Ambiguous clone identity or foreign VPN state remains fail-closed.
- Add focused degraded-OpenVPN regression coverage and update existing dropout/convergence orchestration tests to the new convergence coordinator order.

## MVC 2.4.4 disconnect convergence refactor — stage 5
- Make authenticated standalone WireGuard partial-start states normally disconnectable instead of immediately forcing the recovery tools. The public prepared transaction remains the same-boot ownership root; cleanup authority is granted only where retained journals and live observations prove the exact MVC-owned state.
- For split WireGuard, once the immutable D4 intent exists, reuse the existing convergence-aware split stop path for partial profile/endpoint-route/activation outcomes. A missing or malformed D4 intent remains fail-closed.
- For protected WireGuard, admit the raw authenticated B2 guard as a legitimate partial-start teardown state in addition to the full protected guard and already-absent guard. The D4 convergence engine then removes any authenticated temporary WG/profile/proto-186 residue before guard release.
- Cover the earlier protected-WG interval where B2 exists before D4 publication with a dedicated normal-disconnect release journal. Its release intent is published before B2 deletion and is hash-bound to the public transaction, B2 prepare record, and exact delete batch; current physical-link/IPv4 topology is diagnostic only.
- Preserve the R7 catastrophic-recovery boundary: B4 absence without an already-published normal-disconnect release intent is not adopted as cleanup authority and still requires reboot. Ambiguous/incomplete B2 journal or guard state also remains fail-closed.
- Change failed standalone-WG start guidance to direct the operator to normal `mvc disconnect` first. Recovery remains the fallback only when authenticated convergence itself refuses.
- Add focused partial-start regression coverage and extend persistent-record namespace coverage for the new protected-WG pre-D4 release record.

## MVC 2.4.4 disconnect convergence refactor — stage 4
- Complete the R6 current-final-safety policy for standalone WireGuard split teardown. Split runtime retirement no longer requires traffic to `1.1.1.1` to resolve through the originally admitted interface/source/gateway after authenticated MVC-owned WG residue is removed.
- Add `mvc24gws_final_safety_witness()` and reuse the shared post-session safety witness already used by combined teardown, protected standalone WireGuard, and early OpenVPN reconciliation. Changed interface/gateway/address, multiple ordinary IPv4 defaults, or no IPv4 default therefore remain warning/diagnostic conditions during split teardown rather than cleanup blockers.
- Preserve split connect-time admission and active-state observation unchanged: a running split session must still prove the originally admitted ordinary Internet route while being established/observed.
- Preserve hard teardown blockers for unexpected B4 state, IPv6 default routing, MVC-reserved proto-186/proto-187 residue, and authenticated ownership/profile/kernel conflicts.
- Add focused regression coverage proving split retirement has no hidden dependency on the original Internet route while connect-time active-state verification remains strict.

## MVC 2.4.4 emergency recovery boundary
- Remove the provisional R3 post-emergency lifecycle-finalization subsystem from normal `mvc disconnect`; B4 absence no longer grants authority to archive failed-session journals, delete an inactive OpenVPN clone, retire the public-session marker, or claim same-boot reuse.
- Restore `/root/mvc-emergency-rollback` as a narrow independent catastrophic B4 disarm. After a successful emergency disarm, failed-session evidence is intentionally retained and the operator must reboot before starting another MVC session.
- Preserve normal crash-resume semantics: if an authenticated normal teardown had already published its own guard-release intent before interruption, subsequent `mvc disconnect` may continue that normal teardown even when B4 is already absent.
- Add an explicit emergency-boundary classifier so an authenticated protected session with B4 absent and no normal guard-release intent refuses before OpenVPN/WireGuard/profile mutation with `emergency-disarm-reboot-required`.
- Remove the provisional `mvc-c24b-breakglass-*` record namespace and the public CLI success result that advertised post-emergency same-boot readiness.
- Keep the released 2.4.3 emergency tool and the exact R6 emergency-tool bytes as authenticated installer update predecessors.
- Same-boot MVC reuse after successful catastrophic recovery remains an explicit design goal, deferred to 2.4.5 where recovery success can be defined as complete lifecycle recovery rather than B4 disarm alone.

## MVC 2.4.4 disconnect convergence refactor — stage 3
- Replace post-session byte-for-byte physical-link/IPv4 restoration with the owner-approved final-safety convergence policy. Once the same-boot MVC session is authenticated, saved B2 link/IPv4 snapshots remain admission/forensic evidence rather than teardown restoration targets.
- Accept changed physical interface, address, gateway, route metric, multiple ordinary IPv4 defaults, or no IPv4 default at all during authenticated teardown. These conditions are diagnostic topology drift and no longer block cleanup or B4 release by themselves.
- Preserve strict connect/preflight admission unchanged: starting a fresh protected session still requires the narrow supported baseline, including exactly one IPv4 default and no IPv6 default. Disconnect success therefore does not imply the current host is immediately eligible for a new connect.
- Introduce a shared post-session safety witness used by combined finalization, protected standalone WireGuard teardown, and early OpenVPN/preclone reconciliation. It takes two live observations, requires both to have no IPv6 default route, requires MVC-reserved proto-186/proto-187 routes absent, and preserves transition-journal integrity where applicable.
- Emit a one-time warning when current physical-link/IPv4 topology differs from the pre-connect snapshot, but continue cleanup. Remove the obsolete teardown-only NetworkManager `+20000` route-metric equivalence exception because IPv4 restoration is no longer a release prerequisite.
- Keep foreign nftables policy, active-VPN absence, session/lock authentication, owned-resource cleanup, and no-IPv6-default safety checks fail-closed.
- Add regression coverage for changed interface/gateway/address, no IPv4 default, multiple IPv4 defaults, IPv6-default refusal, managed-route residue refusal, journal-integrity refusal, and unchanged strict connect admission.
- This stage intentionally does not yet redesign the provisional R3 emergency-recovery workflow.

## MVC 2.4.4 disconnect convergence refactor — stage 2
- Extend authenticated observed-state convergence to standalone WireGuard protected and split teardown. Published standalone sessions no longer require the historical fully-active WG shape before cleanup begins.
- Add one shared standalone WG cleanup primitive that authenticates the temporary profile identity, kernel WireGuard endpoint, and proto-186 endpoint route before touching them; already-absent owned resources are treated as clean post-state.
- If NetworkManager reports the authenticated temporary profile active, disconnect it and judge the observed result rather than the command exit alone. If the profile is already down/absent but the exact authenticated WG kernel object remains, remove only that proven-owned interface and require absence afterwards.
- Make proto-186 deletion absence-tolerant while refusing conflicting/foreign endpoint or proto-186 state; temporary profile/keyfile cleanup remains identity-bound.
- Route both standalone protected and split public disconnect paths directly through the convergence-aware stop routines instead of enumerating active-versus-clean transitional shapes in the coordinator.
- Preserve protected guard authentication, split no-B4 policy, existing final topology checks, and all foreign-state refusal semantics. This stage intentionally does not yet relax the old physical-link/IPv4 baseline restoration requirement or redesign provisional break-glass recovery.

## MVC 2.4.4 disconnect convergence refactor — stage 1
- Begin refactoring authenticated `mvc disconnect` from historical-shape verification toward observed-state convergence; ownership/session authentication remains unchanged and fail-closed.
- Reconstruct combined-session WireGuard teardown identity from the immutable same-boot D4 intent and authenticated public marker rather than requiring the mutable saved WireGuard source profile to remain present and byte-identical.
- Route published combined-session WireGuard teardown through one exact-inventory reconciler for nominal, already-down, already-absent and partially retired MVC-owned state instead of separate enumerated running/dropout coordinator paths.
- Treat an already-absent owned proto-186 endpoint route as an acceptable cleanup post-state when the authenticated parallel guard is still exact; foreign/ambiguous route or guard state remains fatal before mutation.
- Emit a public warning when the authenticated dual WireGuard state differs from the nominal running shape, while continuing bounded cleanup of proven MVC-owned residue.
- Preserve all existing OpenVPN-loss, WireGuard-loss, partial-D4, break-glass, foreign-policy and final-convergence safety checks. This stage does not yet relax exact post-session physical-link/IPv4 topology restoration or refactor standalone WireGuard teardown.

## MVC 2.4.4 underlay-replacement reconciliation
- Add authenticated break-glass recovery finalization to normal `mvc disconnect`: after the independent emergency tool has already disarmed B4, an exact same-boot recovered OpenVPN-bearing session can be retired without reboot only when its public marker/journals authenticate and all managed VPN, WireGuard, route and guard residue is proven absent.
- Publish a dedicated recovery-finalization intent before any recovered-session mutation, then a separate clone-delete intent before removing the authenticated inactive temporary OpenVPN clone; ambiguous outcomes remain resumable rather than blindly retried.
- Archive the failed session under the existing root-only `/run/mvc-completed/<clone-uuid>` historical namespace with an explicit break-glass archive chain, then retire the live public-session authority so ordinary fresh admission can run again in the same boot.
- Keep `/root/mvc-emergency-rollback` independent and B4-only; change only its successful-disarm guidance to direct the operator to one authenticated `mvc disconnect` finalization before starting a new session.
- Keep ambiguous B4-absent states blocked: B4 absence alone grants no lifecycle authority, and nftables inventory failure cannot be mistaken for table absence.
- Extend authenticated installer update to accept the exact prior emergency-recovery tool identity and the exact R1/R2 2.4.4 development controller predecessors while continuing to refuse unknown content.
- Begin the 2.4.4 maintenance line from the exact released 2.4.3 baseline and authorize that exact controller as an authenticated update predecessor.
- Surface C23T's fixed post-stop convergence category in public `disconnect` failures so physical reproduction can distinguish link, IPv4-route and IPv6-safety failures without weakening teardown authentication.
- Preserve exact IPv6 snapshot stability during B1/B2 admission, B2 attestation, and protected transition establishment.
- Change only post-session IPv6 convergence to enforce MVC's actual IPv6 safety invariant: the live host must have no IPv6 default route, but incidental link-local address/route regeneration no longer prevents authenticated teardown.
- Apply that post-session invariant consistently to normal combined finalization, protected WireGuard teardown, and early OpenVPN reconciliation.
- Keep the existing exact physical-link/IPv4 restoration contract, including only the narrowly proven NetworkManager `+20000` default-route metric equivalence.
- Add regression coverage proving changed no-default IPv6 topology is accepted after session stop, an IPv6 default route remains fail-closed, and exact IPv6 snapshot checks remain intact during protected-state establishment.
- Do not add automatic reconnection, watchdog behavior, or a general replacement-underlay trust shortcut.

## MVC 2.4.3 CI, release infrastructure and identity centralization
- Add GitHub Actions CI and contributor/release documentation for the public regression workflow.
- Remove retired predecessor-era public source/install/test artifacts and scope identity/module audits to the authoritative production surface.
- Introduce manifest-pinned `source/release-version` as the single current-version source; the builder derives release checkpoint and authority from it instead of repeating release literals.
- Make the modular CLI, generated monolith, installer verification and release regressions consume the same release identity and add a regression that forbids duplicating the current version literal elsewhere under `source/`.
- Make dependency/preflight regressions independent of installed/live MVC state by exercising the branch-built monolith with a controlled clean fixed-root predicate; host `/run/mvc-*` state can no longer contaminate these cases.
- Authorize the exact final MVC 2.4.2 controller hash `a83aeb10a5cda9e055fe4aedee69c5797a7dc7a06470e085647b2d77554f9eeb` as an approved update predecessor.
- Keep routing policy, nftables rule semantics, DNS policy, recovery-tool content, persistent record schema and VPN lifecycle behavior unchanged.

## MVC 2.4.2 final release promotion

- Promote the generated controller to stable `MVC_V242_RELEASE` / `audited-dispatch-mvc-v242-release` provenance; physical validation remains external and hash-specific.
- Keep the physically validated R1/R2 runtime inputs unchanged; only release provenance and installer authorization change the generated artifact identity.
- Allow `install-mvc.sh update` to authenticate the exact physically validated 2.4.2 candidate hash `a334261fd892adea75d9d0ee7680e8215666d2f379334dbe96eb69e7fdad9001` as an approved predecessor.
- Extend installer regression coverage to reconstruct that exact candidate from source and prove candidate -> final 2.4.2 promotion through the normal update path.
- No routing policy, nftables rule semantics, DNS policy, persistent record schema, recovery-tool content, or VPN lifecycle implementation changed.

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
