# Releasing Multi VPN Controller

This document records the public release procedure for Multi VPN Controller (MVC). It intentionally separates deterministic/offline validation from live-host validation.

A green CI run is a release prerequisite, not a substitute for physical validation when networking behavior changes.

## 1. Develop away from `master`

Keep `master` stable. Create a versioned development branch for release work, for example:

```bash
git switch master
git pull --ff-only
git switch -c dev/2.x.y
```

Keep individual changes bounded and reviewable. Runtime behavior changes should not be mixed unnecessarily with unrelated documentation or repository-maintenance changes.

## 2. Validate source changes

Build the generated executable from the repository root:

```bash
mkdir -p dist
./source/build/build-mvc-monolith.sh ./dist/mvc
```

Run the public regression suite:

```bash
sudo ./source/tests/run-tests.sh
```

CI performs the same source-oriented checks on pull requests and `master` without activating real VPN sessions.

If production inputs change, verify that `source/build/monolith-runtime.manifest` describes the intended ordered composition and contains the correct SHA-256 for every changed input.

## 3. Prove deterministic construction

Build at least twice from the same clean source and require byte-for-byte equality:

```bash
A=$(mktemp)
B=$(mktemp)
./source/build/build-mvc-monolith.sh "$A"
./source/build/build-mvc-monolith.sh "$B"
cmp "$A" "$B"
cmp "$A" ./dist/mvc
sha256sum "$A" "$B" ./dist/mvc
rm -f "$A" "$B"
```

Record the exact executable SHA-256 used for any subsequent physical validation. Validation evidence is hash-specific: rebuilding different bytes creates a different artifact that has not inherited the earlier artifact's physical proof.

## 4. Candidate physical validation

When a release changes VPN lifecycle/runtime behavior, routing, DNS, firewall policy, NetworkManager interaction, persistent ownership records, recovery behavior, or other live networking semantics, validate the exact candidate artifact on an appropriate real host before final promotion.

The required scenario depends on the change. At minimum, validate the behavior directly affected by the release and prove clean restoration to baseline. Do not expand destructive testing beyond the release scope without a concrete reason.

Repository-only changes such as documentation, issue templates or CI configuration do not require live VPN validation unless they also change generated/runtime bytes.

## 5. Promote stable release provenance

Set the intended release in `source/release-version`. This one-line file is the single current-version source for the modular CLI, deterministic builder, installer expectations and release regressions. The builder derives the release checkpoint and authority from that value; do not duplicate the current version as literals in other `source/` files.

Update the manifest SHA-256 for `source/release-version`, rebuild the generated executable, and treat the resulting SHA-256 as a new artifact.

The installer update policy must explicitly authenticate any supported predecessor by exact content identity. Do not authorize an update based only on a version string or filename.

Run the complete regression suite again after promotion.

## 6. Reproduce and smoke-test the final artifact

From the committed release branch, independently rebuild the final artifact and require it to match the packaged `dist/mvc` byte-for-byte.

If final promotion changed the executable hash, perform the bounded final physical smoke test required for that exact hash before release. For MVC's current combined mode, a typical smoke test proves:

- private destinations route through WireGuard;
- ordinary Internet routes through OpenVPN;
- protected state is observed while active;
- authenticated `mvc disconnect` succeeds;
- baseline routes, DNS, managed profiles/links, nftables state and runtime roots are restored;
- temporary monolith resources are not left behind.

Use a known responsive private host for WireGuard data-plane liveness rather than assuming every configured gateway address answers ICMP.

## 7. Merge without rewriting validated history

Open a pull request into `master` and allow required CI checks to pass.

MVC normally uses a merge commit rather than squash or rebase merging so that validated development commits retain their original identities and remain ancestors of the release.

After merging, verify that the `master` merge commit has the same tree as the validated development tip and that a fresh build from `master` reproduces the exact final executable hash.

## 8. Tag the release

Create an annotated version tag on the verified `master` release commit:

```bash
git tag -a v2.x.y -m "Multi VPN Controller 2.x.y"
git show --no-patch v2.x.y
git push origin v2.x.y
```

Confirm that the peeled tag target is the intended release commit before pushing.

## 9. Publish GitHub release assets

The recommended release assets are:

- `multi-vpn-controller-2.x.y.tar.gz` — complete public source/install bundle, including the exact generated `dist/mvc` artifact;
- `mvc-2.x.y` — exact validated standalone monolithic executable;
- `SHA256SUMS` — checksums for the manually uploaded release assets.

Private development material such as `.handoff` must not be included in public release archives.

Before publication, extract the release bundle into a clean directory, rebuild the controller from the bundled source, require byte-for-byte equality with bundled `dist/mvc`, and run the public regression suite from the extracted bundle.

GitHub's automatically generated source archives contain the tagged Git tree. Because `dist/` is intentionally Git-ignored, those automatic archives are supplemental source archives rather than the recommended complete install bundle.

## 10. Close the development branch

After the GitHub release is published and marked as the current stable release, delete the merged development branch remotely and locally. Preserve the release history through `master` and the annotated version tag.
