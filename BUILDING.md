# Building UBS VPN Controller

## Rebuild the current source

From the repository root:

```bash
mkdir -p dist
./source/build/build-v240-monolith.sh ./dist/ubs-vpn
```

The builder validates every declared runtime input against `source/build/monolith-runtime.manifest`, embeds the required resources, and emits one readable Bash executable.

A second build from the same source should be byte-for-byte identical:

```bash
./source/build/build-v240-monolith.sh /tmp/ubs-vpn.a
./source/build/build-v240-monolith.sh /tmp/ubs-vpn.b
cmp /tmp/ubs-vpn.a /tmp/ubs-vpn.b
sha256sum /tmp/ubs-vpn.a /tmp/ubs-vpn.b
```

## Development workflow

Do not edit `dist/ubs-vpn` directly. Make changes in the modular source tree, then:

1. update the SHA-256 entry for each intentionally changed manifest input;
2. update version/provenance in the builder when producing a new release candidate;
3. rebuild the monolith;
4. run `./source/tests/run-tests.sh`;
5. perform any required live-host validation for the new artifact before promoting it as a release.

Changing any production input creates a different release artifact. Physical validation of an older hash does not automatically apply to a newly generated hash.

## Manifest

`source/build/monolith-runtime.manifest` is the authoritative ordered composition contract. Later Bash definitions may intentionally override earlier definitions; module order therefore matters and must not be casually rearranged.

## Historical filenames

Some internal source filenames retain `v240` or older implementation identifiers for compatibility with the audited composition. They are internal names and do not indicate that the generated controller reports version 2.4.0.
