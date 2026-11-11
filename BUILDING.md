# Building Multi VPN Controller

## Rebuild the current source

From the repository root:

```bash
mkdir -p dist
./source/build/build-mvc-monolith.sh ./dist/mvc
```

The builder validates every declared runtime input against `source/build/monolith-runtime.manifest`, embeds the required resources, and emits one readable Bash executable.

A second build from the same source should be byte-for-byte identical:

```bash
./source/build/build-mvc-monolith.sh /tmp/mvc.a
./source/build/build-mvc-monolith.sh /tmp/mvc.b
cmp /tmp/mvc.a /tmp/mvc.b
sha256sum /tmp/mvc.a /tmp/mvc.b
```

## Development workflow

Do not edit `dist/mvc` directly. Make changes in the modular source tree, then:

1. update the SHA-256 entry for each intentionally changed manifest input;
2. update version/provenance in the builder when producing a new release artifact;
3. rebuild the monolith;
4. run `./source/tests/run-tests.sh`;
5. perform any required live-host validation for the new artifact before promoting it as a release.

Changing any production input creates a different release artifact. Physical validation of an older hash does not automatically apply to a newly generated hash.

## Manifest

`source/build/monolith-runtime.manifest` is the authoritative ordered composition contract. Later Bash definitions may intentionally override earlier definitions; module order therefore matters and must not be casually rearranged.

## Internal compatibility names

Some audited internal source filenames and Bash symbols retain legacy 2.4.x identifiers. They are implementation details and do not change the public product name, executable name, or reported version.
