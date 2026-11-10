# Build architecture

The modular source tree is authoritative. `dist/mvc` is generated and should not be edited by hand.

`source/build/monolith-runtime.manifest` records every production module, embedded asset, integrated diagnostic source, independent recovery source and deliberately excluded loader. Each entry is pinned by SHA-256.

`source/build/build-mvc-monolith.sh`:

1. validates manifest structure, order, paths and hashes;
2. composes the ordered runtime modules;
3. embeds deterministic resource payloads;
4. integrates the read-only verifier;
5. adds MVC version/provenance and the public CLI wrapper;
6. emits an executable Bash artifact.

The build is deterministic: identical source inputs must produce identical bytes.
