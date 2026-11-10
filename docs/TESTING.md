# Testing

Run the curated public regression suite from the repository root:

```bash
./source/tests/run-tests.sh
```

The public suite is hermetic. It covers deterministic generation, embedded runtime seams, CLI/verifier behavior, structural equivalence, installer behavior, partial-session reconciliation, generated-artifact dropout handling, public/runtime identity boundaries and public-tree sanitization.

A release candidate should also satisfy:

```bash
./source/build/build-mvc-monolith.sh /tmp/mvc.a
./source/build/build-mvc-monolith.sh /tmp/mvc.b
cmp /tmp/mvc.a /tmp/mvc.b
bash -n /tmp/mvc.a
```

Physical validation is required for a newly generated release hash before that hash is promoted as an approved release.
