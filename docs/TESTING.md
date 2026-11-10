# Testing

The public source tree contains a curated hermetic regression suite:

```bash
./source/tests/run-tests.sh
```

It covers deterministic building, runtime composition seams, the integrated verifier, structural equivalence, installer behavior, pre-existing partial-state reconciliation and the 2.4.1 bidirectional combined-session dropout handling.

The tests use synthetic profile names, UUIDs, interfaces and documentation address ranges. They do not require access to a real VPN service or the maintainer's network.
