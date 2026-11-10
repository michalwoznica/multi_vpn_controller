# Installation

Build the controller first:

```bash
./source/build/build-v240-monolith.sh ./dist/ubs-vpn
```

For 2.4.1, use the release installer:

```bash
sudo ./source/tools/install-v241-monolith.sh install
```

To update an already recognized UBS 2.4.x installation:

```bash
sudo ./source/tools/install-v241-monolith.sh update
```

Verify the installed file set:

```bash
sudo ./source/tools/install-v241-monolith.sh verify
sudo /usr/local/sbin/ubs-vpn version --verbose
```

Remove the managed file set:

```bash
sudo ./source/tools/install-v241-monolith.sh uninstall
```

The installer refuses package maintenance while UBS-managed runtime state or managed VPN links are present. Disconnect the active session first.

The installed files are:

```text
/usr/local/sbin/ubs-vpn
/root/ubs-v240-emergency-rollback
/root/ubs-v240-dual-recovery
```

The `v240` names of the independent recovery tools are retained for compatibility across the 2.4.x series.
