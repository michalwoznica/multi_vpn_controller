# Installation

Build the controller first:

```bash
./source/build/build-mvc-monolith.sh ./dist/mvc
```

Install MVC:

```bash
sudo ./source/tools/install-mvc.sh install
```

Update an authenticated current or explicitly approved prior MVC installation:

```bash
sudo ./source/tools/install-mvc.sh update
```

Verify the installed file set:

```bash
sudo ./source/tools/install-mvc.sh verify
sudo /usr/local/sbin/mvc version --verbose
```

Remove the managed file set:

```bash
sudo ./source/tools/install-mvc.sh uninstall
```

The installer refuses package maintenance while MVC-managed runtime state or managed VPN links are present. Disconnect the active session first.

The installed files are:

```text
/usr/local/sbin/mvc
/root/mvc-emergency-rollback
/root/mvc-dual-recovery
```

The installer manages MVC installations only. `install` accepts only an absent destination or the exact current package identity. `update` also accepts explicitly approved prior MVC controller identities by exact SHA-256; version/banner strings are not trusted. Unrecognized or locally modified existing files are never overwritten.
