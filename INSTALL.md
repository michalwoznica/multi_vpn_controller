# Installation

Build the controller first:

```bash
./source/build/build-mvc-monolith.sh ./dist/mvc
```

Install MVC:

```bash
sudo ./source/tools/install-mvc.sh install
```

Update an already recognized installation:

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

The installer also recognizes the exact approved pre-MVC 2.4.0 file set and can migrate it to the MVC filenames during a controlled update. Unrecognized existing files are never overwritten.
