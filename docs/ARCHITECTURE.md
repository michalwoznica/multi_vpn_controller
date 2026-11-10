# Architecture

Multi VPN Controller 2.4.x is developed as ordered Bash modules and released as a deterministic monolithic Bash executable.

The main architectural layers are:

- NetworkManager profile discovery and exact profile binding;
- OpenVPN temporary-clone preparation and activation;
- WireGuard profile inspection, temporary runtime profile creation and endpoint pinning;
- nftables protection for host output, bridge forwarding and the physical underlay;
- durable same-boot runtime journals used to authenticate disconnect/recovery ownership;
- read-only verification and independent recovery tools.

The generated artifact is built from `source/build/monolith-runtime.manifest`. Manifest order is significant because later modules intentionally override selected functions from earlier layers.

Runtime state is ephemeral across reboot. MVC 2.4.x intentionally uses manual activation rather than an always-on early-boot service.

Some internal runtime identifiers and audited module filenames retain a legacy implementation namespace. That namespace is not part of the public MVC command/API and is intentionally deferred to a separate no-behavior-change refactor.
