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

MVC-owned runtime filesystem state uses `/run/mvc-*`, and MVC-owned B4 nftables tables use the `mvc_preclone_*` namespace. These names are runtime-visible implementation identifiers and are authenticated as part of the same-boot lifecycle.

Internal Bash functions/helpers use the `mvc24*` namespace and internal variables/constants use `MVC24*`. Current authenticated journal record signatures are MVC-native, and the targeted runtime module filenames are version-neutral. These remain internal implementation details rather than public MVC command/API contracts.
