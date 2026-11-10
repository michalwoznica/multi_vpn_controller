# Architecture

UBS VPN Controller 2.4.x is developed as ordered Bash modules and released as a deterministic monolithic Bash executable.

The main architectural layers are:

- NetworkManager profile discovery and exact profile binding;
- OpenVPN temporary-clone preparation and activation;
- WireGuard profile inspection, temporary runtime profile creation and endpoint pinning;
- nftables protection for host output, bridge forwarding and the physical underlay;
- durable same-boot runtime journals used to authenticate disconnect/recovery ownership;
- read-only verification and independent recovery tools.

The generated artifact is built from `source/build/monolith-runtime.manifest`. The manifest order is significant because later modules intentionally override selected functions from earlier layers.

Runtime state is stored under fixed `/run/ubs-v240-*` roots. Those roots are ephemeral across reboot; UBS 2.4.x intentionally uses manual activation rather than an always-on early-boot service.
