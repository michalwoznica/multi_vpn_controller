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

Normal disconnect is an authenticated convergence operation. Connect/preflight admission remains intentionally strict, but teardown does not require the current physical/IPv4 topology to match the pre-connect snapshot. After MVC ownership is authenticated, teardown removes proven MVC-owned state and evaluates a final safety witness. Successful teardown retires MVC live authority; any later connect attempt must independently pass normal admission.

The independent recovery tools are a narrower catastrophic fallback rather than an extension of normal teardown. Emergency B4 disarm remains journal-independent, but the emergency tool may subsequently retire a mature retained same-boot MVC lifecycle only after authenticating its journals, proving managed network residue absent, preserving recovery evidence, and retiring live authority with the public-session marker last. Full recovery may therefore permit a fresh same-boot admission attempt; normal disconnect never adopts B4 absence as cleanup authority.

MVC-owned runtime filesystem state uses `/run/mvc-*`, and MVC-owned B4 nftables tables use the `mvc_preclone_*` namespace. These names are runtime-visible implementation identifiers and are authenticated as part of the same-boot lifecycle.

Internal Bash functions/helpers use the `mvc24*` namespace and internal variables/constants use `MVC24*`. Current authenticated journal record signatures are MVC-native, and the targeted runtime module filenames are version-neutral. These remain internal implementation details rather than public MVC command/API contracts.
