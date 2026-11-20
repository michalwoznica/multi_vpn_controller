# Security model

Multi VPN Controller is designed to fail closed for protected sessions.

Key properties include:

- exact saved-profile binding before activation;
- temporary managed VPN profiles rather than mutation of the saved source profiles;
- coordinated nftables protection for host output, bridge forwarding and the physical underlay;
- OpenVPN ordinary-Internet/DNS routing separated from WireGuard AllowedIPs in combined mode;
- IPv6 Internet blocking during protected sessions;
- authenticated same-boot runtime journals before disconnect/recovery mutation;
- independent recovery tools with narrower authority than the main controller;
- no automatic reconnect/watchdog behavior.

A partial tunnel loss or host-underlay change does not grant authority by itself. MVC first authenticates the owned same-boot session from durable runtime evidence, then converges only state it can prove belongs to MVC. During teardown the saved pre-connect physical/IPv4 topology is forensic/admission evidence rather than a restoration target; final safety still requires MVC-owned residue to be gone, foreign policy to remain untouched, and no IPv6 default route. Unknown ownership, foreign managed state, or an unprovable mutation outcome remains fail-closed.

MVC same-boot ownership records live under `/run/mvc-*`. Protected-session B4 tables use the `mvc_preclone_*` nftables namespace. Both are ephemeral runtime state rather than persistent configuration.
