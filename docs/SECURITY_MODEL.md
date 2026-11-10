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

A partial tunnel loss does not grant authority by itself. MVC first authenticates the owned same-boot session from its durable runtime evidence, then reconciles only tightly recognized states. Unknown or ambiguous state remains fail-closed.

MVC same-boot ownership records live under `/run/mvc-*`. Protected-session B4 tables use the `mvc_preclone_*` nftables namespace. Both are ephemeral runtime state rather than persistent configuration.
