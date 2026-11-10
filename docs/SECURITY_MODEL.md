# Security model

UBS VPN Controller is designed to fail closed for protected sessions.

Key properties include:

- exact saved-profile binding before activation;
- temporary managed VPN profiles rather than modifying the user's source profiles;
- explicit WireGuard endpoint routing over the physical underlay;
- nftables protection that prevents ordinary protected traffic from silently falling back to the physical connection;
- IPv6 Internet blocking during protected operation;
- authenticated same-boot ownership records before disconnect or recovery mutation;
- independent recovery tools with deliberately limited scopes;
- no interactive credential fallback in controller operations.

The controller does not provide an automatic reconnect daemon. A transient failure may recover naturally through NetworkManager or WireGuard, but UBS itself does not continuously repair tunnels. If a published session becomes partial, normal `disconnect` is the first supported reconciliation action.
