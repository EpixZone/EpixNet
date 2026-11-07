# LAN discovery

Set `local_discovery` to `true` on each participating device and restart the
node. Keep the `AnnounceLocal` plugin enabled. The configuration switch controls
whether the discovery service runs; the plugin switch pauses both broadcasts
and replies, including at startup.

Both nodes must have the xite address registered or requested. LAN discovery
finds peers for shared xites. It does not subscribe to every xite another device
owns. On the receiving device, open the xite address you want to download.

Discovery uses UDP port 1544 and the broadcast address of each active IPv4
subnet. It works without a default Internet route. Devices need compatible
local IPv4 addresses and subnet masks. Access-point client isolation, blocked
broadcast traffic, or platform local-network permissions can prevent the
exchange. IPv6 has no broadcast and is not part of this discovery protocol.
Loopback, point-to-point interfaces and invalid subnet masks are excluded.
Enumeration failure or no eligible interface produces a rate-limited log
warning and retries on the next discovery tick. There is no fallback broadcast
through the default route or a VPN.

A desktop node accepts connections on its configured fileserver TCP port,
26552 by default. Phones retain their existing download-only clearnet policy.
Once a phone connects to a desktop peer, the desktop can pull an already-requested
xite through that same authenticated EDX session. Signed-manifest, content-hash,
size and activation checks are unchanged. Direct incoming sessions are not used
under Tor-always routing.

Session handles exist only while the connection is alive. They are not dialable
addresses, cannot be parsed from network input, are excluded from peer exchange
and saved peers, and disappear when the connection closes. A first unsolicited
publication still cannot install a xite on another device. Receiving a verified
pull and acknowledging a later publication remain separate operations with the
existing download-completion checks.

## Development checks

These focused tests exercise session authentication and lifecycle, serialization,
subnet selection and discovery controls without broadcasting on the host LAN:

```sh
cargo test --locked -p epix-core --lib session_tests
cargo test --locked -p epix-edx --lib server::tests::interest
cargo test --locked -p epix-runtime --lib --no-default-features \
  --features local-discovery,inbound-seeding incoming_session::tests
cargo test --locked -p epix-runtime --lib --no-default-features \
  --features local-discovery,inbound-seeding local::
```

For device verification, test both a registered and an unregistered receiver,
configuration/plugin-disabled controls, and a LAN without Internet access.
Confirm the signed manifest and exact file contents after the transfer. Check
that a phone has not opened a clearnet fileserver listener. Android native
interface enumeration must be checked inside an ordinary app UID; `adb shell`
alone does not exercise the application sandbox.
