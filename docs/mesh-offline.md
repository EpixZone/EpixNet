# Use EpixNet without Internet through Reticulum

EpixNet already has a Reticulum peer transport. Enable it explicitly in Config
under **Offline & Mesh**. It is disabled by default. The built-in interface
connects to a Reticulum TCP endpoint; an external Reticulum router can connect
that endpoint to a local Wi-Fi/Ethernet network or an RNode radio.

This is different from the **Offline mode** switch. `offline=true` and
`EPIX_OFFLINE` disable network transfers, including mesh. Leave that switch off
when communicating with nearby peers. For a network with no Internet access,
use a LAN without a WAN connection or route, or an isolated radio gateway.
The node may still attempt its configured Internet services; an empty tracker
field restores default trackers and is not an Internet-blocking setting.

## Connect two nodes

1. Install the xites you need while connected, or copy their signed files from
   another trusted node. Keep `content.json` and its signed files together.
   Use the canonical `epix1...` address when Internet name resolution is not
   available. A mesh connection does not automatically discover every xite.
2. On the node hosting the xite, set **Reticulum mesh** to Enable. Set
   **Mesh TCP listen address** to that computer's LAN address and an unused
   port, for example `192.168.50.2:4242`. Leave **Mesh TCP interfaces to join**
   empty. Restart EpixNet.
3. On the other EpixNet node, enable mesh and put `192.168.50.2:4242` in
   **Mesh TCP interfaces to join**. Leave its listen address empty and restart.
   Allow that port on the hosting computer's local firewall. Both nodes run
   the native Rust transport; no separate gateway or Python runtime is needed.
4. On the hosting node, open `/EpixNet-Internal/Status` on its local node UI.
   Copy `mesh_endpoints.reliable_v2`, including `rns:`. This public destination
   is a peer endpoint, not the xite address or a private key.
5. Open that xite's canonical address on the other node. In its properties
   Sidebar, enter the endpoint in **Peers > Add peer**. Retry the xite download
   if necessary. Reticulum announcements are periodic, so initial discovery
   can take about a minute.

On Android, `127.0.0.1` means the phone itself. Use the hosting computer's LAN
address. A local Wi-Fi access point can connect the devices without Internet.
This is ordinary IP networking, not Wi-Fi Aware. The EpixNet app does not yet
open a phone's Bluetooth radio or USB LoRa radio directly. Do not expose the
mesh listener to the Internet merely to connect nearby devices.

The reliable v2 destination uses small acknowledged Channel messages. The
legacy `rns:` destination remains available for existing EpixNet peers and
uses the older raw stream. Prefer `mesh_endpoints.reliable_v2` for radio links.
A new client upgrades a legacy endpoint only after receiving a verified v2
announcement with the same public identity. It does not silently fall back
from v2 to raw traffic.

## Optional external radio gateways

A separately operated Reticulum gateway can bridge its TCP listener to
hardware interfaces. EpixNet connects to that endpoint through **Mesh TCP
interfaces to join**. This is optional and is not needed for the two-node
Rust setup above. The official gateway currently requires its own Python
environment; those dependencies belong to that external gateway, not EpixNet.
Reticulum-rs does not currently implement its AutoInterface or RNodeInterface.

Official Reticulum's [interface manual](https://reticulum.network/manual/interfaces.html)
describes the physical interfaces. Add the appropriate interface to each
router's config while retaining the local TCP listener for EpixNet:

- **Wi-Fi or Ethernet:** `AutoInterface` discovers other Reticulum routers on
  the local network. Its IPv6 multicast must be supported by that network.
  This is ordinary IP networking, not Wi-Fi Aware.
- **LoRa:** `RNodeInterface` connects to a supported RNode over a serial port,
  such as `/dev/ttyUSB0`. Configure the radio frequency, bandwidth, spreading
  factor, coding rate, and transmit power for the hardware and local rules.
  Both ends need compatible settings. Long transfers are limited by radio
  airtime and link speed.
- **Bluetooth to an RNode:** official Python Reticulum supports a `ble://`
  RNode port on supported hosts with its Bluetooth dependencies and pairing.
  The gateway host supplies that adapter and its dependencies; EpixNet
  connects to its local TCP endpoint.
  This is a Bluetooth radio bridge, not direct EpixNet phone-to-phone BLE mesh.

For example, two router computers on the same offline LAN can add:

```ini
  [[Nearby routers]]
    type = AutoInterface
    enabled = yes
```

Follow the official [Reticulum setup guide](https://reticulum.network/manual/using.html)
for installation, interface credentials, and access controls. Keep mesh opt-in
and retain your existing Tor and gateway policies. These instructions do not
make mesh traffic travel through Tor or hide the presence of a nearby radio.

## Validation and current limits

EpixNet and the required regression tests run in Rust. No Python runtime is
needed to build or run its mesh transport. Run the adapter tests with:

```sh
cargo test -p epix-reticulum --locked
```

The development interoperability lab used a separately installed official
Reticulum 1.6.0 gateway as an external reference. That disposable lab had no
Internet route and transferred exact signed 16 KiB xite files across two
routers, a configured 500-byte interface, dropped data, reordered data, and
lost receipts. The external reference implementation is not shipped with
EpixNet and is not part of its required build or test commands.

The Android verification uses the native Rust transport in an emulator with
Internet traffic blocked. Software tests do not measure physical radio range,
interference, airtime compliance, BLE support on a particular phone, or Wi-Fi
Aware. Direct Android BLE, USB LoRa, and Wi-Fi Aware adapters are not implemented.
A deployment that needs those physical links currently needs a compatible
external gateway and its platform-specific dependencies. A fully native radio
adapter remains separate work requiring supported hardware and on-air tests.
