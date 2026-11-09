# Use EpixNet without Internet through Reticulum

EpixNet has a native Rust Reticulum peer transport. Enable it explicitly in
Config under **Offline & Mesh**. It is disabled by default. Turning mesh on or
off applies immediately; changing TCP peers or the TCP listener still requires
a restart. Enabled nodes can relay encrypted Reticulum traffic for other mesh
participants. Enabling mesh does not download unsolicited xites or grant access
to a local profile.

Rust handles packet framing, signed node announcements, identity, encrypted
links, routing, and EDX transfers. Platform radio adapters provide only bounded
socket byte streams. TCP interfaces can also connect to another EpixNet node
or an optional external Reticulum router.

This is different from the **Offline mode** switch. `offline=true` and
`EPIX_OFFLINE` disable network transfers, including mesh. Leave that switch off
when communicating with nearby peers. For a network with no Internet access,
use a LAN without a WAN connection or route, or an isolated radio gateway.
The node may still attempt its configured Internet services; an empty tracker
field restores default trackers and is not an Internet-blocking setting.

## Connect nearby Android devices

On Android 10 or later, hold the Epix icon beside the address bar, then open
**Nearby mesh**. Bluetooth and Wi-Fi Aware are optional and start off.

1. Turn on Bluetooth or Wi-Fi in Android settings on both devices. The app
   does not enable system radios for you.
2. Enable **Bluetooth** or **Wi-Fi Aware** in Nearby mesh and allow the nearby
   device permission. Bluetooth discovery needs location permission on Android
   10 and 11; Wi-Fi Aware needs it on Android 10 through 12. EpixNet does not
   read your position. Wi-Fi Aware also needs compatible hardware. The panel
   explains when a radio is unsupported or unavailable.
3. Leave both nodes running. The panel shows the number of nearby connections.
   With notifications allowed, an ongoing notification shows radio activity
   and provides **Stop**. You can also turn both radios off in Nearby mesh.
   Background operation is subject to Android battery and process limits.
   After a force stop or reboot, reopen EpixNet to resume your selected radios.
4. Open the canonical address of a signed xite hosted by the other device.
   Discovery provides candidate peers for requested xites, so no TCP address
   or pairing code is needed. A connection alone does not download xites.

Turning on a radio enables the Rust mesh transport and permits encrypted
traffic to relay through your node. Turning off both radios stops native radio
activity; it does not disable a separately configured mesh TCP connection.
Use **Reticulum mesh > Disable** to disable all mesh links. The global
**Offline mode** setting also blocks nearby communication.

Bluetooth uses Android BLE L2CAP sockets. Wi-Fi Aware uses peer-specific local
data paths and scoped sockets without joining an access point. Both are
untrusted bearers: Rust verifies Reticulum identities and signed xite content.
Radio discovery is visible to nearby observers; mesh is not an anonymity layer.
Each radio has at most four pending or active links, with eight native links
across both radios. Permission revocation and unavailable radios close links.

For offline chat, install the signed
[EpixMeshChat xite](https://github.com/EpixZone/EpixMeshChat-Xite) before leaving
your existing network, or obtain its canonical address from a nearby host.
Create a local profile in the xite and grant the native profile permission.
An xID link is optional. Public rooms and encrypted private groups work without
an Internet account; never paste a private key into the xite.

## Connect two nodes over a LAN

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
5. Open that xite's canonical address on the other node. Verified mesh node
   announcements supply fallback peers for xites the user has already requested.
   They do not advertise a list of hosted xites. If needed, enter the public
   endpoint in the xite's properties Sidebar under **Peers > Add peer** and
   retry the download. EpixNet announces periodically, so initial discovery
   can take about 15 seconds.

On Android, `127.0.0.1` means the phone itself. Use the hosting computer's LAN
address. A local Wi-Fi access point can connect the devices without Internet.
This is ordinary IP networking. Native Android radio links use the separate
Nearby mesh controls above. USB LoRa still requires an external adapter. Do not
expose the mesh listener to the Internet merely to connect nearby devices.

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

The mesh core and its transport tests run in Rust. The Android adapters have
separate Kotlin tests below. No Python runtime is needed to build or run these
mesh components. Run the core transport tests with:

```sh
cargo test -p epix-reticulum --locked
cargo test -p epix-runtime --no-default-features --features mesh --lib native_mesh --locked
cargo test -p epix-ui --lib native_radio --locked
```

Native bridge regressions exercise bounded input and output queues, stream and
chunk limits, malformed frames, forged announcements, excessive hop counts,
offline policy, live enable/disable, stale handles, and persistence failures.
A three-node Rust test connects only A-B and B-C byte streams, transfers a
16 KiB payload over encrypted Reticulum and EDX, removes the relay links to
confirm A cannot reach C directly, then reconnects and transfers again. This
proves the native protocol and bridge behavior, not physical radio operation.

The Rust transport limits the following remote state per node:

| State | Limit and reclamation |
| --- | --- |
| Remote destinations and their discovery metadata | 1,024. Unpinned entries expire after an hour without an accepted announcement; the oldest unpinned entry can be replaced when full. Existing outgoing links and live relay entries pin their destinations. |
| Incoming logical links | 1,024. Closed or expired stale links free slots; active links are not evicted to admit another peer. |
| Relayed logical links | 1,024. Pending entries expire after ten minutes; validated entries expire after an hour without observed link traffic. |
| Packet fingerprints | 4,096. The least recently seen entry is replaced when full. |
| Discovery request destination/tag pairs | 4,096. The oldest pair is replaced when full. Relays retain request tags and advance the hop count so a repeated request does not keep circulating through a radio cycle. |
| Announcement replay cache | Two generations of at most 1,024 entries each. Removing a remote destination also removes its cached announcements. |

These are limits on specific transport tables, not a cap on the node's total
memory or radio airtime. A crowded mesh can reject new links or forget older
discovery entries. Announcements must pass signature and derived-address
validation before allocating destination metadata. Regression tests cover
forged announcements, table pressure, idle reclamation, invalid timing values,
and oversized packet payloads with both supported Fernet key widths.

The development interoperability lab used a separately installed official
Reticulum 1.6.0 gateway as an external reference. That disposable lab had no
Internet route and transferred exact signed 16 KiB xite files across two
routers, a configured 500-byte interface, dropped data, reordered data, and
lost receipts. The external reference implementation is not shipped with
EpixNet and is not part of its required build or test commands.

Android adapter, framing and cancellation regressions compile the production
Kotlin with controlled platform doubles. Run them with the Kotlin compiler,
Node.js, and the existing coroutines library:

```sh
node shells/android/tests/run-ble-mesh-regressions.cjs
node shells/android/tests/run-wifi-aware-regressions.cjs
COROUTINES_JAR=/path/to/kotlinx-coroutines-core-jvm-1.9.0.jar \
  node shells/android/tests/run-nearby-pump-regressions.cjs
```

Software tests do not measure physical radio range, interference, or BLE
support on a particular phone. The available emulator advertises Bluetooth
support but no Wi-Fi Aware feature. Wi-Fi Aware discovery and data paths still
need verification on compatible phones. USB LoRa remains an optional external
gateway feature.
