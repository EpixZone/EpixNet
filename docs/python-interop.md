# Live interop verification against Python EpixNet

Date: 2026-07-07. Rust node and Python EpixNet 0.2.7 (this repo's sibling
checkout) running side by side on one machine, talking over loopback TCP.
This closes the standing "verify against a live Python peer" checkpoint for
the publish round-trip and the inbound serving surface.

## Verified

Python client against the Rust server (port 26599):

- `peerPing`: handshake + ping round-trips (5/5, sub-millisecond).
- `peerGetFile`: Python's streaming download path (`streamFile`) fetched the
  file byte-for-byte. This exercises the raw-stream framing fix - the reply
  carries `stream_bytes` with the file bytes following raw on the socket.
- `listModified`: reports the site's content.json versions in the shape
  Python expects.
- `pex`: answers with typed peer buckets; Python parses the reply.

Publish round-trip, both directions:

- **Python signs, Rust accepts.** `sitePublish <site> 127.0.0.1 26599` from
  the Python CLI: the Rust node verified the Python-signed content.json,
  replied "Thanks, file content.json updated!", fetched the changed
  index.html back from the sender, and wrote both to disk.
- **Rust signs, Python accepts.** The `interop_push` example
  (`cargo run -p epix-runtime --example interop_push`) signs a bumped
  content.json with epix-crypt and pushes `update` over the wire. The Python
  node logged "Update for content.json looks valid, saving..." and saved it -
  a Python peer accepts a Rust-signed content.json. Python then fetched the
  changed file from the Rust node's file server by hash.

## Fixes that came out of this

- The handshake reply must carry `fileserver_port` (KeyError in Python's
  `Connection.handleHandshake` without it) plus `port_opened`/`crypt`. Python
  adopts the advertised port as our dial-back port, so the TCP server sends
  its real listener port, the onion service its virtual port, mesh 0.
- `streamFile` had answered with an inline body like `getFile`; Python's
  streaming download misread it. Now reframed as `stream_bytes` + raw tail
  in `serve_stream`, for every handler and transport.

## Rerunning it

1. Python env: `python3 -m venv env && env/bin/pip install -r
   ../EpixNet/requirements.txt`.
2. Python needs a scratch profile: `--start-dir <dir>` (holds
   `private/sites.json`, `plugins.json`, `epixnet.conf` - create the conf
   empty or startup refuses the directory), `--data-dir <dir>/data`,
   `--log-dir`. Disable the plugins that fight a second node on one machine
   or a headless run: `{"builtin": {"Trayicon": {"enabled": false},
   "AnnounceLocal": {"enabled": false}}}` in `plugins.json` (Trayicon
   SIGTRAPs headless via AppKit; AnnounceLocal's port collides with a real
   node and takes the process down with it).
3. Rust node: `EPIX_DATA_DIR=<dir> EPIX_TOR=disable EPIX_HEADLESS=1 cargo
   run -p epix-server`, with `fileserver_port`/`i2p`/`mesh` set in
   `<dir>/private/config.json`. Both registries live in `private/sites.json`
   (same layout, either node reads the other's).
4. Drive Python's client against the Rust server with `peerPing` /
   `peerGetFile` / `peerCmd`, publish with `siteSign` + `sitePublish
   <site> <ip> <port>`, and push Rust-signed updates with the
   `interop_push` example.

## Still open (needs infrastructure, not code spikes)

- A Python peer reaching our onion service inbound (needs Tor up on both
  sides; the onion service itself is exercised by `cargo test -p epix-tor
  -- --ignored`).
- The `--tor always` zero-direct-IP clone checkpoint.
