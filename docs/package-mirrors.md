# Package repositories over EpixNet

`epix-mirror` transports a bounded repository snapshot through an
ordinary signed xite, exports it from a local node, and serves it to an ordinary
package manager. It is a native Rust executable. It does not change system
package sources, install packages, sign xites, or publish files automatically.

Build it from the checkout with `cargo build -p epix-mirror --release --locked`,
then use `target/release/epix-mirror` (`epix-mirror.exe` on Windows). Alternatively,
`cargo install --path crates/epix-mirror --locked` installs it in Cargo's binary
directory. It is currently built separately from the desktop release bundle.

The xite signature authenticates the snapshot publisher and its bytes. Keep
the package manager's upstream signature and checksum checks enabled as well.
Choose upstream signing keys independently; do not trust a new key just because
it arrived in a mirror. The exported repository retains its original signatures,
metadata, package checksums, and expiry. This is the same separation between
transport and signed repository metadata used by
[F-Droid's repository indexes](https://f-droid.org/en/docs/All_our_APIs/).

## Supported layouts

| Client | Snapshot contents | Client access |
| --- | --- | --- |
| APT | Complete binary repository with signed `InRelease` or `Release` + `Release.gpg`, SHA256 indexes, and every indexed package | Local HTTP repository, with `Signed-By` |
| DNF | `repodata/repomd.xml` + `.asc`, all referenced metadata, XML primary index, and every indexed RPM | Local HTTP `baseurl`, with `gpgcheck=1` and `repo_gpgcheck=1` |
| Homebrew | Selected artifacts and an explicit map of original download request paths | `HOMEBREW_ARTIFACT_DOMAIN`, with upstream formula/bottle checksums |
| Chocolatey | Flat directory of self-contained `.nupkg` packages, including dependencies | Exported local folder passed to `--source` |

APT `Packages` and DNF primary XML indexes may be plain, gzip, or xz. Other
index compression formats are rejected rather than treated as complete. APT
source-package repositories and a full Homebrew API/tap mirror are outside this
tool's supported layouts. Snapshot limits are 60,000 files, 8 GiB per file,
15 GiB total, 8 MiB catalog, and 64 MiB expanded repository metadata. The local
node's public ZIP exporter has its own bounds. Large distributions should use
separate complete repositories, not incomplete slices of an upstream index.
Import accepts the node's single-disk ZIP/ZIP64 format without archive comments;
it bounds the index to 65,536 entries and 64 MiB before decoding ZIP metadata.

## Prepare and publish a snapshot

First use the upstream project's repository synchronization tool to obtain a
complete public repository. Include package dependencies for the clients you
intend to support. This tool checks that each indexed package and metadata file
exists with its declared checksum; native clients still resolve dependencies
against their installed packages and configured repositories. It is not a web
crawler and does not silently fetch missing files.

Choose an explicit UTC expiry. For APT it cannot be later than the upstream
`Valid-Until`. An already expired APT release is rejected. DNF and artifact
collections need an operator-selected expiry because they do not supply the
same signed freshness field. Repackaging old metadata does not make it current.

```sh
epix-mirror stage \
  --manager apt --source /path/to/public-repository \
  --output /path/to/new-snapshot --expires 2026-12-01T00:00:00Z
```

Use an expiry appropriate for the actual upstream metadata, not the example
date. The output contains `epix-mirror.json` and `repo/`. Every file is copied
unchanged. Symlinks, hidden paths, nonportable paths, duplicate names, and common
identity files are rejected. Select only a public repository directory; never
point staging at your node data root or a signing-key directory.

Create a dedicated xite using the normal authoring flow, copy those two entries
into its root, then sign and publish using the existing owner key:

```sh
epix-server siteCreate
# Copy epix-mirror.json and repo/ into the new xite's data/<address>/ directory.
epix-server siteSign <address> --full
epix-server sitePublish <address>
```

Keep repository files mandatory in `content.json`. Do not add an `optional`
pattern that lets a supposedly complete repository remain unavailable. A
publisher may update the same xite after preparing and checking a new complete
snapshot. Publish only after staging succeeds. Keep signing keys and
`private/users.json` outside the public xite.

## Export from a receiving node

Open/download the xite on the receiving node and wait until its required files
are available. Export uses the existing verified public ZIP endpoint. That
endpoint freezes the node's accepted manifest tree, checks file hashes, excludes
private/unsigned files, and refuses changed or missing required content. Export
does not ask the node to execute commands or fetch arbitrary remote URLs.

```sh
epix-mirror export \
  --node http://127.0.0.1:42222 --address <canonical-epix1-address> \
  --output /path/to/snapshot-001
epix-mirror verify --snapshot /path/to/snapshot-001
epix-mirror serve --snapshot /path/to/snapshot-001 --port 42700
```

The node URL must be a literal loopback address with its UI port. Redirects and
environment proxy settings are refused. For a password-protected node, pass a
private Netscape-format cookie file with `--cookie-file`; credentials are not
put in command-line arguments or exported files. Normal node authentication
remains in force. The executable does not disable CORS or use a public gateway's
administrator interface.

Export validates the catalog, every file size/hash, repository completeness and
expiry before atomically renaming the new directory into place. It refuses an
existing destination and removes an incomplete temporary export on failure.
`--expected-snapshot <sha256>` can require the snapshot identifier reported by
the publisher. Obtain that identifier through a trusted channel when using it
as an additional pin.

The HTTP server binds only `127.0.0.1`, accepts only the matching literal Host,
and serves exact catalog entries using GET/HEAD, including bounded byte ranges.
There is no directory listing, upstream proxy, administrator API, or write
endpoint. A changed or expired snapshot stops serving. Each response validates
and streams the same open file, so pathname replacement cannot substitute an
unchecked file. Keep snapshot directories writable only by their operator.
Concurrent in-place writes by that operator after validation are outside the
immutability guarantee; native package checksums still detect changed downloads.
Do not edit an active snapshot. Export to a new directory instead.

## Configure clients

These examples show configuration for a chosen mirror; they are not executed
by the tool. Keep other repositories only if you intend to allow dependencies
or updates from those sources.

### APT

Use a source entry such as:

```text
deb [signed-by=/path/to/independently-verified-upstream-keyring.gpg] http://127.0.0.1:42700 stable main
```

Run the usual `apt-get update` and `apt-get install`/`upgrade`. Do not add
`trusted=yes`, `--allow-unauthenticated`, or disable `Check-Valid-Until`.
[APT's source documentation](https://manpages.debian.org/unstable/apt/sources.list.5.en.html)
explains `Signed-By`; its
[authentication chain](https://www.debian.org/doc/manuals/debian-handbook/sect.package-authentication.en.html)
binds signed Release metadata to indexes and package hashes.

### DNF

```ini
[epix-snapshot]
name=Selected upstream through EpixNet
baseurl=http://127.0.0.1:42700
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///path/to/independently-verified-upstream-key.asc
metadata_expire=0
skip_if_unavailable=0
```

Run the usual `dnf --refresh install`/`upgrade`. Both package and repository
signature checks matter; [DNF documents them separately](https://dnf.readthedocs.io/en/latest/conf_ref.html).

### Homebrew

Create a JSON URL map before staging. Keys are exact paths Homebrew requests;
values are files relative to the public source directory:

```json
{
  "/https://downloads.example.org/tool-1.0.tar.gz": "tool-1.0.tar.gz",
  "/v2/homebrew/core/tool/blobs/sha256:0123456789abcdef": "selected-bottle.tar.gz"
}
```

Use the actual full bottle digest and include every requested OCI manifest/blob
for the selected bottle. Stage with `--manager homebrew --url-map map.json`.
The server accepts the documented
[artifact-domain paths](https://docs.brew.sh/Manpage.html#environment), including
GHCR `/v2/` paths. Homebrew 7.0.12's
[download strategy](https://github.com/Homebrew/brew/blob/7.0.12/Library/Homebrew/download_strategy/curl_download_strategy.rb)
rewrites GHCR URLs, but leaves arbitrary source URLs unchanged despite the
broader wording in its manual. Use GHCR artifacts for this environment-variable
route. For an ordinary source archive, a trusted formula can explicitly point
its URL/mirror at `http://127.0.0.1:42700/https://downloads.example.org/tool-1.0.tar.gz`
while retaining the original SHA256. The server performs exact map lookups and
never forwards an unlisted URL.

```sh
export HOMEBREW_ARTIFACT_DOMAIN=http://127.0.0.1:42700
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1
brew install <trusted-formula>
brew upgrade <trusted-formula>
```

Keep the trusted formula/tap and its original checksums. A bottle is selected
for a particular OS/architecture. Formula/tap/API updates, build dependencies,
and Git-based resources require their own availability; an artifact snapshot
alone does not mirror all of Homebrew. No checksum bypass is provided.

### Chocolatey

Use the exported folder directly:

```powershell
choco install <package-name> --source 'C:\mirrors\snapshot-001\repo'
choco upgrade <package-name> --source 'C:\mirrors\snapshot-002\repo'
```

[Chocolatey supports flat local package folders](https://docs.chocolatey.org/docs/how-to-host-feed/).
Its HTTP package sources need a NuGet/OData feed; a static directory is not
such a feed. This tool deliberately uses the supported folder interface.
Include all `.nupkg` dependencies. Many community packages download an installer
from their install script, so they must already be internalized/self-contained
for offline use. The tool does not rewrite scripts, installer URLs, or checksums.

## Updates and rollback

Export each newly accepted xite snapshot to a **new** directory. Check its
reported digest and expiry, stop the local mirror server, then start it on the
same port with the new directory. Native clients can then refresh and upgrade
without changing the repository URL. This prevents a client reading metadata
from one snapshot and package bytes from another during publication.

Keep the old directory until the new snapshot passes the client's checks.
Restoring an old directory does not bypass catalog or upstream expiry. The tool
does not automate downgrades or prove upstream freshness when the upstream
format has no signed expiry. A newly exported xite is subject to the node's
normal signed-update acceptance rules.

## Verification

`cargo test -p epix-mirror --locked` checks atomic imports, incomplete and
tampered repositories, expiry, path safety, exact URL maps and read-only HTTP.
The Rust `client_lab` example refuses package operations outside a container
whose only network interface is loopback. Its disposable APT/DNF fixtures include
upstream signatures and a dependency, and check installation followed by an
upgrade. Repository fixtures must first pass through the real local node's ZIP
export, which is recorded by `epix-export.json`.

For a repeatable Linux run, create a disposable absolute `QA_ROOT` directory and
use a locally built `NODE_BINARY` from the checkout under test. Set `LAB_BINARY`
to the absolute path of the built `target/debug/examples/client_lab` executable:

```sh
cargo build -p epix-mirror --example client_lab --locked
podman build --network host -f packaging/mirrors/Containerfile -t localhost/epix-mirror-rust-qa .
podman run --rm --network none -v "$QA_ROOT:/qa" \
  -v "$LAB_BINARY:/usr/local/bin/epix-mirror-lab:ro" \
  localhost/epix-mirror-rust-qa generate --root /qa/fixtures
unshare --user --map-current-user --keep-caps --net \
  "$LAB_BINARY" export-node --node-binary "$NODE_BINARY" \
  --root "$QA_ROOT/fixtures" --output "$QA_ROOT/node-export"
podman run --rm --network none -v "$QA_ROOT:/qa" \
  -v "$LAB_BINARY:/usr/local/bin/epix-mirror-lab:ro" \
  localhost/epix-mirror-rust-qa apt --root /qa/fixtures
podman run --rm --network none -v "$QA_ROOT:/qa" \
  -v "$LAB_BINARY:/usr/local/bin/epix-mirror-lab:ro" \
  localhost/epix-mirror-rust-qa dnf --root /qa/fixtures
podman build --network host -f packaging/mirrors/BrewContainerfile -t localhost/epix-mirror-brew-rust-qa .
podman run --rm --network none --userns=keep-id:uid=2000,gid=2000 \
  -v "$QA_ROOT:/qa:ro" -v "$LAB_BINARY:/usr/local/bin/epix-mirror-lab:ro" \
  localhost/epix-mirror-brew-rust-qa brew --root /qa/fixtures
```

Container-image preparation downloads tools; fixture generation, node export,
and native installs use only loopback. The Homebrew image prepares the pinned
client and core metadata first. Its native test uses a dependency-free shell
fixture through the GHCR artifact path, preserves its formula checksum, and
checks an incorrect checksum is rejected. The Windows CI test exercises the
Chocolatey folder interface in a private copy of the runner's Chocolatey
runtime, without modifying its installed-package inventory or source config.
It is separate from the real-node export test on Linux.
