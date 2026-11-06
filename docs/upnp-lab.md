# Isolated UPnP reachability test

This Linux lab runs EpixNet's actual UPnP discovery, mapping, renewal and removal
code against MiniUPnPd. An independent client outside the NAT checks the mapped
port by exchanging a known request and response with the node's TCP listener.
Opening a container port with `-p` is not part of this test.

The runner creates three network namespaces inside an unprivileged user
namespace:

```text
EpixNet test listener       MiniUPnPd router          Outside probe
10.77.0.2:42424       <--->  10.77.0.1 / 192.0.2.1 <---> 192.0.2.2:42425
```

All interfaces, forwarding settings and nftables rules belong to those
namespaces. The router has no Internet route or interface attached to the host.
Discovery packets cannot reach the real router. The runner refuses to change
network settings until it verifies that it is outside the original host network
namespace. It does not use sudo, publish host ports, or fall back to host
networking. An enclosing PID namespace and bounded process cleanup remove the
lab processes on completion or failure.

## Dependencies

Use an ordinary Linux user with unprivileged user/network namespaces enabled.
The runner needs Python 3, `unshare`, `nsenter`, `ip`, `sysctl`, `nft`, a
MiniUPnPd binary built with the nftables backend, and its shared libraries.
Docker is not required.

On Debian or Ubuntu, the daemon can be extracted without installing or starting
a host router service:

```sh
mkdir -p /tmp/epix-upnp-tools
cd /tmp/epix-upnp-tools
apt-get download miniupnpd-nftables
dpkg-deb -x miniupnpd-nftables_*.deb root
ldd root/usr/sbin/miniupnpd
```

Resolve any missing shared libraries before running the lab. The runner writes
its own daemon configuration and does not need a host MiniUPnPd service.

## Run

From the repository root, compile the ignored test without running other
runtime tests:

```sh
cargo test --locked -p epix-runtime --lib --no-default-features \
  --features inbound-seeding --no-run --message-format=json \
  > /tmp/epix-upnp-build.jsonl
runtime_test=$(python3 - <<'PY'
import json
from pathlib import Path
for line in Path('/tmp/epix-upnp-build.jsonl').read_text().splitlines():
    item = json.loads(line)
    if item.get('target', {}).get('name') == 'epix_runtime' and item.get('executable'):
        print(item['executable'])
PY
)
python3 scripts/run-upnp-lab.py \
  --runtime-test "$runtime_test" \
  --miniupnpd /tmp/epix-upnp-tools/root/usr/sbin/miniupnpd \
  --output /tmp/epix-upnp-results
```

The output directory must not already exist. Use `--cases mapped` for one case,
or omit it to run all six. Namespace creation failure is a test-environment
failure; the runner does not retry discovery on the host network.

## Cases and evidence

| Case | Router configuration | Expected observation |
| --- | --- | --- |
| `mapped` | UPnP enabled | Closed before mapping, expected TCP response after mapping, closed after removal. |
| `unmapped` | No IGD service or forwarding rule | Outside probe stays closed. |
| `static-forward` | Static DNAT, no IGD service | Outside probe succeeds without UPnP. This models preconfigured VPN forwarding; it does not run a WireGuard tunnel. |
| `manual-override` | Explicit external IP configured, no forwarding | Runtime trusts the configured address even though the outside port is closed. This documents the override's limits. |
| `tor-always` | IGD available, clearnet disabled | No discovery/mapping or runtime clearnet probe. Outside port stays closed. |
| `mapped-filtered` | UPnP mapping plus a WAN forwarding drop | Mapping exists, but outside reachability stays closed. This models an additional firewall or upstream filter. |

The production mapping code uses real SSDP and SOAP requests and a real nftables
DNAT rule. Only the public dial-back service is replaced by the isolated outside
probe. That probe uses the source address it observes after NAT, restricts it to
the lab router address, and requires the exact `EPIX-UPNP-OK` response. The
documentation address `192.0.2.1` is accepted only at this test boundary; the
production public-address validation is unchanged.

Mapped cases keep the normal 3600-second SOAP lease and shorten only the test's
refresh wait to 2 seconds. The runner requires three TCP `AddPortMapping` actions
(creation plus two renewals), a `DeletePortMapping` action, an active DNAT
snapshot and empty owned mapping chains after shutdown. A successful TCP probe
alone cannot satisfy these checks.

Each case preserves the runtime state/result, daemon SSDP/SOAP log, outside
probe results and nftables snapshots. A missing runtime result fails the run,
including when an incorrect libtest filter exits successfully without running
the test. The top-level summary records each exit code and evidence checks.
Host namespace identity and network-state hashes are recorded before and after;
namespace cleanup has its own result file.

These results establish how the client behaves with a controlled gateway. They
do not establish that a particular home router, VPN provider, or upstream
firewall supports UPnP or permits inbound traffic.
