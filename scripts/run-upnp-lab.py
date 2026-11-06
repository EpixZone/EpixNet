#!/usr/bin/env python3
"""Run the ignored EpixNet UPnP test behind a real, isolated Linux NAT."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

CASES = ("mapped", "unmapped", "static-forward", "manual-override", "tor-always", "mapped-filtered")
PORT = 42424
PROBE_PORT = 42425
CHALLENGE = b"EPIX-UPNP-LAB\n"
ANSWER = b"EPIX-UPNP-OK\n"


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15, **kwargs)


def namespace():
    return os.readlink("/proc/self/ns/net")


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def assert_isolated():
    original = os.environ.get("EPIX_UPNP_LAB_HOST_NETNS")
    if not original or namespace() == original or os.environ.get("EPIX_UPNP_LAB") != "1":
        raise RuntimeError("Refusing network changes outside the disposable namespace")


def enter(pid, args, **kwargs):
    return run(["nsenter", "--target", str(pid), "--net", *args], **kwargs)


def stop(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def connection_probe(observed_ip):
    if observed_ip != "192.0.2.1":
        raise RuntimeError("Outside probe did not observe the isolated router's NAT address")
    try:
        with socket.create_connection((observed_ip, PORT), timeout=.6) as peer:
            peer.sendall(CHALLENGE)
            data = b""
            while len(data) < len(ANSWER):
                chunk = peer.recv(len(ANSWER) - len(data))
                if not chunk:
                    break
                data += chunk
        return {"ip": observed_ip, "open": data == ANSWER,
                "challengeMatched": data == ANSWER, "receivedHex": data.hex()}
    except OSError as error:
        return {"ip": observed_ip, "open": False,
                "challengeMatched": False, "error": type(error).__name__}


def probe_server(output, router_pid):
    assert_isolated()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/check" or urllib.parse.parse_qs(parsed.query) != {"port": [str(PORT)]}:
                self.send_error(400)
                return
            case = (output / "current-case").read_text().strip()
            if case not in CASES:
                self.send_error(409)
                return
            directory = output / case
            stamp = time.time_ns()
            rules = enter(router_pid, ["nft", "-j", "list", "table", "inet", "epix_lab"]).stdout
            (directory / f"probe-{stamp}-nft.json").write_text(rules)
            verdict = connection_probe(self.client_address[0])
            record = {**verdict, "epochNs": stamp, "namespace": namespace(),
                      "source": self.client_address[0]}
            with (directory / "outside-probes.jsonl").open("a") as log:
                log.write(json.dumps(record) + "\n")
            body = json.dumps(verdict).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    http.server.HTTPServer(("192.0.2.2", PROBE_PORT), Handler).serve_forever()


def nft_rules(case):
    block = 'iifname "wan0" tcp dport 42424 drop;' if case == "mapped-filtered" else ""
    permit = 'iifname "wan0" ip daddr 10.77.0.2 tcp dport 42424 accept;' if case == "static-forward" else ""
    mapping = 'iifname "wan0" tcp dport 42424 dnat ip to 10.77.0.2:42424;' if case == "static-forward" else ""
    return f"""table inet epix_lab {{
 chain forward {{ type filter hook forward priority 0; policy drop;
  {block}
  ct state established,related accept;
  iifname "lan0" oifname "wan0" accept;
  {permit}
  jump miniupnpd;
 }}
 chain miniupnpd {{ }}
 chain prerouting {{ type nat hook prerouting priority -100; policy accept;
  {mapping}
  jump prerouting_miniupnpd;
 }}
 chain postrouting {{ type nat hook postrouting priority 100; policy accept;
  jump postrouting_miniupnpd;
  oifname "wan0" ip saddr 10.77.0.0/24 masquerade;
 }}
 chain prerouting_miniupnpd {{ }}
 chain postrouting_miniupnpd {{ }}
}}
"""


def gateway_config(directory):
    return f"""ext_ifname=wan0
ext_allow_private_ipv4=yes
listening_ip=lan0
http_port=5000
enable_upnp=yes
enable_pcp_pmp=no
ipv6_disable=yes
secure_mode=yes
upnp_table_name=epix_lab
upnp_nat_table_name=epix_lab
minissdpdsocket=/dev/null
lease_file={directory / 'leases'}
uuid=2d3c61e3-00ab-41bb-993a-711000000001
friendly_name=EpixNet isolated UPnP lab
notify_interval=30
allow 42424 10.77.0.2/32 42424
deny 0-65535 0.0.0.0/0 0-65535
"""


def mapping_rules(path):
    data = json.loads(path.read_text())
    chains = {"miniupnpd", "prerouting_miniupnpd", "postrouting_miniupnpd"}
    return [entry["rule"] for entry in data["nftables"]
            if "rule" in entry and entry["rule"]["chain"] in chains]


def inspect_evidence(directory, case):
    result_path = directory / "runtime-result.json"
    if not result_path.is_file():
        raise RuntimeError("Runtime test emitted no result; an unmatched libtest filter is not a pass")
    result = json.loads(result_path.read_text())
    required = {"before", "active", "after_shutdown", "runtime_active", "runtime_shutdown", "runtime_probes"}
    if result.get("case") != case or not required.issubset(result):
        raise RuntimeError("Runtime result does not describe the requested lab case")
    probes = [json.loads(line) for line in (directory / "outside-probes.jsonl").read_text().splitlines()]
    if not probes or any(probe["source"] != "192.0.2.1" for probe in probes):
        raise RuntimeError("Outside probe did not observe the expected NAT address")
    gateway = (directory / "gateway.log").read_text()
    adds = gateway.count("AddPortMapping: ext port 42424 to 10.77.0.2:42424 protocol TCP ")
    deletes = gateway.count("DeletePortMapping: external port: 42424, protocol: TCP")
    snapshots = [mapping_rules(path) for path in sorted(directory.glob("probe-*-nft.json"))]
    active = any(rule["chain"] == "prerouting_miniupnpd" for rules in snapshots for rule in rules)
    empty_after = not mapping_rules(directory / "after-nft.json")
    if not empty_after:
        raise RuntimeError("Owned UPnP rules remain after runtime shutdown")
    if case in ("mapped", "mapped-filtered"):
        if adds < 3 or deletes < 1 or not active or "SSDP M-SEARCH from 10.77.0.2:" not in gateway:
            raise RuntimeError("Missing independent SSDP, mapping, two renewals, or deletion evidence")
    elif adds or active:
        raise RuntimeError("Unexpected UPnP mapping in a case that must not create one")
    return {"runtimeResultPresent": True, "tcpAddPortMappingCalls": adds,
            "tcpDeletePortMappingCalls": deletes, "activeDnatObserved": active,
            "ownedMappingRulesEmptyAfterShutdown": empty_after, "outsideProbeCount": len(probes)}


def create_network(children):
    assert_isolated()
    links = json.loads(run(["ip", "-j", "link", "show"]).stdout)
    if [link["ifname"] for link in links] != ["lo"]:
        raise RuntimeError("New router namespace unexpectedly contains a network interface")
    run(["ip", "link", "set", "lo", "up"])
    peers = []
    for router_name, peer_name, router_ip, peer_ip in (
        ("lan0", "node0", "10.77.0.1/24", "10.77.0.2/24"),
        ("wan0", "outside0", "192.0.2.1/24", "192.0.2.2/24"),
    ):
        process = subprocess.Popen(["unshare", "--net", "sleep", "3600"])
        children.append(process)
        deadline = time.monotonic() + 5
        while os.readlink(f"/proc/{process.pid}/ns/net") == namespace():
            if time.monotonic() >= deadline:
                raise RuntimeError("Child network namespace did not start")
            time.sleep(.02)
        run(["ip", "link", "add", router_name, "type", "veth", "peer", "name", peer_name])
        run(["ip", "link", "set", peer_name, "netns", str(process.pid)])
        run(["ip", "addr", "add", router_ip, "dev", router_name])
        run(["ip", "link", "set", router_name, "up"])
        enter(process.pid, ["ip", "link", "set", "lo", "up"])
        enter(process.pid, ["ip", "addr", "add", peer_ip, "dev", peer_name])
        enter(process.pid, ["ip", "link", "set", peer_name, "up"])
        peers.append(process.pid)
    enter(peers[0], ["ip", "route", "add", "default", "via", "10.77.0.1"])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    return peers


def run_case(args, node_pid, case, children):
    directory = args.output / case
    directory.mkdir()
    (args.output / "current-case").write_text(case)
    subprocess.run(["nft", "delete", "table", "inet", "epix_lab"], capture_output=True)
    rules = nft_rules(case)
    (directory / "initial-rules.nft").write_text(rules)
    run(["nft", "-f", "-"], input=rules)
    (directory / "before-nft.json").write_text(run(["nft", "-j", "list", "ruleset"]).stdout)
    daemon = None
    with (directory / "gateway.log").open("w") as gateway_log, (directory / "runtime.log").open("w") as runtime_log:
        if case in ("mapped", "mapped-filtered", "manual-override", "tor-always"):
            config = directory / "miniupnpd.conf"
            config.write_text(gateway_config(directory))
            daemon = subprocess.Popen([str(args.miniupnpd), "-d", "-f", str(config), "-P", str(directory / "gateway.pid")], stdout=gateway_log, stderr=subprocess.STDOUT)
            children.append(daemon)
            time.sleep(.3)
            if daemon.poll() is not None:
                raise RuntimeError(f"Gateway failed to start: {directory / 'gateway.log'}")
        env = dict(os.environ, EPIX_UPNP_LAB_CASE=case,
                   EPIX_UPNP_LAB_PROBE_URL=f"http://192.0.2.2:{PROBE_PORT}/check",
                   EPIX_UPNP_LAB_RESULT=str(directory / "runtime-result.json"))
        command = ["nsenter", "--target", str(node_pid), "--net", str(args.runtime_test),
                   "--ignored", "--exact", "upnp_lab::isolated_router_reachability", "--nocapture"]
        try:
            result = subprocess.run(command, env=env, stdout=runtime_log, stderr=subprocess.STDOUT, timeout=45)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
        finally:
            (directory / "after-nft.json").write_text(run(["nft", "-j", "list", "ruleset"]).stdout)
            if daemon:
                stop(daemon)
    report = {"case": case, "runtimeExitCode": code, "exitCode": code}
    try:
        report["evidence"] = inspect_evidence(directory, case)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        report.update(exitCode=1, evidenceFailure=str(error))
    return report


def lab(args):
    assert_isolated()
    children = []
    try:
        node_pid, outside_pid = create_network(children)
        details = {"hostNamespace": os.environ["EPIX_UPNP_LAB_HOST_NETNS"],
                   "routerNamespace": namespace(), "nodeNamespace": os.readlink(f"/proc/{node_pid}/ns/net"),
                   "outsideNamespace": os.readlink(f"/proc/{outside_pid}/ns/net"),
                   "routerRoutes": json.loads(run(["ip", "-j", "route", "show", "table", "all"]).stdout)}
        (args.output / "namespaces.json").write_text(json.dumps(details, indent=2) + "\n")
        probe = subprocess.Popen(["nsenter", "--target", str(outside_pid), "--net", sys.executable,
                                  str(Path(__file__).resolve()), "--probe", "--output", str(args.output),
                                  "--router-pid", str(os.getpid())])
        children.append(probe)
        time.sleep(.2)
        results = [run_case(args, node_pid, case, children) for case in args.cases]
        (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(results), flush=True)
        return int(any(result["exitCode"] for result in results))
    finally:
        for process in reversed(children):
            stop(process)
        (args.output / "namespace-cleanup.json").write_text(json.dumps({
            "ownedChildrenStopped": all(process.poll() is not None for process in children)}) + "\n")


def host_network_hash():
    snapshot = [json.loads(run(["ip", "-j", "link", "show"]).stdout),
                json.loads(run(["ip", "-j", "route", "show", "table", "all"]).stdout)]
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()


def outer(args):
    if os.geteuid() == 0:
        raise RuntimeError("Run this lab as an ordinary user, without sudo")
    for command in ("unshare", "nsenter", "ip", "nft", "sysctl"):
        if not shutil.which(command):
            raise RuntimeError(f"Required command missing: {command}")
    if not args.miniupnpd or not args.runtime_test:
        raise RuntimeError("Both --miniupnpd and --runtime-test are required")
    for path in (args.miniupnpd, args.runtime_test):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"Not an executable file: {path}")
    args.output.mkdir(parents=True)
    original = namespace()
    network_before = host_network_hash()
    env = dict(os.environ, EPIX_UPNP_LAB="1", EPIX_UPNP_LAB_HOST_NETNS=original)
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy"):
            del env[key]
    env["NO_PROXY"] = "*"
    command = ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
               sys.executable, str(Path(__file__).resolve()), "--inside", "--output", str(args.output),
               "--miniupnpd", str(args.miniupnpd), "--runtime-test", str(args.runtime_test),
               "--cases", *args.cases]
    process = subprocess.Popen(command, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=360)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        network_after = host_network_hash()
        (args.output / "host-isolation.json").write_text(json.dumps({
            "namespaceBefore": original, "namespaceAfter": namespace(),
            "hostNamespaceUnchanged": namespace() == original,
            "hostNetworkHashBefore": network_before, "hostNetworkHashAfter": network_after,
            "hostLinksAndRoutesUnchanged": network_before == network_after,
            "rootless": os.geteuid() != 0,
            "exitCode": process.returncode}, indent=2) + "\n")
    return code


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--miniupnpd", type=lambda value: Path(value).resolve())
    parser.add_argument("--runtime-test", type=lambda value: Path(value).resolve())
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--router-pid", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe:
        return probe_server(args.output, args.router_pid)
    return lab(args) if args.inside else outer(args)


if __name__ == "__main__":
    sys.exit(main())
