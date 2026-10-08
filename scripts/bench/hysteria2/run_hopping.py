#!/usr/bin/env python3
"""Compare fixed-port/hopping peers in disposable Podman network namespaces.

Requires Linux, rootless/rootful Podman, Go, openssl, and an official Hysteria
binary. The supplied container image needs sh and glibc. Only the server receives
NET_ADMIN. Host firewall rules are never modified.
"""
import argparse
import json
import os
import pathlib
import statistics
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[3]


def call(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def podman(*args):
    return call(["podman", *map(str, args)])


def ready(container):
    for _ in range(100):
        logs = podman("logs", container)
        if '"ready"' in logs:
            return
        if podman("inspect", "--format", "{{.State.Running}}", container) != "true":
            raise RuntimeError(logs)
        time.sleep(.1)
    raise TimeoutError(logs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official", required=True, type=pathlib.Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--diagnose", action="store_true", help="also compare 1h hopping interval and official bulk TCP")
    parser.add_argument("--disable-gso", action="store_true", help="disable QUIC UDP segmentation offload for comparison")
    parser.add_argument("--bytes", default=4 << 30, type=int,
                        help="TCP bytes per transfer; use enough for multiple 5s hops")
    args = parser.parse_args()
    report = {"topology": "independent target/server/client processes; two Podman containers on a disposable bridge",
              "gomaxprocs": 4, "interval_seconds": 5, "hop_ports": "20000-20020",
              "congestion": "BBR (both bandwidth settings zero)", "repeats": args.repeats,
              "gso_disabled": args.disable_gso,
              "official_version": call([str(args.official.resolve()), "version"]),
              "go_version": call(["go", "version"]), "measurements": []}
    cpu = pathlib.Path("/proc/cpuinfo").read_text().splitlines()
    report["cpu"] = next(line.split(":", 1)[1].strip() for line in cpu if line.startswith("model name"))
    resources = []
    with tempfile.TemporaryDirectory(prefix="hy2-hopping-") as directory:
        work = pathlib.Path(directory)
        subprocess.run(["go", "build", "-o", str(work / "native"), "./scripts/bench/hysteria2"],
                       cwd=ROOT, env=dict(os.environ, GOMAXPROCS="4"), check=True)
        subprocess.run(["cp", str(args.official.resolve()), str(work / "official")], check=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-subj", "/CN=bench.example", "-addext",
                        "subjectAltName=DNS:bench.example", "-keyout", str(work / "key.pem"), "-out", str(work / "cert.pem")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        network = "hy2-hop-" + uuid.uuid4().hex[:10]
        try:
            podman("network", "create", network)
            resources.append(["network", "rm", network])
            common = ["--network", network, "-v", f"{work}:/work:ro", "-e", "GOMAXPROCS=4"]
            if args.disable_gso:
                common += ["-e", "QUIC_GO_DISABLE_GSO=true"]
            server = podman("run", "-d", *common, "--cap-add", "NET_ADMIN", args.image,
                            "/work/native", "-mode", "server", "-listen", "0.0.0.0:4433",
                            "-cert", "/work/cert.pem", "-key", "/work/key.pem", "-hop-ports", "20000-20020")
            resources.append(["rm", "-f", server])
            ready(server)
            client = podman("run", "-d", *common, args.image, "/work/native", "-mode", "target", "-listen", "0.0.0.0:9000")
            resources.append(["rm", "-f", client])
            ready(client)
            def ip(container):
                return json.loads(podman("inspect", container))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
            server_ip, client_ip = ip(server), ip(client)
            def measure(label, extra, implementation="native", destination=None, interval=5):
                endpoint = f"{server_ip}:" + ("20000-20020" if label.startswith("hopping") else "4433")
                command = ["podman", "exec", client, "/work/native", "-mode", "client", "-implementation", implementation,
                           "-server", endpoint, "-target", destination or f"{client_ip}:9000", "-ca", "/work/cert.pem",
                           "-hop-interval-seconds", str(interval), *extra]
                result = call(command, timeout=150)
                sample = next(json.loads(line) for line in reversed(result.splitlines()) if line.startswith("{"))
                sample.update(mode=label, client="official" if implementation == "direct" else implementation,
                              interval_seconds=interval)
                report["measurements"].append(sample)
                print(json.dumps(sample), flush=True)
            # Alternate modes to reduce drift from heat/background activity.
            for direction in ("download", "upload"):
                for _ in range(args.repeats):
                    for mode in ("fixed", "hopping"):
                        measure(mode, ["-direction", direction, "-bytes", str(args.bytes)])
            if args.diagnose:
                for direction in ("download", "upload"):
                    measure("hopping-static", ["-direction", direction, "-bytes", str(args.bytes)], interval=3600)
            for mode in ("fixed", "hopping"):
                measure(mode, ["-udp-packets", "120000", "-udp-pps", "10000"])
            # Official client -> native wildcard-bound server, external PREROUTING.
            config = {"server": f"{server_ip}:20000-20020", "auth": "benchmark-secret",
                      "tls": {"sni": "bench.example", "ca": "/work/cert.pem"},
                      "transport": {"udp": {"hopInterval": "5s"}},
                      "tcpForwarding": [{"listen": "127.0.0.1:19000", "remote": f"{client_ip}:9000"}],
                      "udpForwarding": [{"listen": "127.0.0.1:19000", "remote": f"{client_ip}:9000"}]}
            (work / "official.json").write_text(json.dumps(config))
            podman("exec", "-d", client, "/work/official", "client", "-c", "/work/official.json")
            time.sleep(1)
            if args.diagnose:
                for direction in ("download", "upload"):
                    measure("official-hopping", ["-direction", direction, "-bytes", str(args.bytes)], "direct", "127.0.0.1:19000")
            measure("official-hopping", ["-direction", "download", "-bytes", str(32 << 20)], "direct", "127.0.0.1:19000")
            measure("official-hopping", ["-udp-packets", "120000", "-udp-pps", "10000"], "direct", "127.0.0.1:19000")
            # Graceful server shutdown must remove its own nftables table.
            podman("exec", server, "sh", "-c", "kill -TERM 1")
            for _ in range(100):
                if podman("inspect", "--format", "{{.State.Running}}", server) == "false":
                    break
                time.sleep(.1)
            report["medians_mbps"] = {
                f"{mode}-{direction}": statistics.median(s["mbps"] for s in report["measurements"]
                                                        if s["mode"] == mode and s.get("direction") == direction)
                for mode in ("fixed", "hopping") for direction in ("upload", "download")}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        finally:
            for resource in reversed(resources):
                subprocess.run(["podman", *resource], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
