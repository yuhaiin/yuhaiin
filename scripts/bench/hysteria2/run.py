#!/usr/bin/env python3
"""Run native/official peers in independent processes; emit inspectable JSON.

Requires Python 3, openssl, Go and a downloaded official Hysteria binary.
No system network settings are changed. All listeners use loopback.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import queue
import socket
import statistics
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
ENV = dict(os.environ, GOMAXPROCS="4")
AUTH = "benchmark-secret"


def address():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


class Peer:
    def __init__(self, command, ready):
        self.lines = []
        self.events = queue.Queue()
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, env=ENV)
        def read():
            for line in self.process.stdout:
                self.lines.append(line.rstrip())
                self.events.put(line)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                try:
                    line = self.events.get(timeout=.1)
                except queue.Empty:
                    if self.process.poll() is not None:
                        raise RuntimeError("peer exited: " + "\n".join(self.lines))
                    continue
                if ready.lower() in line.lower():
                    return
            raise TimeoutError("peer not ready: " + "\n".join(self.lines))
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join(timeout=2)
        self.process.stdout.close()


def command_result(command):
    result = subprocess.run(command, env=ENV, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=150)
    if result.returncode:
        raise RuntimeError(" ".join(map(str, command)) + "\n" + result.stdout + result.stderr)
    for line in reversed(result.stdout.splitlines()):
        if line.startswith('{'):
            return json.loads(line)
    raise RuntimeError("missing measurement: " + result.stdout + result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--bytes", type=int, default=128 << 20, help="total TCP payload per measurement")
    parser.add_argument("--udp-pps", type=int, default=20000)
    parser.add_argument("--udp-packets", type=int, default=40000)
    parser.add_argument("--smoke-only", action="store_true")
    parser.add_argument("--scenario", choices=("bbr", "brutal-200mbps", "salamander"))
    parser.add_argument("--relay-buffer-size", type=int, default=16384)
    args = parser.parse_args()
    official = str(args.official.resolve())
    version = subprocess.check_output([official, "version"], text=True)
    cpuinfo = pathlib.Path("/proc/cpuinfo")
    cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines() if line.startswith("model name")), platform.processor()) if cpuinfo.exists() else platform.processor()
    report = {"topology": "independent target, server and client processes over IPv4 loopback",
              "gomaxprocs": 4, "platform": platform.platform(),
              "cpu": cpu, "native_relay_buffer_bytes": args.relay_buffer_size,
              "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
              "official_version": version, "official_sha256": hashlib.sha256(args.official.read_bytes()).hexdigest(),
              "repeats": 1 if args.smoke_only else args.repeats,
              "tcp_payload_bytes": (1 << 20) if args.smoke_only else args.bytes,
              "measurements": []}
    with tempfile.TemporaryDirectory(prefix="hy2-bench-") as directory:
        work = pathlib.Path(directory)
        binary = str(work / "native")
        subprocess.run(["go", "build", "-o", binary, "./scripts/bench/hysteria2"], cwd=ROOT, env=ENV, check=True)
        cert, key = work / "server.crt", work / "server.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-subj", "/CN=bench.example", "-addext",
                        "subjectAltName=DNS:bench.example", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        destination = address()
        target_peer = Peer([binary, "-mode", "target", "-listen", destination], '"ready"')
        try:
            # BBR matrix, followed by Brutal and Salamander comparisons.
            scenarios = [("bbr", 0, "", server, client)
                         for server in ("native", "official") for client in ("native", "official")]
            scenarios += [("brutal-200mbps", 25_000_000, "", "native", "native"),
                          ("brutal-200mbps", 25_000_000, "", "official", "official"),
                          ("salamander", 0, "benchmark-obfs", "native", "official"),
                          ("salamander", 0, "benchmark-obfs", "official", "native")]
            if args.scenario:
                scenarios = [row for row in scenarios if row[0] == args.scenario]
            for label, bandwidth, obfs, server_impl, client_impl in scenarios:
                endpoint = address()
                auto = work / f"auto-{label}-{client_impl}"
                server_config = {"listen": endpoint, "tls": {"cert": str(cert), "key": str(key)},
                                 "auth": {"type": "password", "password": AUTH}}
                if bandwidth:
                    server_config["bandwidth"] = {"up": "200 mbps", "down": "200 mbps"}
                if obfs:
                    server_config["obfs"] = {"type": "salamander", "salamander": {"password": obfs}}
                if server_impl == "native":
                    server_command = [binary, "-mode", "server", "-listen", endpoint, "-auto-dir", str(auto),
                                      "-bandwidth-bps", str(bandwidth), "-salamander", obfs,
                                      "-relay-buffer-size", str(args.relay_buffer_size)]
                    server_peer = Peer(server_command, '"ready"')
                    ca = auto / "ca.pem"
                    original_ca = hashlib.sha256(ca.read_bytes()).hexdigest()
                    # Exercise persistence and real listener release before measuring.
                    server_peer.close()
                    server_peer = Peer(server_command, '"ready"')
                    if hashlib.sha256(ca.read_bytes()).hexdigest() != original_ca:
                        raise RuntimeError("TLS-auto CA changed on server restart")
                else:
                    path = work / "server.json"
                    path.write_text(json.dumps(server_config))
                    server_peer = Peer([official, "server", "-c", str(path)], "server up and running")
                    ca = cert
                try:
                    workloads = [("tcp", "upload", 1), ("tcp", "download", 1), ("udp", "echo", 1)]
                    if not args.smoke_only:
                        workloads += [("tcp", "upload", 4), ("tcp", "download", 4)]
                    repeats = 1 if args.smoke_only else args.repeats
                    for transport, direction, streams in workloads:
                        for repeat in range(repeats):
                            client_peer = None
                            actual_target = destination
                            client_command = [binary, "-mode", "client", "-server", endpoint, "-ca", str(ca),
                                              "-bandwidth-bps", str(bandwidth), "-salamander", obfs]
                            if client_impl == "official":
                                forward = address()
                                config = {"server": endpoint, "auth": AUTH,
                                          "tls": {"sni": "bench.example", "ca": str(ca)},
                                          "tcpForwarding": [{"listen": forward, "remote": destination}],
                                          "udpForwarding": [{"listen": forward, "remote": destination}]}
                                if bandwidth:
                                    config["bandwidth"] = {"up": "200 mbps", "down": "200 mbps"}
                                if obfs:
                                    config["obfs"] = {"type": "salamander", "salamander": {"password": obfs}}
                                path = work / "client.json"
                                path.write_text(json.dumps(config))
                                client_peer = Peer([official, "client", "-c", str(path)], "connected to server")
                                actual_target = forward
                                client_command += ["-implementation", "direct"]
                            try:
                                payload = (1 << 20) if args.smoke_only else args.bytes // streams
                                command = client_command + ["-target", actual_target, "-direction", direction,
                                                            "-streams", str(streams), "-bytes", str(payload)]
                                if transport == "udp":
                                    command += ["-udp-packets", str(100 if args.smoke_only else args.udp_packets),
                                                "-udp-pps", str(500 if args.smoke_only else args.udp_pps)]
                                measurement = command_result(command)
                                measurement.update(scenario=label, server=server_impl, client=client_impl, repeat=repeat)
                                report["measurements"].append(measurement)
                                print(json.dumps(measurement), flush=True)
                                args.output.parent.mkdir(parents=True, exist_ok=True)
                                args.output.write_text(json.dumps(report, indent=2) + "\n")
                            finally:
                                if client_peer:
                                    client_peer.close()
                finally:
                    server_peer.close()
        finally:
            target_peer.close()
    groups = {}
    for row in report["measurements"]:
        key = (row["scenario"], row["server"], row["client"], row["transport"], row.get("direction", "echo"), row.get("streams", 1))
        groups.setdefault(key, []).append(row["mbps"])
    report["medians"] = [{"scenario": key[0], "server": key[1], "client": key[2], "transport": key[3],
                          "direction": key[4], "streams": key[5], "mbps": statistics.median(values)}
                         for key, values in groups.items()]
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
