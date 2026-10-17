#!/usr/bin/env python3
"""Independent-process TCP/SOCKS/TUN comparison, in fresh user/net namespaces.

Build stackprobe with `go build -o /tmp/stackprobe ./scripts/benchmarks/stackprobe`.
Build a pinned hev checkout with `make -j4 shared` (clean before switching targets).
Requires Linux, unshare, ip, taskset, iperf3, /dev/net/tun, and Python 3.11+.
No host routes, sysctls, or container images are changed.
"""

import argparse
import ctypes
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import random
import statistics
import struct
import subprocess
import sys
import tempfile
import time

STACKS = ("direct", "socks", "cubic", "bbr", "gso-cubic", "gso-bbr", "hev-plain", "hev-csum", "hev-tso", "hev-jumbo")
SELF = str(Path(__file__).resolve())


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def open_tun(vnet):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    flags = 0x0001 | 0x1000 | (0x4000 if vnet else 0)  # TUN | NO_PI | VNET_HDR
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH22x", b"bench0", flags))
    return fd


def proc_metrics(pid):
    # /proc stat comm may contain spaces: locate its closing parenthesis first.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    rss = int(next(s.split()[1] for s in status if s.startswith("VmHWM:"))) * 1024
    return ticks / os.sysconf("SC_CLK_TCK"), rss


def worker(a):
    children, logs = [], []
    fd = None
    with tempfile.TemporaryDirectory(prefix="hev-compare-") as tmp:
        tmp = Path(tmp)

        def start(name, cpus, argv, pass_fds=()):
            log = (tmp / f"{name}.log").open("w+")
            logs.append((name, log))
            hev_root = Path(a.hev_lib).parent.parent
            libs = [str(hev_root / "third-part" / name / "bin")
                    for name in ("lwip", "yaml", "hev-task-system")]
            env = dict(os.environ, GOMAXPROCS=str(a.procs),
                       LD_LIBRARY_PATH=":".join(libs + [os.environ.get("LD_LIBRARY_PATH", "")]))
            p = subprocess.Popen(["taskset", "-c", cpus, *argv], stdout=log,
                                 stderr=subprocess.STDOUT, pass_fds=pass_fds,
                                 env=env)
            children.append(p)
            return p

        def wait_port(port):
            for _ in range(200):
                if any(p.poll() is not None for p in children):
                    raise RuntimeError("fixture exited before readiness")
                if any(line.split()[1].endswith(f":{port:04X}") and line.split()[3] == "0A"
                       for line in Path("/proc/net/tcp").read_text().splitlines()[1:]):
                    return
                time.sleep(.01)
            raise TimeoutError(f"port {port} not ready")

        try:
            run("ip", "link", "set", "lo", "up")
            start("iperf-server", a.server_cpus, ["iperf3", "-s", "-B", "127.0.0.1"])
            wait_port(5201)
            proxy_process = None
            if a.case != "direct":
                start("socks", a.backend_cpus, [a.probe, "-mode=socks"])
                wait_port(1080)
            if a.case in ("direct", "socks"):
                host, port = "127.0.0.1", "5201" if a.case == "direct" else "5202"
                if a.case == "socks":
                    proxy_process = start("forward", a.proxy_cpus, [a.probe, "-mode=forward"])
                    wait_port(5202)
            else:
                host, port = "198.18.0.2", "5201"
                fd = open_tun(a.case in ("hev-csum", "hev-tso", "gso-cubic", "gso-bbr"))
                if a.case.startswith("hev-"):
                    config = tmp / "hev.yml"
                    config.write_text(f"""tunnel:
  name: bench0
  mtu: {a.mtu}
  ipv4: 198.18.0.1
  offload:
    tso: {str(a.case == 'hev-tso').lower()}
    uso: false
    jumbo: {str(a.case == 'hev-jumbo').lower()}
socks5:
  address: 127.0.0.1
  port: 1080
misc:
  log-level: info
  log-file: stderr
""")
                    proxy_process = start("proxy", a.proxy_cpus,
                        [sys.executable, SELF, "--hev-worker", a.hev_lib, str(config), str(fd)], (fd,))
                else:
                    argv = [a.probe, "-mode=stack", f"-fd={fd}", f"-mtu={a.mtu}", f"-cc={a.case.removeprefix('gso-')}"]
                    if a.profile_dir:
                        profile = Path(a.profile_dir) / f"{a.case}-{a.mtu}-{a.flows}-{a.direction}-{a.sample}.cpu"
                        argv.append(f"-cpuprofile={profile}")
                    proxy_process = start("proxy", a.proxy_cpus, argv, (fd,))
                run("ip", "addr", "add", "198.18.0.1/24", "dev", "bench0")
                run("ip", "link", "set", "bench0", "mtu", str(a.mtu), "txqueuelen", "10000", "up")
                time.sleep(.2)  # library/core initialization; outside measurement
            before = proc_metrics(proxy_process.pid)[0] if proxy_process else 0
            started = time.monotonic()
            argv = ["taskset", "-c", a.client_cpus, "iperf3", "-c", host, "-p", port,
                    "-P", str(a.flows), "-t", str(a.seconds), "-J"]
            if a.direction == "download":
                argv.append("-R")
            result = subprocess.run(argv, text=True, capture_output=True, timeout=a.seconds + 20)
            wall = time.monotonic() - started
            after, rss = proc_metrics(proxy_process.pid) if proxy_process else (0, 0)
            data = json.loads(result.stdout)
            if result.returncode or "error" in data:
                raise RuntimeError(f"iperf failed: {result.stdout} {result.stderr}")
            end = data["end"]
            # Stop gracefully so Go pprof is complete before collecting fixture logs.
            for p in reversed(children):
                p.terminate()
            for p in children:
                p.wait(timeout=5)
            out = {"case": a.case, "mtu": a.mtu, "flows": a.flows,
                   "direction": a.direction, "sample": a.sample,
                   "gbps": end["sum_received"]["bits_per_second"] / 1e9,
                   "proxy_cpu_seconds": after - before,
                   "proxy_cpu_seconds_per_GB": (after - before) / (end["sum_received"]["bytes"] / 1e9),
                   "proxy_cpu_cores": (after - before) / wall,
                   "proxy_peak_rss_bytes": rss,
                   "sender_retransmits": end["sum_sent"].get("retransmits"),
                   "iperf": data, "logs": {}}
            for name, log in logs:
                log.seek(0)
                out["logs"][name] = log.read()
            print(json.dumps(out))
        except Exception:
            for name, log in logs:
                log.flush()
                log.seek(0)
                print(f"{name}: {log.read()}", file=sys.stderr)
            raise
        finally:
            for p in reversed(children):
                if p.poll() is None:
                    p.kill()
                p.wait()
            for _, log in logs:
                log.close()
            if fd is not None:
                os.close(fd)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--hev-worker":
        lib = ctypes.CDLL(sys.argv[2])
        call = lib.hev_socks5_tunnel_main_from_file
        call.argtypes = (ctypes.c_char_p, ctypes.c_int)
        call.restype = ctypes.c_int
        # Termination ends this fixture process; no Python signal handler is
        # needed while the C event loop is running.
        sys.exit(call(os.fsencode(sys.argv[3]), int(sys.argv[4])))
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe", required=True)
    p.add_argument("--hev-lib", required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--stacks", nargs="+", choices=STACKS, default=["cubic", "bbr", "hev-plain", "hev-tso"])
    p.add_argument("--mtus", type=int, nargs="+", default=[1500])
    p.add_argument("--flow-counts", type=int, nargs="+", default=[1, 8])
    p.add_argument("--directions", nargs="+", choices=["upload", "download"], default=["upload", "download"])
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--seconds", type=int, default=8)
    p.add_argument("--proxy-cpus", default="0-2")
    p.add_argument("--client-cpus", default="3")
    p.add_argument("--backend-cpus", default="4")
    p.add_argument("--server-cpus", default="5")
    p.add_argument("--procs", type=int, default=3)
    p.add_argument("--profile-dir")
    p.add_argument("--source-label", default="current worktree", help="source/fixture provenance for this probe binary")
    p.add_argument("--case", choices=STACKS, help=argparse.SUPPRESS)
    p.add_argument("--mtu", type=int, help=argparse.SUPPRESS)
    p.add_argument("--flows", type=int, help=argparse.SUPPRESS)
    p.add_argument("--direction", help=argparse.SUPPRESS)
    p.add_argument("--sample", type=int, help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.seconds < 1 or a.samples < 1 or any(n < 1 for n in a.flow_counts):
        p.error("durations, samples and flows must be positive")
    a.probe, a.hev_lib = str(Path(a.probe).resolve()), str(Path(a.hev_lib).resolve())
    if a.case:
        worker(a)
        return
    if not a.output:
        p.error("--output is required")
    if a.profile_dir:
        a.profile_dir = str(Path(a.profile_dir).resolve())
        Path(a.profile_dir).mkdir(parents=True, exist_ok=True)
    metadata = {"host": platform.platform(), "go": run("go", "version"),
                "iperf": run("iperf3", "--version"),
                "repo_head": run("git", "rev-parse", "HEAD"),
                "source_label": a.source_label,
                "worktree_status": run("git", "status", "--short"),
                "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--", "pkg/net/proxy/tun"])).hexdigest(),
                "probe_sha256": hashlib.file_digest(open(a.probe, "rb"), "sha256").hexdigest(),
                "hev_lib_sha256": hashlib.file_digest(open(a.hev_lib, "rb"), "sha256").hexdigest(),
                "arguments": vars(a) | {"output": str(a.output)},
                "topology": "Linux client -> TUN -> tested proxy -> common SOCKS -> loopback iperf server",
                "notes": "fresh user/net namespace and independent processes per sample; IPv4 TCP; no encryption; hev buffer defaults; lightweight local_tun profile"}
    hev_root = Path(a.hev_lib).parent.parent
    if (hev_root / ".git").exists():
        metadata["hev_head"] = run("git", "-C", str(hev_root), "rev-parse", "HEAD")
        metadata["hev_submodules"] = run("git", "-C", str(hev_root), "submodule", "status")
    metadata["cpu"] = run("lscpu")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    cases = list(itertools.product(a.stacks, a.mtus, a.flow_counts, a.directions))
    records = []
    with a.output.open("w") as f:
        f.write(json.dumps({"metadata": metadata}) + "\n")
        f.flush()
        for sample in range(1, a.samples + 1):
            random.Random(1729 + sample).shuffle(cases)
            for case, mtu, flows, direction in cases:
                print(f"sample={sample} {case} mtu={mtu} flows={flows} {direction}", flush=True)
                argv = ["unshare", "-Urn", sys.executable, SELF, "--case", case,
                        "--probe", a.probe, "--hev-lib", a.hev_lib, "--mtu", str(mtu),
                        "--flows", str(flows), "--direction", direction, "--sample", str(sample),
                        "--seconds", str(a.seconds), "--procs", str(a.procs)]
                for key in ("proxy_cpus", "client_cpus", "backend_cpus", "server_cpus", "profile_dir"):
                    if getattr(a, key):
                        argv.extend(["--" + key.replace("_", "-"), getattr(a, key)])
                result = subprocess.run(argv, text=True, capture_output=True, timeout=a.seconds + 40)
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                row = json.loads(result.stdout)
                records.append(row)
                f.write(json.dumps(row) + "\n")
                f.flush()
                print(f"  {row['gbps']:.3f} Gbit/s, proxy {row['proxy_cpu_seconds_per_GB']:.3f} CPU s/GB", flush=True)
    medians = []
    for case, mtu, flows, direction in sorted(cases):
        rows = [r for r in records if (r["case"], r["mtu"], r["flows"], r["direction"]) == (case, mtu, flows, direction)]
        medians.append(dict(case=case, mtu=mtu, flows=flows, direction=direction,
            **{k: statistics.median(r[k] for r in rows) for k in (
                "gbps", "proxy_cpu_seconds_per_GB", "proxy_cpu_cores", "proxy_peak_rss_bytes", "sender_retransmits")}))
    a.output.with_suffix(".summary.json").write_text(json.dumps({"metadata": metadata, "medians": medians}, indent=2) + "\n")


if __name__ == "__main__":
    main()
