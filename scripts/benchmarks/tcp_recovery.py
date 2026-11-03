#!/usr/bin/env python3
"""Measure detector overhead, impaired reference-peer TCP and optional Linux TUN TCP."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile


def run(command, output, repo, env):
    result = subprocess.run(command, cwd=repo, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output.write_text("".join(line.rstrip() + "\n" for line in result.stdout.splitlines()))
    if result.returncode:
        raise RuntimeError(f"Command failed; preserved output in {output}")
    return result.stdout


def summarize(output, samples):
    cases = {}
    for line in output.splitlines():
        match = re.match(r"^(Benchmark\S+)-\d+\s+(\d+)\s+(.+)$", line)
        if not match:
            continue
        fields = match[3].split()
        metrics = {fields[i + 1]: float(fields[i]) for i in range(0, len(fields), 2)}
        cases.setdefault(match[1], []).append(metrics)
    if not cases or any(len(rows) != samples for rows in cases.values()):
        raise ValueError("Missing benchmark samples; inspect preserved raw output")
    return {name: {"samples": rows, "median": {
        metric: statistics.median(row[metric] for row in rows)
        for metric in rows[0]}} for name, rows in cases.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--benchtime", default="500ms")
    parser.add_argument("--gomaxprocs", type=int, default=4)
    parser.add_argument("--kernel", action="store_true", help="Require isolated Linux TUN tests and benchmarks")
    args = parser.parse_args()
    if args.samples < 1 or args.gomaxprocs < 1:
        parser.error("samples and gomaxprocs must be positive")
    repo = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOMAXPROCS=str(args.gomaxprocs))
    metadata = {"platform": platform.platform(), "go": subprocess.check_output(
        ["go", "version"], text=True).strip(), "gomaxprocs": args.gomaxprocs,
        "samples": args.samples, "benchtime": args.benchtime,
        "kernel": args.kernel, "offload": False, "encryption": False,
        "reference_peer": "gVisor; Linux TCP for the optional kernel cases",
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()}
    files = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=repo, text=True).splitlines()
    digest = hashlib.sha256()
    for name in sorted(set(files)):
        if name.endswith(".go"):
            digest.update(name.encode())
            digest.update((repo / name).read_bytes())
    metadata["go_source_sha256"] = digest.hexdigest()
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2)+"\n")
    package = "./pkg/net/proxy/tun/lightweight"
    common = ["-test.run=^$", f"-test.benchtime={args.benchtime}", f"-test.count={args.samples}", "-test.benchmem", "-test.timeout=6m"]
    summary = {}
    run(["go", "test", package, "-run", "^TestRecoveryTailLossLatency$", "-v", "-count=1"],
        output / "tail-latency.txt", repo, env)
    raw = run(["go", "test", package+"/recovery", "-run", "^$", "-bench", "BenchmarkDetectorACK",
               "-benchmem", "-benchtime", args.benchtime, "-count", str(args.samples)],
              output / "detector.txt", repo, env)
    summary["detector"] = summarize(raw, args.samples)
    with tempfile.TemporaryDirectory(prefix="yuhaiin-tcp-recovery-") as temporary:
        binary = str(Path(temporary) / "stack.test")
        run(["go", "test", "-c", "-o", binary, package], output / "build.txt", repo, env)
        raw = run([binary, *common, "-test.bench=^BenchmarkImpairedTCP$/(classic|rack-tlp)/(reno|cubic|bbr)/(rtt10ms|rtt50ms-loss0[.]1pct)$"],
                  output / "impaired.txt", repo, env)
        summary["impaired"] = summarize(raw, args.samples)
        if args.kernel:
            kernel = str(Path(temporary) / "kernel.test")
            run(["go", "test", "-c", "-tags", "lightweight_kernel", "-o", kernel, package],
                output / "kernel-build.txt", repo, env)
            for detector in ["classic", "rack-tlp"]:
                run(["unshare", "-Urn", kernel, f"-loss-recovery={detector}",
                     "-test.run=^TestLinuxKernel", "-test.v", "-test.timeout=90s"],
                    output / f"kernel-tests-{detector}.txt", repo, env)
                raw = run(["unshare", "-Urn", kernel, *common, f"-loss-recovery={detector}",
                           "-test.bench=^BenchmarkKernelRecovery$"],
                          output / f"kernel-{detector}.txt", repo, env)
                summary[f"kernel-{detector}"] = summarize(raw, args.samples)
    (output / "summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(f"Preserved raw samples, environment and medians in {output}")


if __name__ == "__main__":
    main()
