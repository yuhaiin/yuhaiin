#!/usr/bin/env python3
"""Measure the production statistics observer in independent test processes.

Build once before running, for example:
  go test -c ./pkg/statistics -o /tmp/user-usage.test
  go build -o /tmp/user-usage-peer ./scripts/bench/userusagepeer
  python3 scripts/bench/user_usage.py --binary /tmp/user-usage.test \
      --peer-binary /tmp/user-usage-peer --output /tmp/usage-bench

CPU and RSS come from wait4 for that individual process, including startup,
background work and shutdown. They exclude compilation. Network cases run long
enough to include the one-second sampler and five-second SQLite flushes.
"""

import argparse
import csv
import json
import os
from pathlib import Path
import re
import subprocess
import time


def measure(binary, pattern, duration, output, procs, targets):
    command = [str(binary), "-test.run=^$", f"-test.bench={pattern}",
               f"-test.benchtime={duration}", "-test.count=1", "-test.benchmem"]
    env = dict(os.environ, GOMAXPROCS=str(procs))
    env.update(YUHAIIN_USAGE_BENCH_TCP_TARGET=targets["tcp"], YUHAIIN_USAGE_BENCH_UDP_TARGET=targets["udp"])
    started = time.monotonic()
    # Read the pipe before wait4 so benchmark/log output cannot fill the pipe.
    # Popen has not reaped the process; wait4 supplies its individual rusage.
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    raw = child.stdout.read().decode("utf-8", "replace")
    _, status, resource = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    wall = time.monotonic() - started
    output.write_text(raw)
    if child.returncode:
        raise RuntimeError(f"benchmark failed ({child.returncode}); see {output}")
    lines = [line for line in raw.splitlines() if re.match(r"^Benchmark\S+\s+\d+\s+", line)]
    if len(lines) != 1:
        raise RuntimeError(f"expected one benchmark result in {output}, got {len(lines)}")
    line = lines[0]
    metrics = {unit: float(value) for value, unit in re.findall(r"([\d.]+)\s+([A-Za-z/\-]+)", line)}
    return {
        "name": line.split()[0], "iterations": int(line.split()[1]),
        "wall_seconds": wall, "user_seconds": resource.ru_utime,
        "system_seconds": resource.ru_stime, "cpu_seconds": resource.ru_utime + resource.ru_stime,
        "max_rss_kib": resource.ru_maxrss, **metrics,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--peer-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=8)
    parser.add_argument("--procs", type=int, default=2)
    args = parser.parse_args()
    if args.repeat < 1 or args.seconds < 6 or args.procs < 1:
        parser.error("repeat/procs must be positive; seconds must be at least 6 to exercise background flushes")
    args.output.mkdir(parents=True, exist_ok=True)
    peer = subprocess.Popen([str(args.peer_binary.resolve())], stdout=subprocess.PIPE, env=dict(os.environ, GOMAXPROCS=str(args.procs)))
    try:
        targets = json.loads(peer.stdout.readline())
        run_benchmarks(args, targets)
    finally:
        peer.terminate()
        peer.wait(timeout=10)


def run_benchmarks(args, targets):
    results = []
    for benchmark, bytes_per_operation in [("TCPRelay", 32768), ("UDPRoundTrip", 2700)]:
        for repetition in range(args.repeat):
            # Alternate the order to reduce systematic thermal/frequency bias.
            for enabled in ([False, True] if repetition % 2 == 0 else [True, False]):
                suffix = str(enabled).lower()
                pattern = f"^BenchmarkUserUsage{benchmark}$/^{suffix}$"
                result = measure(args.binary.resolve(), pattern, f"{args.seconds}s",
                                 args.output / f"{benchmark}-{suffix}-{repetition + 1}.txt", args.procs, targets)
                result.update(enabled=enabled, repetition=repetition + 1)
                result["cpu_seconds_per_gib"] = result["cpu_seconds"] / (result["iterations"] * bytes_per_operation / 2**30)
                results.append(result)
                print(json.dumps(result), flush=True)
    for enabled in [False, True]:
        suffix = str(enabled).lower()
        result = measure(args.binary.resolve(), f"^BenchmarkUserUsageIdleMemory$/^{suffix}$", "3x",
                         args.output / f"IdleMemory-{suffix}.txt", args.procs, targets)
        result.update(enabled=enabled, repetition=1)
        results.append(result)
        print(json.dumps(result), flush=True)
    fields = sorted({key for row in results for key in row})
    with (args.output / "results.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
