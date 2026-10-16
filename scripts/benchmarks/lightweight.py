#!/usr/bin/env python3
"""Run isolated no-offload TUN baselines; retain every sample and its median."""

import argparse
import json
import hashlib
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--benchtime", default="200ms")
    parser.add_argument("--idle", action="store_true", help="1000 idle connections, one measurement per process")
    parser.add_argument("--quick", action="store_true", help="MTU 1500, one flow")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, help="Use an already built benchmark binary")
    parser.add_argument("--stacks", nargs="+")
    parser.add_argument("--mtus", nargs="+", type=int)
    parser.add_argument("--flows", nargs="+", type=int)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ, GOMAXPROCS="4")
    kinds = args.stacks or (["gvisor", "tun2socket", "cubic"] if args.idle else
                            ["gvisor", "tun2socket", "reno", "cubic", "bbr"])
    cases = []
    for kind in kinds:
        if args.idle:
            cases.append((f"{kind}/idle=1000", f"^BenchmarkTUNIdle$/^{kind}$"))
            continue
        for mtu in (args.mtus or ([1500] if args.quick else [1280, 1500, 9000])):
            for flows in (args.flows or ([1] if args.quick else [1, 8, 100])):
                for direction in ("upload", "download"):
                    case = f"{kind}/mtu={mtu}/flows={flows}/{direction}"
                    pattern = "^BenchmarkTUN$/" + "/".join("^" + part + "$" for part in case.split("/"))
                    cases.append((case, pattern))
    benchtime = "1x" if args.idle else args.benchtime
    args.output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with tempfile.TemporaryDirectory(prefix="yuhaiin-lightweight-") as temp:
        binary = str(args.binary.resolve()) if args.binary else str(Path(temp) / "kernel.test")
        if not args.binary:
            subprocess.run(["go", "test", "-c", "-tags", "lightweight_kernel", "-o", binary,
                        "./pkg/net/proxy/tun/lightweight"], cwd=repo, env=env, check=True)
        # Stream the binary hash: loading the whole binary would inflate the
        # Python parent's RSS inherited by each fork/exec child (ru_maxrss).
        with open(binary, "rb") as executable:
            binary_hash = hashlib.file_digest(executable, "sha256").hexdigest()
        with args.output.open("w") as raw:
            metadata = {"os": platform.platform(), "go": subprocess.check_output(
                ["go", "version"], text=True).strip(), "gomaxprocs": 4,
                "offload": False, "tun_tx_queue": 10000, "samples": args.samples,
                "benchtime": benchtime, "client": "Linux TCP, same process",
                "binary_sha256": binary_hash,
                "workload": "1000 idle connections" if args.idle else "TCP stream"}
            raw.write(json.dumps(metadata) + "\n")
            for sample in range(args.samples):
                for case, pattern in cases:
                    command = ["unshare", "-Urn", binary, "-test.run=^$",
                               "-test.bench=" + pattern,
                               "-test.benchtime=" + benchtime,
                               "-test.benchmem", "-test.timeout=90s"]
                    print(f"sample {sample + 1}: {case}", flush=True)
                    result = subprocess.run(command, env=env, text=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            timeout=100)
                    raw.write(f"\n# sample {sample + 1}: {case}\n")
                    raw.write("\n".join(line.rstrip() for line in result.stdout.splitlines()) + "\n")
                    raw.flush()
                    if result.returncode or "--- FAIL:" in result.stdout:
                        raise RuntimeError(f"failed {case}; see {args.output}")
                    line = next(line for line in result.stdout.splitlines()
                                if line.startswith("BenchmarkTUN"))
                    fields = line.split()
                    metrics = {fields[i + 1]: float(fields[i])
                               for i in range(2, len(fields), 2)}
                    records.append({"case": case, "sample": sample + 1,
                                    "iterations": int(fields[1]), **metrics})
    medians = {}
    for case in sorted({record["case"] for record in records}):
        rows = [record for record in records if record["case"] == case]
        medians[case] = {key: statistics.median(row[key] for row in rows)
                         for key in rows[0] if key not in ("case", "sample")}
    args.output.with_suffix(".json").write_text(
        json.dumps({"samples": records, "medians": medians}, indent=2) + "\n")


if __name__ == "__main__":
    main()
