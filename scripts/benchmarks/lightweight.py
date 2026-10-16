#!/usr/bin/env python3
"""Run isolated no-offload TUN baselines; retain every sample and its median."""

import argparse
import json
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
    parser.add_argument("--quick", action="store_true", help="MTU 1500, one flow")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ, GOMAXPROCS="4")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with tempfile.TemporaryDirectory(prefix="yuhaiin-lightweight-") as temp:
        binary = str(Path(temp) / "kernel.test")
        subprocess.run(["go", "test", "-c", "-tags", "lightweight_kernel", "-o", binary,
                        "./pkg/net/proxy/tun/lightweight"], cwd=repo, env=env, check=True)
        with args.output.open("w") as raw:
            metadata = {"os": platform.platform(), "go": subprocess.check_output(
                ["go", "version"], text=True).strip(), "gomaxprocs": 4,
                "offload": False, "tun_tx_queue": 10000, "samples": args.samples,
                "benchtime": args.benchtime, "client": "Linux TCP, same process"}
            raw.write(json.dumps(metadata) + "\n")
            for sample in range(args.samples):
                for kind in ("gvisor", "tun2socket", "reno", "cubic", "bbr"):
                    for mtu in ([1500] if args.quick else [1280, 1500, 9000]):
                        for flows in ([1] if args.quick else [1, 8, 100]):
                            for direction in ("upload", "download"):
                                case = f"{kind}/mtu={mtu}/flows={flows}/{direction}"
                                pattern = "^BenchmarkTUN$/" + "/".join(
                                    "^" + part + "$" for part in case.split("/"))
                                command = ["unshare", "-Urn", binary, "-test.run=^$",
                                           "-test.bench=" + pattern,
                                           "-test.benchtime=" + args.benchtime,
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
                                            if line.startswith("BenchmarkTUN/"))
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
