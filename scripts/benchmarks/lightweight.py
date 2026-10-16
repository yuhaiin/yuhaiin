#!/usr/bin/env python3
"""Run isolated no-offload TUN baselines; retain every sample and its median."""

import argparse
import json
import hashlib
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile


def parse_record(output, case, sample):
    # A stack's close log can split Go's benchmark name from its measurements.
    # Locate the measured ns/op row rather than assuming both share one line.
    line = next((line for line in output.splitlines()
                 if re.search(r"\b[0-9.]+\s+ns/op\b", line)), None)
    if line is None:
        raise ValueError(f"no benchmark measurements for {case}; check filters")
    fields = line.split()
    start = fields.index("ns/op") - 1
    metrics = {fields[i + 1]: float(fields[i])
               for i in range(start, len(fields), 2)}
    return {"case": case, "sample": sample,
            "iterations": int(fields[start - 1]), **metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--benchtime", default="200ms")
    parser.add_argument("--idle", action="store_true", help="1000 idle connections, one measurement per process")
    parser.add_argument("--quick", action="store_true", help="MTU 1500, one flow")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, help="Use an already built benchmark binary")
    parser.add_argument("--resume", action="store_true", help="Continue completed samples from the same binary and environment")
    parser.add_argument("--stacks", nargs="+", choices=["gvisor", "tun2socket", "reno", "cubic", "bbr"])
    parser.add_argument("--mtus", nargs="+", type=int)
    parser.add_argument("--flows", nargs="+", type=int)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ, GOMAXPROCS="4")
    kinds = args.stacks or ["gvisor", "tun2socket", "reno", "cubic", "bbr"]
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
        metadata = {"os": platform.platform(), "go": subprocess.check_output(
                ["go", "version"], text=True).strip(), "gomaxprocs": 4,
                "offload": False, "tun_tx_queue": 10000, "samples": args.samples,
                "benchtime": benchtime, "client": "Linux TCP, same process",
                "binary_sha256": binary_hash,
                "workload": "1000 idle connections" if args.idle else "TCP stream"}
        completed = set()
        if args.resume:
            previous = args.output.read_text()
            if json.loads(previous.splitlines()[0]) != metadata:
                raise ValueError("resume requires identical binary and benchmark environment")
            chunks = re.split(r"(?m)^# sample (\d+): ([^\n]+)\n", previous)
            allowed = {case for case, _ in cases}
            for i in range(1, len(chunks), 3):
                sample, case, output = int(chunks[i]), chunks[i + 1], chunks[i + 2]
                if case not in allowed or not 1 <= sample <= args.samples:
                    raise ValueError("existing sample does not belong to requested cases")
                if "--- FAIL:" in output or not re.search(r"(?m)^PASS$", output):
                    raise ValueError("preserve failed/incomplete run and use a new output file")
                if (sample, case) in completed:
                    raise ValueError("duplicate existing sample")
                records.append(parse_record(output, case, sample))
                completed.add((sample, case))
            print(f"resume: retained {len(completed)} completed samples", flush=True)
        with args.output.open("a" if args.resume else "w") as raw:
            if not args.resume:
                raw.write(json.dumps(metadata) + "\n")
            for sample in range(args.samples):
                for case, pattern in cases:
                    if (sample + 1, case) in completed:
                        continue
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
                    records.append(parse_record(result.stdout, case, sample + 1))
    medians = {}
    for case in sorted({record["case"] for record in records}):
        rows = [record for record in records if record["case"] == case]
        medians[case] = {key: statistics.median(row[key] for row in rows)
                         for key in rows[0] if key not in ("case", "sample")}
    args.output.with_suffix(".json").write_text(
        json.dumps({"samples": records, "medians": medians}, indent=2) + "\n")


if __name__ == "__main__":
    main()
