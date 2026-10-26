#!/usr/bin/env python3
"""Measure fresh-process restore RSS, excluding fixture/encryption generation."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


# A fresh wrapper has exactly one child, so RUSAGE_CHILDREN contains only this
# restore, never the fixture builder or a previous (larger) test case.
MEASURE_CHILD = """
import json, resource, subprocess, sys, time
started = time.monotonic()
completed = subprocess.run(sys.argv[1:], capture_output=True, text=True,
                           timeout=300, check=True)
print(json.dumps(dict(result=json.loads(completed.stdout),
                     rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                     elapsed_s=time.monotonic()-started)))
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--fixture-binary", required=True)
    parser.add_argument("--heap-limit", default="32MiB")
    parser.add_argument("--sizes", default="1,64,256")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this runner reports Linux ru_maxrss in KiB")
    for size in map(int, args.sizes.split(",")):
        fixture = json.loads(subprocess.check_output(
            [args.fixture_binary, "-size-mib", str(size)], text=True
        ))
        try:
            command = [
                args.binary, "recovery", "restore",
                "-path", fixture["target"], "-archive", fixture["archive"],
                "-identity-file", fixture["identityFile"], "-mode", "original",
                "-maintenance", "-source-stopped", "-restore-credentials",
                "-confirm-backup", fixture["backupId"],
                "-confirm-source-instance", fixture["instanceId"],
                "-confirm-target-instance", "empty",
            ]
            environment = dict(os.environ, GOMEMLIMIT=args.heap_limit)
            completed = subprocess.run([sys.executable, "-c", MEASURE_CHILD, *command],
                                       capture_output=True, text=True,
                                       env=environment, timeout=310, check=True)
            measurement = json.loads(completed.stdout)
            result = measurement["result"]
            if result["state"] != "awaiting_startup" or result["instanceId"] != fixture["instanceId"]:
                raise RuntimeError("restore did not reach a verified file-activation boundary")
            restored = Path(fixture["target"], "web", "fixture.bin")
            if restored.stat().st_size != size << 20:
                raise RuntimeError("restored payload size differs")
            print(json.dumps(dict(asset_mib=size, rss_kib=measurement["rss_kib"],
                                  elapsed_s=measurement["elapsed_s"],
                                  heap_limit=args.heap_limit)), flush=True)
        finally:
            # Only directories created by this fixture helper are eligible.
            for key, prefix in (("root", ".recovery-resource-fixture-"),
                                ("keyDirectory", ".recovery-resource-key-")):
                path = Path(fixture[key])
                if not path.name.startswith(prefix):
                    raise RuntimeError("refusing cleanup of an unowned fixture path")
                shutil.rmtree(path)


if __name__ == "__main__":
    main()
