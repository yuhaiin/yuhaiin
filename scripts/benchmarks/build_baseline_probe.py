#!/usr/bin/env python3
"""Build a historical lightweight core with the current benchmark/device fixture.

The historical core ignores the optional packet-view/GSO interfaces. Their
stdlib-only declarations remain available so the current adapter can compile.
Only plain cubic/bbr modes are meaningful for this baseline. No checkout files
are changed; Go's overlay substitutes the historical core for this build.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="29be8d0f")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    ref = subprocess.check_output(["git", "rev-parse", "--verify", args.ref + "^{commit}"], text=True).strip()
    core = "pkg/net/proxy/tun/lightweight"
    paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", ref, "--", core], text=True).splitlines()
    with tempfile.TemporaryDirectory(prefix="lightweight-baseline-") as temporary:
        overlay = {}
        for name in paths:
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            destination = Path(temporary) / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(subprocess.check_output(["git", "show", ref + ":" + name]))
            overlay[str(root / name)] = str(destination)
        if not overlay:
            raise SystemExit("selected revision contains no lightweight core")
        mapping = Path(temporary) / "overlay.json"
        mapping.write_text(json.dumps({"Replace": overlay}))
        subprocess.run(["go", "build", "-overlay", str(mapping), "-o", str(args.output.resolve()),
                        "./scripts/benchmarks/stackprobe"], cwd=root, check=True,
                       env=os.environ | {"CGO_ENABLED": "0"})
    print(f"Built core {ref} with the current plain-packet benchmark adapter: {args.output}")


if __name__ == "__main__":
    main()
