#!/usr/bin/env python3
"""Run go build/test with only lightweight's native checksum path disabled.

The temporary Go overlay changes no checkout files or dependency build tags.
Examples: checksum_portable.py test ./pkg/net/proxy/tun/lightweight
          checksum_portable.py build -o /tmp/probe ./scripts/benchmarks/stackprobe
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("build", "test"):
        raise SystemExit(__doc__)
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="checksum-portable-") as temporary:
        source = Path(temporary) / "checksum_native.go"
        source.write_text("""//go:build amd64 || arm64

package lightweight

const checksumAccelerated = false

func checksumBulk(b []byte, sum uint32) ([]byte, uint32) { return b, sum }
""")
        mapping = Path(temporary) / "overlay.json"
        target = root / "pkg/net/proxy/tun/lightweight/checksum_native.go"
        mapping.write_text(json.dumps({"Replace": {str(target): str(source)}}))
        subprocess.run(["go", sys.argv[1], "-overlay", str(mapping), *sys.argv[2:]],
                       cwd=root, check=True)


if __name__ == "__main__":
    main()
