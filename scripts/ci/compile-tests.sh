#!/usr/bin/env bash
set -euo pipefail

if (( $# < 4 )); then
  echo "usage: $0 OS ARCH OUTPUT_DIR PACKAGE..." >&2
  exit 1
fi

export GOOS="$1" GOARCH="$2" CGO_ENABLED=0
output_dir="$3"
shift 3
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)
suffix=.test
if [[ "$GOOS" == windows ]]; then suffix+=.exe; fi

# Expand patterns first and check go list's status, then compile each package
# separately. Full import paths avoid collisions between packages named backup.
packages=$(go list "$@")
while IFS= read -r package; do
  echo "Cross-compile $package for $GOOS/$GOARCH"
  go test -c -o "$output_dir/${package//\//_}$suffix" "$package"
done <<< "$packages"
