#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_dir"
output="${RUNNER_TEMP:-/tmp}/yuhaiin-linux-abi"
mkdir -p "$output"
CGO_ENABLED=0 go test -c -o "$output/purego.test" ./pkg/storage/sqlite
CGO_ENABLED=1 CC=musl-gcc go test -c -tags=sqlite_cgo \
  -ldflags='-linkmode external -extldflags -static' -o "$output/static.test" ./pkg/storage/sqlite
CGO_ENABLED=1 CC=musl-gcc go test -c -tags=sqlite_cgo \
  -ldflags='-linkmode external -extldflags -static' -o "$output/abi.test" ./pkg/update/compatibility
if readelf -l "$output/static.test" "$output/abi.test" | grep INTERP; then
  echo 'Static fallback contains an ELF interpreter' >&2
  exit 1
fi

docker build -t yuhaiin-sqlite-abi-scratch -f - "$output" <<'DOCKERFILE'
FROM scratch
DOCKERFILE

for image in docker.io/library/centos:7 docker.io/library/debian:bookworm-slim docker.io/library/centos:6 docker.io/library/alpine:3.23 yuhaiin-sqlite-abi-scratch; do
  abi=static
  case "$image" in docker.io/library/centos:7|docker.io/library/debian:bookworm-slim) abi=glibc ;; esac
  echo "Checking $image (expected SQLite update ABI: $abi)"
  args=(--rm --network none --tmpfs "/tmp:exec,mode=1777"
    -v "$repo_dir:/src:ro" -v "$output:/abi:ro"
    -e XDG_CACHE_HOME=/tmp/cache -e "YUHAIIN_TEST_LINUX_ABI=$abi" -e YUHAIIN_GLIBC_CANDIDATE=/abi/purego.test)
  docker run "${args[@]}" "$image" /abi/abi.test -test.v -test.run='^TestLinuxABIEnvironment$'
  docker run "${args[@]}" -w /src/pkg/storage/sqlite "$image" /abi/static.test -test.v -test.timeout=5m
  if [[ "$abi" == glibc ]]; then
    docker run "${args[@]}" -w /src/pkg/storage/sqlite "$image" /abi/purego.test -test.v -test.timeout=5m
  fi
done
