#!/usr/bin/env bash
set -euo pipefail

# Installs the prebuilt FreeBSD ARM64 cross toolchain (FreeBSD SDK plus GNU
# ld.bfd) that .github/workflows/freebsd-toolchain.yml builds with
# build-freebsd-toolchain.sh and publishes as a GitHub release asset.
# freebsd-toolchain.lock pins the release tag and the asset checksum.
if [[ "${1:?usage: install-freebsd-toolchain.sh arm64}" != arm64 || $(uname -s) != Linux ]]; then
  echo 'this FreeBSD toolchain supports arm64 builds on Linux only' >&2
  exit 1
fi
root="${FREEBSD_CROSS_ROOT:-${RUNNER_TEMP:?RUNNER_TEMP must be set}/freebsd-cross}"
mkdir -p "$root"
root=$(cd "$root" && pwd)
compiler="$root/bin/freebsd-arm64-cc"
if [[ -f "$root/.complete" && -x "$compiler" && -x "$root/toolchain/bin/ld.bfd" ]]; then
  echo "$compiler"
  exit 0
fi

lock="$(cd "$(dirname "$0")" && pwd)/freebsd-toolchain.lock"
tag=$(sed -n 's/^tag=//p' "$lock")
digest=$(sed -n 's/^sha256=//p' "$lock")
if [[ -z "$tag" || ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid $lock; run build-freebsd-toolchain.sh to build from source" >&2
  exit 1
fi
repo="${FREEBSD_TOOLCHAIN_REPO:-yuhaiin/yuhaiin}"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/freebsd-cross-download.XXXXXX")
trap 'rm -rf "$work"' EXIT
archive="$work/freebsd-arm64-toolchain.tar.zst"
curl --fail --location --retry 3 --silent --show-error --output "$archive" \
  "https://github.com/$repo/releases/download/$tag/freebsd-arm64-toolchain.tar.zst" >&2
echo "$digest  $archive" | sha256sum --check >&2

rm -rf "$root/bin" "$root/sysroot" "$root/toolchain" "$root/.complete"
tar --extract --zstd --file "$archive" --directory "$root"
"$compiler" -fuse-ld=bfd -Wl,--version >&2
touch "$root/.complete"
echo "$compiler"
