#!/usr/bin/env bash
set -euo pipefail

# Print only the compiler path to stdout so release and container jobs can share it.
case "${1:?usage: install-musl-toolchain.sh ARCH}" in
  amd64|amd64v3|amd64v4)
    target=x86_64-unknown-linux-musl
    sha256=5f20e367608d6e547c04534d37d00ecedbaa0c2e82730df12957b3332fa36a2d
    ;;
  arm64)
    target=aarch64-unknown-linux-musl
    sha256=90282c463498dcdab9b96a464a0925d53f30c884b2d7b25e3998999416ae34b8
    ;;
  mipsle)
    target=mipsel-unknown-linux-muslsf
    sha256=f4677bd1e8792aa8ccab705295c4360f41dac0690cc8b3125df2c34e4fd66dfa
    ;;
  *)
    echo "unsupported Linux release architecture: $1" >&2
    exit 1
    ;;
esac

toolchain_dir="${RUNNER_TEMP:?RUNNER_TEMP must be set}"
archive="${toolchain_dir}/${target}.tar.xz"
url="https://github.com/cross-tools/musl-cross/releases/download/20260515/${target}.tar.xz"
curl --fail --location --retry 3 --output "$archive" "$url" >&2
echo "$sha256  $archive" | sha256sum --check >&2
tar --extract --xz --file "$archive" --directory "$toolchain_dir"
compiler="${toolchain_dir}/${target}/bin/${target}-gcc"
test -x "$compiler"
echo "$compiler"
