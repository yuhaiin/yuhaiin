#!/usr/bin/env bash
set -euo pipefail

case "${1:?usage: install-windows-toolchain.sh ARCH}" in
  amd64|amd64v3|amd64v4) target=x86_64-w64-mingw32 ;;
  arm64) target=aarch64-w64-mingw32 ;;
  *)
    echo "unsupported Windows release architecture: $1" >&2
    exit 1
    ;;
esac

# All hosts use the same LLVM release and UCRT, which ships with Windows 10+.
version=20260922
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    host=ubuntu-22.04-x86_64
    sha256=bb7bb7654b33d5aa8712acb837c963b2e0c56352560c76105270a3268c665c21
    checksum=(sha256sum -c)
    ;;
  Linux-aarch64)
    host=ubuntu-22.04-aarch64
    sha256=07d21263c56bfe9a713db6fdb3f7434bf4c121a005e40397d3b4c0170fb06769
    checksum=(sha256sum -c)
    ;;
  Darwin-arm64|Darwin-x86_64)
    host=macos-universal
    sha256=52e5f5a7b131021d0c39a37a38fa380a1da7885cd04bd61afd0cd4ecfb8bc1f3
    checksum=(shasum -a 256 -c)
    ;;
  *)
    echo "unsupported llvm-mingw host" >&2
    exit 1
    ;;
esac

toolchain_dir="${RUNNER_TEMP:?RUNNER_TEMP must be set}"
name="llvm-mingw-${version}-ucrt-${host}"
archive="${toolchain_dir}/${name}.tar.xz"
url="https://github.com/mstorsjo/llvm-mingw/releases/download/${version}/${name}.tar.xz"
curl --fail --location --retry 3 --output "$archive" "$url" >&2
echo "$sha256  $archive" | "${checksum[@]}" >&2
tar --extract --xz --file "$archive" --directory "$toolchain_dir"
compiler="${toolchain_dir}/${name}/bin/${target}-clang"
test -x "$compiler"
echo "$compiler"
