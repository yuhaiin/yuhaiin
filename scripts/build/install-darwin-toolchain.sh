#!/usr/bin/env bash
set -euo pipefail

case "${1:?usage: install-darwin-toolchain.sh ARCH}" in
  amd64|amd64v3|amd64v4) compiler_name=o64-clang ;;
  arm64) compiler_name=oa64-clang ;;
  *)
    echo "unsupported Darwin release architecture: $1" >&2
    exit 1
    ;;
esac
if [[ $(uname -s) != Linux ]]; then
  echo "osxcross installation requires Linux" >&2
  exit 1
fi

# Pin both inputs; update their checksums together with their versions.
revision=27d21e4977c9751d01199c7a226a6faf494c3dd9
source_sha256=c94952432565db84f1b3a9e4ba3d44344b1464fcbeb8c7580ab9db1e7c22834a
sdk_version=14.5
sdk_sha256=6e146275d19f027faa2e8354da5e0267513abf013b8f16ad65a231653a2b1c5d
root="${OSXCROSS_ROOT:-${RUNNER_TEMP:?RUNNER_TEMP must be set}/osxcross}"
target_dir="$root/target"
compiler="$target_dir/bin/$compiler_name"
version="$revision:$sdk_version:$sdk_sha256:llvm18:13.0"

# The workflow restores this directory before calling the installer.
if [[ -f "$root/.version" && $(cat "$root/.version") == "$version" ]]; then
  test -x "$compiler"
  echo "$compiler"
  exit 0
fi

export PATH="/usr/lib/llvm-18/bin:$PATH"
for tool in clang clang++ ld64.lld llvm-lipo; do
  command -v "$tool" >/dev/null
done
source_dir="$root/source"
mkdir -p "$source_dir/tarballs"
source_archive="$root/osxcross.tar.gz"
sdk_archive="$source_dir/tarballs/MacOSX${sdk_version}.sdk.tar.xz"
curl --fail --location --retry 3 --output "$source_archive" \
  "https://github.com/tpoechtrager/osxcross/archive/${revision}.tar.gz" >&2
echo "$source_sha256  $source_archive" | sha256sum -c >&2
tar --extract --gzip --file "$source_archive" --directory "$source_dir" --strip-components=1
curl --fail --location --retry 3 --output "$sdk_archive" \
  "https://github.com/joseluisq/macosx-sdks/releases/download/${sdk_version}/MacOSX${sdk_version}.sdk.tar.xz" >&2
echo "$sdk_sha256  $sdk_archive" | sha256sum -c >&2
(
  cd "$source_dir"
  UNATTENDED=1 BUILD_FLAVOR=llvm ENABLE_REPLACEMENT_LIPO=0 \
    ENABLE_ARCHS='x86_64 arm64' OSX_VERSION_MIN=13.0 SDK_VERSION="$sdk_version" \
    TARGET_DIR="$target_dir" ./build.sh >&2
)
test -x "$target_dir/bin/o64-clang"
test -x "$target_dir/bin/oa64-clang"
rm -- "$source_archive" "$sdk_archive"
echo "$version" > "$root/.version"
echo "$compiler"
