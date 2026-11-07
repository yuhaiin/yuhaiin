#!/usr/bin/env bash
set -euo pipefail

# Go requires GNU ld.bfd for FreeBSD ARM64 external linking (golang/go#35197).
# Clang supplies the cross compiler; the official base archive supplies the SDK.
#
# This builds the toolchain from source, which takes minutes because the
# FreeBSD archive mirror is slow. CI installs the prebuilt copy published by
# .github/workflows/freebsd-toolchain.yml through install-freebsd-toolchain.sh.
# Any change here publishes a new release; then update freebsd-toolchain.lock.
if [[ "${1:?usage: build-freebsd-toolchain.sh arm64}" != arm64 || $(uname -s) != Linux ]]; then
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

work=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP must be set}/freebsd-cross-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
download() {
  local url=$1 digest=$2 archive=$3
  curl --fail --location --retry 3 --output "$archive" "$url" >&2
  echo "$digest  $archive" | sha256sum --check >&2
}
download https://archive.freebsd.org/old-releases/arm64/aarch64/14.3-RELEASE/base.txz \
  f83e824cb7a20dbadb2888a8bd253e6a1ac35024cc6dc8af9f3e229f75ec7129 "$work/base.txz"
download https://ftp.gnu.org/gnu/binutils/binutils-2.45.tar.xz \
  c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2 "$work/binutils.tar.xz"

rm -rf "$root/sysroot" "$root/toolchain"
mkdir -p "$root/sysroot" "$root/bin" "$work/build"
tar --extract --xz --file "$work/base.txz" --directory "$root/sysroot" \
  --no-same-owner --no-same-permissions ./lib ./usr/lib ./usr/include
# Keep any absolute SDK symlinks inside the sysroot when used on Linux.
while IFS= read -r -d '' link; do
  target=$(readlink "$link")
  if [[ "$target" == /* ]]; then
    ln -sfn "$(realpath -m --relative-to="$(dirname "$link")" "$root/sysroot$target")" "$link"
  fi
done < <(find "$root/sysroot" -type l -print0)
tar --extract --xz --file "$work/binutils.tar.xz" --directory "$work"
if ! (
  cd "$work/build"
  ../binutils-2.45/configure --target=aarch64-unknown-freebsd14.3 \
    --prefix="$root/toolchain" --with-sysroot="$root/sysroot" \
    --disable-nls --disable-werror --disable-gdb --disable-gprof --disable-gprofng \
    --disable-gold --disable-sim --disable-binutils --disable-gas --disable-libctf \
    --disable-shared --disable-plugins --without-debuginfod --without-zstd &&
  make -j"$(getconf _NPROCESSORS_ONLN)" all-ld &&
  make install-ld
) > "$work/binutils.log" 2>&1; then
  cat "$work/binutils.log" >&2
  exit 1
fi
ln -s aarch64-unknown-freebsd14.3-ld.bfd "$root/toolchain/bin/ld.bfd"
cat > "$compiler" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
exec clang --target=aarch64-unknown-freebsd14.3 --sysroot="$root/sysroot" \
  -B"$root/toolchain/bin" "$@"
EOF
chmod +x "$compiler"
"$compiler" -fuse-ld=bfd -Wl,--version >&2
touch "$root/.complete"
echo "$compiler"
