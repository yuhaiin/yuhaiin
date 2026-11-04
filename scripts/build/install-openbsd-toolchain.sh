#!/usr/bin/env bash
set -euo pipefail

case "${1:?usage: install-openbsd-toolchain.sh ARCH}" in
  amd64|amd64v3|amd64v4)
    arch=amd64
    base_sha256=2f7a6fba6c6448b95a3118099bc71b832b4b7c7c5a7f97418e443546fa6e6243
    comp_sha256=a2a8a6f9b83e4e43e609e7ef4cb22c676f4e6fcfb9407ea566ed31a8021d386f
    ;;
  arm64)
    arch=arm64
    base_sha256=4c4524e4a0def7101daf3b110605e8ad1017b99ed5c962638537af05c290f02d
    comp_sha256=e96b60469756c8c42085b982558c8a52f15def4a1dc9b1226ed786e17d0834fe
    ;;
  *) echo "unsupported OpenBSD architecture: $1" >&2; exit 1 ;;
esac
if [[ $(uname -s) != Linux ]]; then
  echo 'this OpenBSD cross toolchain requires Linux' >&2
  exit 1
fi
root="${OPENBSD_CROSS_ROOT:-${RUNNER_TEMP:?RUNNER_TEMP must be set}/openbsd-cross/$arch}"
mkdir -p "$root"
root=$(cd "$root" && pwd)
compiler="$root/bin/openbsd-$arch-cc"
if [[ -f "$root/.complete" && -x "$compiler" && -x "$root/llvm/bin/ld.lld" ]]; then
  echo "$compiler"
  exit 0
fi
work=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP must be set}/openbsd-cross-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
for set in base comp; do
  archive="$work/${set}78.tgz"
  curl --fail --location --retry 3 --output "$archive" \
    "https://cdn.openbsd.org/pub/OpenBSD/7.8/$arch/${set}78.tgz" >&2
  digest="$base_sha256"
  if [[ "$set" == comp ]]; then digest="$comp_sha256"; fi
  echo "$digest  $archive" | sha256sum --check >&2
done

# Reuse the pinned native LLVM distribution, targeting OpenBSD instead of
# Windows. Its LLD supports the OpenBSD NOBTCFI and random-data program headers.
llvm_compiler=$(RUNNER_TEMP="$work" bash "$(dirname "$0")/install-windows-toolchain.sh" "$arch")
llvm_root=$(cd "$(dirname "$llvm_compiler")/.." && pwd)
rm -rf "$root/llvm" "$root/sysroot"
mkdir -p "$root/bin" "$root/sysroot"
mv "$llvm_root" "$root/llvm"
tar --extract --gzip --file "$work/base78.tgz" --directory "$root/sysroot" \
  --no-same-owner --no-same-permissions --wildcards \
  './usr/lib/crt*.o' './usr/lib/libcompiler_rt.a' \
  './usr/lib/libc.so.*' './usr/lib/libm.so.*' './usr/lib/libpthread.so.*'
tar --extract --gzip --file "$work/comp78.tgz" --directory "$root/sysroot" \
  --no-same-owner --no-same-permissions ./usr/include
# OpenBSD's native linker finds versioned libraries without these aliases.
# Upstream LLD needs the conventional names; DT_NEEDED retains each real SONAME.
for library in "$root/sysroot/usr/lib/"*.so.*; do
  ln -s "$(basename "$library")" "${library%%.so.*}.so"
done
# The native OpenBSD linker merges Retguard cookies into the random-data area.
# Preserve that layout, including loader randomization and RELRO protection.
cat > "$root/randomdata.ld" <<'EOF'
SECTIONS {
  .openbsd.randomdata : { *(.openbsd.randomdata .openbsd.randomdata.*) }
}
INSERT BEFORE .dynamic;
EOF
cat > "$compiler" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
case "${0##*/}" in
  openbsd-amd64-cc) target=x86_64-unknown-openbsd7.8 ;;
  openbsd-arm64-cc) target=aarch64-unknown-openbsd7.8 ;;
  *) exit 1 ;;
esac
args=()
for arg in "$@"; do
  case "$arg" in
    # Go uses the native OpenBSD spelling; upstream LLD uses --no-pie.
    -Wl,-nopie) args+=(-Wl,--no-pie) ;;
    *) args+=("$arg") ;;
  esac
done
exec "$root/llvm/bin/clang" -Qunused-arguments --target="$target" \
  --sysroot="$root/sysroot" -fuse-ld="$root/llvm/bin/ld.lld" \
  "-Wl,-T,$root/randomdata.ld,-z,now" "${args[@]}"
EOF
chmod +x "$compiler"
"$root/llvm/bin/ld.lld" -z nobtcfi --version >&2
touch "$root/.complete"
echo "$compiler"
