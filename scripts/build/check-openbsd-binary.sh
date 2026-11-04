#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: check-openbsd-binary.sh BINARY ARCH}"
case "${2:?usage: check-openbsd-binary.sh BINARY ARCH}" in
  amd64|amd64v3|amd64v4)
    arch=amd64
    machine='Advanced Micro Devices X86-64'
    cpu="${2#amd64}"
    cpu="${cpu:-v1}"
    ;;
  arm64) arch=arm64; machine=AArch64; cpu='' ;;
  *) echo "unsupported OpenBSD architecture: $2" >&2; exit 1 ;;
esac
header=$(readelf --file-header "$binary")
notes=$(readelf --notes "$binary")
if [[ "$header" != *'UNIX - OpenBSD'* || "$header" != *"$machine"* || "$notes" != *OpenBSD* ]]; then
  echo "expected an OpenBSD $arch ELF executable" >&2
  exit 1
fi
metadata=$(go version -m "$binary")
if [[ "$metadata" != *$'\tbuild\tGOOS=openbsd'* ||
      "$metadata" != *$'\tbuild\tGOARCH='"$arch"* ||
      ( -n "$cpu" && "$metadata" != *$'\tbuild\tGOAMD64='"$cpu"* ) ||
      "$metadata" != *$'\tbuild\tCGO_ENABLED=1'* ||
      "$metadata" != *$'\tdep\tgithub.com/yuhaiin/purego-sqlite\t'* ||
      "$metadata" == *modernc.org/sqlite* || "$metadata" == *github.com/mattn/go-sqlite3* ]]; then
  echo 'expected the OpenBSD CPU target with linked purego-sqlite CGO' >&2
  exit 1
fi
segments=$(readelf --program-headers --wide "$binary")
if [[ "$segments" != *'Requesting program interpreter: /usr/libexec/ld.so]'* ||
      "$segments" != *OPENBSD_NOBTCF* || "$segments" != *OPENBSD_RANDOM* ||
      "$segments" != *GNU_RELRO* || "$segments" == *RWE* ]]; then
  echo 'missing OpenBSD loader/security headers or executable writable segment' >&2
  exit 1
fi
sections=$(readelf --sections --wide "$binary")
if [[ "$sections" == *' .openbsd.randomdata.'* ]]; then
  echo 'Retguard cookies must be merged into the randomized, protected area' >&2
  exit 1
fi
read -r random_start random_size < <(awk '$1 == "OPENBSD_RANDOM" { print $3, $6 }' <<< "$segments")
read -r relro_start relro_size < <(awk '$1 == "GNU_RELRO" { print $3, $6 }' <<< "$segments")
read -r cookie_start cookie_size < <(awk '{ for (i=1; i<=NF; i++) if ($i == ".openbsd.randomdata") print "0x"$(i+2), "0x"$(i+4) }' <<< "$sections")
if (( cookie_size == 0 || cookie_start != random_start || cookie_size > random_size ||
      random_start < relro_start || random_start + random_size > relro_start + relro_size )); then
  echo 'OpenBSD random data must be covered by both RANDOMIZE and RELRO' >&2
  exit 1
fi
dynamic=$(readelf --dynamic --wide "$binary")
if [[ "$dynamic" == *'(RPATH)'* || "$dynamic" == *'(RUNPATH)'* || "$dynamic" != *BIND_NOW* ]]; then
  echo 'expected immediate binding without build-host library search paths' >&2
  exit 1
fi
libraries=$(sed -n 's/.*(NEEDED).*\[\([^]]*\)\].*/\1/p' <<< "$dynamic")
test -n "$libraries"
while IFS= read -r library; do
  case "$library" in
    libc.so.102.0|libpthread.so.28.0|libm.so.10.1) ;;
    *) echo "unexpected OpenBSD shared library: $library" >&2; exit 1 ;;
  esac
done <<< "$libraries"
symbols=$(readelf --dyn-syms --wide "$binary")
if awk '$7 == "UND" && $8 ~ /^sqlite3_/ { found=1 } END { exit !found }' <<< "$symbols"; then
  echo 'SQLite must be linked into the executable' >&2
  exit 1
fi
printf '%s: OpenBSD %s, linked SQLite, NOBTCFI and protected random data\n%s\n' "$binary" "$2" "$libraries"
