#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: check-freebsd-binary.sh BINARY}"
header=$(readelf --file-header "$binary")
notes=$(readelf --notes "$binary")
if [[ "$header" != *AArch64* || "$notes" != *FreeBSD*NT_VERSION* ]]; then
  echo 'expected a FreeBSD ARM64 ELF executable' >&2
  exit 1
fi
segments=$(readelf --program-headers --wide "$binary")
if [[ "$segments" != *'Requesting program interpreter: /libexec/ld-elf.so.1]'* ]]; then
  echo 'expected the FreeBSD system loader' >&2
  exit 1
fi
metadata=$(go version -m "$binary")
if [[ "$metadata" != *$'\tbuild\tGOOS=freebsd'* ||
      "$metadata" != *$'\tbuild\tGOARCH=arm64'* ||
      "$metadata" != *$'\tbuild\tCGO_ENABLED=1'* ||
      "$metadata" != *$'\tdep\tgithub.com/yuhaiin/purego-sqlite\t'* ||
      "$metadata" == *modernc.org/sqlite* || "$metadata" == *github.com/mattn/go-sqlite3* ]]; then
  echo 'expected FreeBSD ARM64 with the linked purego-sqlite CGO backend' >&2
  exit 1
fi
dynamic=$(readelf --dynamic --wide "$binary")
if [[ "$dynamic" == *'(RPATH)'* || "$dynamic" == *'(RUNPATH)'* ]]; then
  echo 'FreeBSD binaries must not depend on build-host library paths' >&2
  exit 1
fi
libraries=$(sed -n 's/.*(NEEDED).*\[\([^]]*\)\].*/\1/p' <<< "$dynamic")
test -n "$libraries"
while IFS= read -r library; do
  case "$library" in
    libc.so.7|libthr.so.3|libm.so.5) ;;
    *) echo "unexpected FreeBSD shared library: $library" >&2; exit 1 ;;
  esac
done <<< "$libraries"
symbols=$(readelf --dyn-syms --wide "$binary")
if awk '$7 == "UND" && $8 ~ /^sqlite3_/ { found=1 } END { exit !found }' <<< "$symbols"; then
  echo 'SQLite must be linked into the executable' >&2
  exit 1
fi
printf '%s: FreeBSD ARM64, linked SQLite, FreeBSD system libraries only\n%s\n' "$binary" "$libraries"
