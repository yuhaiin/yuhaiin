#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: check-windows-binary.sh BINARY ARCH}"
case "${2:?usage: check-windows-binary.sh BINARY ARCH}" in
  amd64|amd64v3|amd64v4)
    expected_format=COFF-x86-64
    expected_goarch=amd64
    expected_cpu="${2#amd64}"
    expected_cpu="${expected_cpu:-v1}"
    ;;
  arm64)
    expected_format=COFF-ARM64
    expected_goarch=arm64
    expected_cpu=""
    ;;
  *)
    echo "unsupported Windows release architecture: $2" >&2
    exit 1
    ;;
esac

details=$("${LLVM_READOBJ:-llvm-readobj}" --file-headers --coff-imports "$binary")
format=$(awk '$1 == "Format:" { print $2 }' <<< "$details")
if [[ "$format" != "$expected_format" ]]; then
  echo "unexpected PE architecture: $format, want $expected_format" >&2
  exit 1
fi

metadata=$(go version -m "$binary")
if [[ "$metadata" != *$'\tbuild\tGOARCH='"$expected_goarch"* ||
      ( -n "$expected_cpu" && "$metadata" != *$'\tbuild\tGOAMD64='"$expected_cpu"* ) ]]; then
  echo "unexpected Go architecture/CPU target for $2" >&2
  exit 1
fi
if [[ "$metadata" != *$'\tdep\tgithub.com/mattn/go-sqlite3\t'* ||
      "$metadata" != *$'\tbuild\tCGO_ENABLED=1'* ||
      "$metadata" == *modernc.org/sqlite* ]]; then
  echo "Windows binary must use cgo and the mattn SQLite backend" >&2
  exit 1
fi

dlls=$(awk '$1 == "Name:" { print tolower($2) }' <<< "$details")
test -n "$dlls"
while IFS= read -r dll; do
  case "$dll" in
    # These are Windows system libraries/API sets, never toolchain sidecar DLLs.
    api-ms-win-*.dll|ext-ms-win-*.dll|kernel32.dll|ntdll.dll|ucrtbase.dll|msvcrt.dll|\
    advapi32.dll|bcrypt.dll|crypt32.dll|dnsapi.dll|iphlpapi.dll|mswsock.dll|\
    ole32.dll|oleaut32.dll|secur32.dll|shell32.dll|user32.dll|userenv.dll|\
    version.dll|ws2_32.dll|wtsapi32.dll) ;;
    *)
      echo "unexpected external DLL dependency: $dll" >&2
      exit 1
      ;;
  esac
done <<< "$dlls"
printf '%s: %s, cgo + mattn, Windows system DLLs only\n%s\n' "$binary" "$format" "$dlls"
