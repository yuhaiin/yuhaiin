#!/usr/bin/env bash
# Builds the c-shared core for the host and runs the C conformance harness.
# Requires cgo and a C compiler. Usage: cmd/androidlib/abi_test.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
CGO_ENABLED=1 go build -buildmode=c-shared -o "$work/libyuhaiin.so" ./cmd/androidlib
${CC:-cc} -Wall -Werror -pthread -I cmd/androidlib cmd/androidlib/testdata/abi_harness.c \
  -L "$work" -lyuhaiin -Wl,-rpath,"$work" -o "$work/harness"
mkdir "$work/data"
"$work/harness" "$work/data"
