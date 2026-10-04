#!/usr/bin/env bash
set -euo pipefail

export GOOS="${1:?usage: release.sh OS ARCH [OUTPUT_DIR]}"
export RELEASE_ARCH="${2:?usage: release.sh OS ARCH [OUTPUT_DIR]}"
output_dir="${3:-.}"

export GOARCH="$RELEASE_ARCH" GOAMD64="" GOMIPS=""
case "$RELEASE_ARCH" in
  amd64|arm64) ;;
  amd64v3|amd64v4)
    export GOARCH=amd64 GOAMD64="${RELEASE_ARCH#amd64}"
    ;;
  mipsle)
    export GOMIPS=softfloat
    ;;
  *)
    echo "unsupported release architecture: $RELEASE_ARCH" >&2
    exit 1
    ;;
esac

export CGO_ENABLED=0 STATIC_LINK=0 EXTRA_GO_TAGS=""
case "$GOOS" in
  linux)
    export CGO_ENABLED=1 STATIC_LINK=1 EXTRA_GO_TAGS=sqlite_mattn
    ;;
  darwin)
    export CGO_ENABLED=1 EXTRA_GO_TAGS=sqlite_mattn
    if [[ $(uname -s) == Darwin ]]; then
      CC="${CC:-$(xcrun --find clang)}"
      SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path)}"
      export SDKROOT
    else
      : "${CC:?Darwin cgo cross-builds require an osxcross compiler}"
    fi
    export CC
    # Keep cgo's deployment target aligned with Go 1.27's macOS minimum.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
    # Explicit flags also make the target part of Go's cgo build cache key.
    export CGO_CFLAGS="${CGO_CFLAGS:--O2 -g} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"
    export CGO_LDFLAGS="${CGO_LDFLAGS:--O2 -g} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"
    ;;
  windows)
    # Link compiler runtimes statically; only Windows system DLLs may be imported.
    export CGO_ENABLED=1 STATIC_LINK=1 EXTRA_GO_TAGS=sqlite_mattn
    : "${CC:?Windows cgo builds require the llvm-mingw compiler}"
    ;;
  android|freebsd|openbsd) ;;
  *)
    echo "unsupported release OS: $GOOS" >&2
    exit 1
    ;;
esac

extension=""
if [[ "$GOOS" == windows ]]; then
  extension=.exe
fi
binary="${output_dir}/yuhaiin-${GOOS}-${RELEASE_ARCH}${extension}"
mkdir -p "$output_dir"
make yuhaiin
mv "yuhaiin${extension}" "$binary"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "binary=$binary" >> "$GITHUB_OUTPUT"
fi
