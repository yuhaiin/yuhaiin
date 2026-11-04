#!/usr/bin/env bash
set -euo pipefail

export GOOS="${1:?usage: release.sh OS ARCH [OUTPUT_DIR]}"
asset_arch="${2:?usage: release.sh OS ARCH [OUTPUT_DIR]}"
export RELEASE_ARCH="${asset_arch%-glibc}"
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

# Primary targets load the embedded library through PureGo. Linux publishes
# explicit -glibc variants; legacy Linux asset names stay fully static so older
# musl installations can safely update through their existing asset selector.
backend="${SQLITE_BACKEND:-auto}"
if [[ "$asset_arch" == *-glibc ]]; then
  if [[ "$GOOS" != linux ]]; then echo "-glibc is a Linux-only variant" >&2; exit 1; fi
  backend=purego
fi
case "$backend" in auto|purego|cgo) ;; *) echo "invalid SQLITE_BACKEND: $backend" >&2; exit 1 ;; esac
purego_supported=0
case "$GOOS/$GOARCH" in
  linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/arm64|freebsd/amd64)
    purego_supported=1 ;;
  android/amd64|android/arm64|freebsd/arm64|openbsd/amd64|openbsd/arm64|linux/mipsle) ;;
  *) echo "unsupported release target: $GOOS/$GOARCH" >&2; exit 1 ;;
esac
if [[ "$backend" == auto ]]; then
  if [[ "$GOOS" == linux ]]; then backend=cgo
  elif [[ "$purego_supported" == 1 ]]; then backend=purego
  else backend=cgo; fi
fi
export CGO_ENABLED=0 STATIC_LINK=0 EXTRA_GO_TAGS=""
if [[ "$backend" == purego ]]; then
  if [[ "$GOOS" == linux ]]; then asset_arch="${RELEASE_ARCH}-glibc"; fi
  if [[ "$purego_supported" != 1 ]]; then
    echo "PureGo SQLite is unavailable for $GOOS/$GOARCH; use SQLITE_BACKEND=cgo" >&2
    exit 1
  fi
  if [[ "$GOOS" == freebsd ]]; then
    export GO_GCFLAGS=github.com/ebitengine/purego/internal/fakecgo=-std
  fi
else
  export CGO_ENABLED=1 EXTRA_GO_TAGS=sqlite_cgo
  case "$GOOS" in
    linux|windows)
      export STATIC_LINK=1
      : "${CC:?static CGO builds require a compiler matching the target (musl for Linux)}"
      ;;
    android)
      if [[ -z "${CC:-}" ]]; then
        ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-}}"
        : "${ndk:?Android builds require ANDROID_NDK_HOME or CC}"
        triple=aarch64-linux-android
        if [[ "$GOARCH" == amd64 ]]; then triple=x86_64-linux-android; fi
        export CC="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}24-clang"
      fi
      ;;
    freebsd|openbsd)
      if [[ $(uname -s | tr '[:upper:]' '[:lower:]') != "$GOOS" ]]; then
        : "${CC:?BSD cross-builds require a compiler with the matching target sysroot}"
      fi
      ;;
    darwin)
      if [[ $(uname -s) == Darwin ]]; then
        export CC="${CC:-$(xcrun --find clang)}"
        export SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path)}"
      else
        : "${CC:?Darwin cgo cross-builds require an osxcross compiler}"
      fi
      export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
      export CGO_CFLAGS="${CGO_CFLAGS:--O2 -g} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"
      export CGO_LDFLAGS="${CGO_LDFLAGS:--O2 -g} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"
      ;;
  esac
fi

extension=""
if [[ "$GOOS" == windows ]]; then
  extension=.exe
fi
binary="${output_dir}/yuhaiin-${GOOS}-${asset_arch}${extension}"
mkdir -p "$output_dir"
"${MAKE:-make}" yuhaiin
mv "yuhaiin${extension}" "$binary"

# Describe the target on the build host; never execute a cross-compiled binary.
metadata_host_os=$(go env GOHOSTOS)
metadata_host_arch=$(go env GOHOSTARCH)
metadata_target_os="$GOOS"
GOOS="$metadata_host_os" GOARCH="$metadata_host_arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0 \
  go run ./cmd/update-metadata -binary "$binary" -os "$metadata_target_os" -arch "$RELEASE_ARCH"


if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "binary=$binary" >> "$GITHUB_OUTPUT"
fi
