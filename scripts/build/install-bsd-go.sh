#!/usr/bin/env bash
set -euo pipefail

os="${1:?usage: install-bsd-go.sh OS ARCH}"
case "${2:?usage: install-bsd-go.sh OS ARCH}" in
  amd64|amd64v3|amd64v4) arch=amd64 ;;
  arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $2" >&2; exit 1 ;;
esac
case "$os/$arch" in
  freebsd/amd64) digest=c15c88d07d6b2d2db5df7b65d9b9c73d631ac4e787da04e2bef2a5b6952c2cbb ;;
  freebsd/arm64) digest=cca2dd0aa1cf6df18df55762ee9fe6ee31c77ebcfc51e8c635d333e14aa9e2c1 ;;
  openbsd/amd64) digest=8b16704326759ee5bc8aded3852bbcbf6ea96daa93033e696d6e4dc63f041644 ;;
  openbsd/arm64) digest=9efb4b26089e23f39ecaf8763c6b35ab306924e8c93d56bd8f8289f92a4471a9 ;;
  *) echo "unsupported BSD: $os" >&2; exit 1 ;;
esac
root=/tmp/sqlite-go
mkdir -p "$root"
curl --fail --location --retry 3 --output "$root/go.tar.gz" "https://go.dev/dl/go1.27.3.${os}-${arch}.tar.gz"
test "$(sha256 -q "$root/go.tar.gz")" = "$digest"
tar -C "$root" -xzf "$root/go.tar.gz"
