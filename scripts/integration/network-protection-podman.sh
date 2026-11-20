#!/bin/sh
# Network Protection (kill switch) on Linux, against the real kernel's
# nftables, in a privileged Podman container: the container has its own
# network namespace, so the host's firewall, interfaces and routes are not
# touched.
#
#   scripts/integration/network-protection-podman.sh
#
# Requires podman and go; the first run builds a small Alpine image with
# iproute2 and nftables (the same image as system-network-podman.sh).
set -eu
cd "$(dirname "$0")/../.."
BASE_IMAGE=${SYSNET_BASE_IMAGE:-docker.io/library/alpine:3.23}
IMAGE=localhost/yuhaiin-sysnet-test:1
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

go test ./pkg/sysnet/protection/nft/
CGO_ENABLED=0 go test -c -o "$WORK/nft.test" ./pkg/sysnet/protection/nft
if ! podman image exists "$IMAGE"; then
	printf 'FROM %s\nRUN apk add --no-cache iproute2 nftables\n' "$BASE_IMAGE" | podman build -q -t "$IMAGE" -f - "$WORK" >/dev/null
fi
podman run --rm --privileged -v "$WORK:/work:z" "$IMAGE" \
	sh -c 'YUHAIIN_TEST_NFT=1 /work/nft.test -test.v -test.run "^TestKernel"'
