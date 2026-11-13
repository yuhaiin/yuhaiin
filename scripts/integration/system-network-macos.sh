#!/usr/bin/env bash
# macOS checks for the System Network Manager.
#
#   scripts/integration/system-network-macos.sh          unit tests (no root)
#   sudo scripts/integration/system-network-macos.sh --live
#                                                       also live route and PF tests
#
# The live tests add routes for documentation prefixes (198.51.100.0/24,
# 2001:db8:77::/48) via lo0, load rules into the PF anchor com.apple/yuhaiin
# and toggle net.inet.ip.forwarding; Close restores everything. They never
# edit /etc/pf.conf or other anchors.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ "$(uname)" = Darwin ] || { echo "run this on macOS" >&2; exit 2; }
packages=(./pkg/net/netlink ./pkg/sysnet/... ./pkg/contract/sysnet ./pkg/inbound)
if [ "${1:-}" = --live ]; then
	[ "$(id -u)" = 0 ] || { echo "--live needs root (sudo)" >&2; exit 2; }
	echo "PF anchor before: $(/sbin/pfctl -a com.apple/yuhaiin -s rules 2>/dev/null | wc -l | tr -d ' ') rules"
	YUHAIIN_TEST_DARWIN_LIVE=1 go test -count=1 -v -run 'Darwin' ./pkg/net/netlink ./pkg/sysnet/forward
fi
go test -count=1 "${packages[@]}"
