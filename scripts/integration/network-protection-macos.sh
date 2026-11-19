#!/bin/sh
# Network Protection (kill switch) checks on macOS.
#
#   scripts/integration/network-protection-macos.sh          unit tests, no root
#   scripts/integration/network-protection-macos.sh --live   real PF tests (sudo)
#
# --live changes the real packet filter, /etc/pf.conf (restored byte for
# byte afterwards), creates utun devices, routes for documentation
# prefixes, the _yuhaiin group and a LaunchDaemon. Run it only on a
# disposable machine (CI runner or VM) that does not use Yuhaiin.
set -eu
cd "$(dirname "$0")/../.."

go test ./pkg/sysnet/protection/... ./pkg/sysnet/forward/...
[ "${1:-}" = "--live" ] || exit 0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Two builds of different versions for the service upgrade test; the test
# binary is the same build as "yuhaiin".
v=github.com/Asutorufa/yuhaiin/internal/version
go build -ldflags "-X $v.Version=pf-test-old -X $v.GitCommit=old" -o "$tmp/yuhaiin-old" ./cmd/yuhaiin
go build -ldflags "-X $v.Version=pf-test-new -X $v.GitCommit=new" -o "$tmp/yuhaiin" ./cmd/yuhaiin
go test -c -ldflags "-X $v.Version=pf-test-new -X $v.GitCommit=new" -o "$tmp/helper.test" ./pkg/sysnet/protection/helper
go test -c -o "$tmp/forward.test" ./pkg/sysnet/forward

echo "pf.conf before: $(shasum -a 256 /etc/pf.conf)"
sudo YUHAIIN_TEST_PF=1 YUHAIIN_TEST_BINARY="$tmp/yuhaiin" YUHAIIN_TEST_BINARY_OLD="$tmp/yuhaiin-old" "$tmp/helper.test" -test.run '^TestPF(KillSwitch|CommandLine|ServiceUpgrade)$' -test.v -test.timeout 10m
sudo YUHAIIN_TEST_DARWIN_LIVE=1 "$tmp/forward.test" -test.run '^TestDarwinLivePF$' -test.v
echo "pf.conf after:  $(shasum -a 256 /etc/pf.conf)"
/sbin/pfctl -s info 2>/dev/null | head -1 || sudo /sbin/pfctl -s info | head -1
