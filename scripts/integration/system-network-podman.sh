#!/usr/bin/env bash
# Linux integration test for the System Network Manager.
#
# Everything runs inside Podman containers on internal networks: routes,
# policy rules, nftables, sysctls and TUN devices live in the containers'
# network namespaces. The host's routing table, firewall and sysctls are never
# changed. Rootless Podman is supported; the router container is started with
# --privileged only to get a writable /proc/sys/net, nftables and TUN devices
# inside its own user and network namespace.
#
#   Client(s) ──lan── Router (yuhaiin System Network) ──up1── Upstream 1
#                                                   └──up2── Upstream 2
#
# Usage: scripts/integration/system-network-podman.sh
#   SYSNET_PREBUILT=DIR uses sysnettest, netlink.test, forward.test and
#   dialer.test already built in DIR (CGO_ENABLED=0, GOOS=linux) instead of
#   building them, for hosts without Go.
# Results are PASS, FAIL or SKIP; the script exits non-zero on any FAIL and
# never reports a check it could not run as passed.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BASE_IMAGE=${SYSNET_BASE_IMAGE:-docker.io/library/alpine:3.23}
IMAGE=localhost/yuhaiin-sysnet-test:1
ID=yhsn$$
WORK=$(mktemp -d "${TMPDIR:-/tmp}/yuhaiin-sysnet.XXXXXX")
PASS=0 FAIL=0 SKIP=0
FAILED=()

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); FAILED+=("$1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
skip() { SKIP=$((SKIP + 1)); printf '  \033[33mSKIP\033[0m %s (%s)\n' "$1" "$2"; }

cleanup() {
	log "cleanup"
	for c in router client client2 up1 up2; do podman rm -f -t 2 "$ID-$c" >/dev/null 2>&1; done
	for n in lan up1 up2; do podman network rm -f "$ID-$n" >/dev/null 2>&1; done
	rm -rf "$WORK"
}
trap cleanup EXIT

PREBUILT=${SYSNET_PREBUILT:-}
TOOLS="podman jq"
[ -n "$PREBUILT" ] || TOOLS="$TOOLS go"
for tool in $TOOLS; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
if ! podman info >/dev/null 2>&1; then
	echo "podman is not usable here" >&2
	exit 2
fi
ROOTLESS=$(podman info --format '{{.Host.Security.Rootless}}')
# Readable without privileges; compared at the end to prove isolation.
host_state() { ip rule show 2>/dev/null; ip route show table 63 2>/dev/null; cat /proc/sys/net/ipv4/ip_forward; }
HOST_STATE=$(host_state)
log "podman $(podman --version | awk '{print $3}'), rootless=$ROOTLESS"

if [ -n "$PREBUILT" ]; then
	log "use prebuilt test binaries from $PREBUILT"
	for b in sysnettest netlink.test forward.test dialer.test; do
		cp "$PREBUILT/$b" "$WORK/" || { echo "missing $PREBUILT/$b" >&2; exit 1; }
	done
else
	log "build test binaries"
	(
		cd "$ROOT" &&
			CGO_ENABLED=0 go build -o "$WORK/sysnettest" ./internal/sysnettest &&
			CGO_ENABLED=0 go test -c -o "$WORK/netlink.test" ./pkg/net/netlink &&
			CGO_ENABLED=0 go test -c -o "$WORK/forward.test" ./pkg/sysnet/forward &&
			CGO_ENABLED=0 go test -c -o "$WORK/dialer.test" ./pkg/net/dialer
	) || { echo "build failed" >&2; exit 1; }
fi
cp "$ROOT/pkg/net/trie/maxminddb/testdata/countries.mmdb" "$WORK/"
mkdir -p "$WORK/router"

log "prepare test image"
if ! podman image exists "$IMAGE"; then
	printf 'FROM %s\nRUN apk add --no-cache iproute2 nftables\n' "$BASE_IMAGE" | podman build -q -t "$IMAGE" -f - "$WORK" >/dev/null ||
		{ echo "cannot build $IMAGE (needs network access to Alpine packages once)" >&2; exit 2; }
fi

log "create isolated networks"
podman network create --internal --ipv6 --subnet 10.77.20.0/24 --subnet fd77:20::/64 "$ID-lan" >/dev/null &&
	podman network create --internal --ipv6 --subnet 10.77.31.0/24 --subnet fd77:31::/64 "$ID-up1" >/dev/null &&
	podman network create --internal --subnet 10.77.32.0/24 "$ID-up2" >/dev/null ||
	{ echo "cannot create Podman networks" >&2; exit 2; }

run() { podman run -d --name "$ID-$1" "${@:2}" >/dev/null; }
run router --privileged -v "$WORK:/work:z" \
	--network "$ID-lan:ip=10.77.20.2,ip=fd77:20::2" --network "$ID-up1:ip=10.77.31.2,ip=fd77:31::2" --network "$ID-up2:ip=10.77.32.2" \
	"$IMAGE" sleep infinity || { echo "cannot start the router container" >&2; exit 2; }
run client --cap-add NET_ADMIN -v "$WORK:/work:z" --network "$ID-lan:ip=10.77.20.10,ip=fd77:20::10" "$IMAGE" sleep infinity
run client2 --cap-add NET_ADMIN -v "$WORK:/work:z" --network "$ID-lan:ip=10.77.20.11,ip=fd77:20::11" "$IMAGE" sleep infinity
run up1 --cap-add NET_ADMIN -v "$WORK:/work:z" --network "$ID-up1:ip=10.77.31.10,ip=fd77:31::10" "$IMAGE" sleep infinity
run up2 --cap-add NET_ADMIN -v "$WORK:/work:z" --network "$ID-up2:ip=10.77.32.10" "$IMAGE" sleep infinity

ex() { podman exec "$ID-$1" "${@:2}"; }
R() { ex router "$@"; }

# Upstreams answer on an "internet" address 198.51.100.1 (and 2001:db8:100::1).
for u in up1 up2; do
	ex "$u" ip addr add 198.51.100.1/32 dev lo
	podman exec -d "$ID-$u" /work/sysnettest serve 0.0.0.0:8080 "$u"
done
ex up1 ip -6 addr add 2001:db8:100::1/128 dev lo
podman exec -d "$ID-up1" /work/sysnettest serve "[::]:8081" up1v6
for c in client client2; do
	ex "$c" ip route replace default via 10.77.20.2
	ex "$c" ip -6 route replace default via fd77:20::2 2>/dev/null
done

# Simulated interfaces: two Yuhaiin TUNs and an "external" tunnel (e.g. wg0).
tun() { # tun NAME IPV4 [IPV6]
	R ip tuntap add mode tun name "$1" && R ip addr add "$2" dev "$1" &&
		{ [ -z "${3:-}" ] || R ip -6 addr add "$3" dev "$1" nodad; } && R ip link set "$1" up
}
tun tuna 172.19.0.1/30 fdfe:a::1/64
tun tunb 172.20.0.1/30 fdfe:b::1/64
tun extwg 10.8.0.2/32
R sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv6/conf/all/forwarding'
INITIAL_RULES=$(R ip rule show | sort)

log "kernel-level Go tests inside the router namespace"
if out=$(R env YUHAIIN_TEST_TUN_ROUTES=1 YUHAIIN_TEST_ISOLATED_CONTAINER=1 /work/netlink.test -test.run 'TestLinuxSystemRoutesInNamespace' -test.v 2>&1) && grep -q -- '--- PASS' <<<"$out"; then
	pass "route manager: add/delete, ownership, gateway, stale cleanup, external route preserved, interface removal"
else
	fail "route manager kernel test" "$(tail -5 <<<"$out")"
fi
if out=$(R env YUHAIIN_TEST_TUN_ROUTES=1 YUHAIIN_TEST_ISOLATED_CONTAINER=1 /work/netlink.test -test.run 'TestLinuxPolicyRule' -test.v 2>&1) && grep -q -- '--- PASS' <<<"$out" && ! grep -q -- '--- FAIL' <<<"$out"; then
	pass "TUN policy rule: mark exclusion, migration of an unmarked rule, foreign rule preserved"
else
	fail "TUN policy rule kernel test" "$(tail -5 <<<"$out")"
fi
# Outbound socket routing: each test builds two NICs and a TUN table in a
# fresh namespace nested in the router, and checks which interface really
# transmitted marked and unmarked UDP/TCP.
if out=$(R env YUHAIIN_TEST_TUN_ROUTES=1 /work/dialer.test -test.run 'TestRouting' -test.v 2>&1) && grep -q -- '--- PASS' <<<"$out" && ! grep -q -- '--- FAIL' <<<"$out"; then
	pass "outbound sockets: marked UDP/TCP per destination on two NICs, never the TUN; SO_MARK fallback; explicit interface"
else
	fail "outbound socket routing kernel test" "$(grep -E -- '--- FAIL|_test.go' <<<"$out" | tail -5)"
fi
if out=$(R env YUHAIIN_TEST_ISOLATED_CONTAINER=1 /work/forward.test -test.run 'TestKernelForwardingLifecycle' -test.v 2>&1) && grep -q -- '--- PASS' <<<"$out"; then
	pass "forwarding manager: nftables table, foreign table preserved, policy rules, sysctl restore"
else
	fail "forwarding manager kernel test" "$(tail -5 <<<"$out")"
fi

log "start the System Network harness"
podman exec -d "$ID-router" /work/sysnettest run /work/router
VERSION=0
apply() { # apply JSON-CONFIG: write the harness config and wait until applied
	VERSION=$((VERSION + 1))
	jq -n --argjson v "$VERSION" --argjson c "$1" '$c + {version: $v, geoip: "/work/countries.mmdb"}' >"$WORK/router/config.json.tmp"
	mv "$WORK/router/config.json.tmp" "$WORK/router/config.json"
	for _ in $(seq 100); do
		[ "$(jq -r '.version' "$WORK/router/status.json" 2>/dev/null)" = "$VERSION" ] && return 0
		sleep 0.1
	done
	echo "harness did not apply version $VERSION: $(cat "$WORK/router/status.json" 2>/dev/null)" >&2
	return 1
}
status() { jq -r "$1" "$WORK/router/status.json"; }
wait_status() { # wait_status JQ EXPECTED
	for _ in $(seq 100); do
		[ "$(status "$1")" = "$2" ] && return 0
		sleep 0.1
	done
	return 1
}
dev_for() { R ip "$@" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1; }
expect_dev() { # expect_dev NAME DEV ip-route-get-args...
	local name=$1 want=$2 got
	shift 2
	got=$(dev_for "$@")
	if [ "$got" = "$want" ]; then pass "$name"; else fail "$name" "ip $* -> dev '$got', want '$want'"; fi
}
expect_not_dev() { # an unreachable destination (no route at all) also counts
	local name=$1 unwanted=$2 got
	shift 2
	got=$(dev_for "$@")
	if [ "$got" != "$unwanted" ]; then pass "$name"; else fail "$name" "ip $* -> dev '$got'"; fi
}
rule() { # rule ID PRIORITY MATCH TARGET
	jq -n --arg id "$1" --argjson p "$2" --argjson m "$3" --argjson t "$4" '{id: $id, name: $id, enabled: true, priority: $p, match: $m, target: $t}'
}
TUNS='[{"id":"a","interface":"tuna","required":["198.18.0.0/15"]},{"id":"b","interface":"tunb"}]'
tunA='{"type":"tun_inbound","inboundId":"a"}'
tunB='{"type":"tun_inbound","inboundId":"b"}'

log "A. multiple interfaces, priority and conflicts"
R ip route add 10.70.0.0/16 dev extwg table 63
RULES=$(jq -s . <(rule a-net 100 '{"mode":"custom","includeCidrs":["10.50.0.0/16"]}' "$tunA") \
	<(rule b-sub 200 '{"mode":"custom","includeCidrs":["10.50.1.0/24","10.51.0.0/16"]}' "$tunB") \
	<(rule wg 300 '{"mode":"custom","includeCidrs":["10.60.0.0/16"]}' '{"type":"interface","interfaceName":"extwg"}') \
	<(rule upstream 400 '{"mode":"custom","includeCidrs":["203.0.113.0/24"]}' '{"type":"interface","interfaceName":"eth1","gateway":"10.77.31.10"}') \
	<(rule taken 500 '{"mode":"custom","includeCidrs":["10.70.0.0/16"]}' "$tunA"))
apply "$(jq -n --argjson t "$TUNS" --argjson r "$RULES" '{tuns: $t, config: {routes: $r, forwarding: {ipv4: false, ipv6: false, rules: []}}}')" || fail "apply multi-interface config"
expect_dev "rule a-net routes 10.50.0.0/16 to TUN A" tuna route get 10.50.9.9
expect_dev "priority: 10.50.1.0/24 stays with the higher-priority TUN A" tuna route get 10.50.1.5
expect_dev "rule b-sub routes 10.51.0.0/16 to TUN B" tunb route get 10.51.0.1
expect_dev "external interface target (extwg)" extwg route get 10.60.0.1
expect_dev "physical interface with gateway" eth1 route get 203.0.113.5
[ "$(R ip route get 203.0.113.5 | grep -o 'via [0-9.]*')" = "via 10.77.31.10" ] && pass "gateway 10.77.31.10 used" || fail "gateway used"
expect_dev "required FakeIP route goes to TUN A" tuna route get 198.18.0.1
[ "$(status '.status.rules[] | select(.id=="b-sub") | .overriddenBy[0]')" = "a-net" ] && pass "overlap reported (b-sub overridden by a-net)" || fail "overlap status"
[ "$(status '.status.rules[] | select(.id=="taken") | .state')" = "conflict" ] && pass "same-prefix route of another program reported as conflict" || fail "conflict status" "$(status '.status.rules[] | select(.id=="taken")')"
R ip route show table 63 | grep -q '10.70.0.0/16 dev extwg' && pass "foreign route in table 63 kept" || fail "foreign route kept"
R ip route del 10.70.0.0/16 dev extwg table 63

log "A. interface disappearance and reappearance"
R ip link del extwg
if wait_status '.status.rules[] | select(.id=="wg") | .state' unavailable; then pass "rule becomes unavailable when extwg disappears"; else fail "unavailable after interface removal" "$(status '.status.rules[] | select(.id=="wg")')"; fi
[ "$(R ip route show table 63 | grep -c '10.60.0.0/16')" = 0 ] && pass "no route left for the missing interface" || fail "stale route for missing interface"
[ "$(status '.interfaces.missing[0].ruleIds[0]')" = "wg" ] && pass "missing interface lists its rule" || fail "missing target listing"
R ip tuntap add mode tun name extwg && R ip addr add 10.8.0.2/32 dev extwg && R ip link set extwg up
if wait_status '.status.rules[] | select(.id=="wg") | .state' active; then pass "rule active again after extwg returns"; else fail "resync after interface returns"; fi
expect_dev "route restored on the new extwg (new index)" extwg route get 10.60.0.1

log "A. TUN stop and restart"
apply "$(jq -n --argjson r "$RULES" '{tuns: [{"id":"b","interface":"tunb"}], config: {routes: $r, forwarding: {ipv4: false, ipv6: false, rules: []}}}')"
[ "$(status '.status.rules[] | select(.id=="a-net") | .state')" = "unavailable" ] && pass "stopped TUN A: its rule is unavailable" || fail "TUN stop status"
expect_dev "TUN A stopped: 10.50.1.0/24 falls through to TUN B" tunb route get 10.50.1.5
apply "$(jq -n --argjson t "$TUNS" --argjson r "$RULES" '{tuns: $t, config: {routes: $r, forwarding: {ipv4: false, ipv6: false, rules: []}}}')"
expect_dev "TUN A restarted: routes resynchronized" tuna route get 10.50.1.5

log "B. Global / Non-private / Custom / GeoIP"
mode() { # mode MATCH
	apply "$(jq -n --argjson t "$TUNS" --argjson r "$(jq -s . <(rule m 100 "$1" "$tunA"))" '{tuns: $t, config: {routes: $r, forwarding: {ipv4: false, ipv6: false, rules: []}}}')"
}
mode '{"mode":"global"}'
expect_dev "Global IPv4 1.1.1.1 -> TUN A" tuna route get 1.1.1.1
expect_dev "Global IPv6 2606:4700::1 -> TUN A" tuna -6 route get 2606:4700::1
expect_not_dev "Global keeps link-local 169.254.1.1 off the TUN" tuna route get 169.254.1.1
[ "$(R ip route show table 63 | grep -c '^default')" = 0 ] && pass "Global uses /1 routes, no default route replaced" || fail "default route in table 63"
mode '{"mode":"non_private"}'
expect_dev "Non-private 8.8.8.8 -> TUN A" tuna route get 8.8.8.8
expect_dev "Non-private keeps LAN 10.77.20.10 on eth0" eth0 route get 10.77.20.10
expect_not_dev "Non-private keeps Tailscale 100.100.1.1 off the TUN" tuna route get 100.100.1.1
expect_not_dev "Non-private keeps IPv6 ULA fd00::1 off the TUN" tuna -6 route get fd00::1
mode '{"mode":"non_private","includeCidrs":["10.88.0.0/16"],"bypassCidrs":["8.8.8.0/24"]}'
expect_dev "private CIDR include 10.88.0.1 -> TUN A" tuna route get 10.88.0.1
expect_not_dev "bypass CIDR 8.8.8.8 stays off the TUN" tuna route get 8.8.8.8
expect_dev "outside the bypass 1.1.1.1 -> TUN A" tuna route get 1.1.1.1
mode '{"mode":"custom","includeCidrs":["8.8.8.8/32","2001:4860:4860::8888"]}'
expect_dev "Custom CIDR 8.8.8.8 -> TUN A" tuna route get 8.8.8.8
expect_not_dev "Custom: 1.1.1.1 not selected" tuna route get 1.1.1.1
mode '{"mode":"custom","geoipCountries":["CN","JP"]}'
expect_dev "GeoIP CN 1.0.1.1 -> TUN A" tuna route get 1.0.1.1
expect_dev "GeoIP JP 2001:4860::1 -> TUN A" tuna -6 route get 2001:4860::1
expect_not_dev "GeoIP: 2.0.0.1 not in CN/JP" tuna route get 2.0.0.1
mode '{"mode":"custom","geoipCountries":["CN"],"geoipInvert":true}'
expect_not_dev "GeoIP reverse: CN 1.0.0.1 stays off the TUN" tuna route get 1.0.0.1
expect_dev "GeoIP reverse: 2.0.0.1 -> TUN A" tuna route get 2.0.0.1
expect_not_dev "GeoIP reverse keeps private 10.77.20.10 off the TUN" tuna route get 10.77.20.10

log "C. forwarding / side router"
fwd() { # fwd RULES-JSON IPV6
	apply "$(jq -n --argjson t "$TUNS" --argjson f "$1" --argjson v6 "${2:-false}" '{tuns: $t, config: {routes: [], forwarding: {ipv4: true, ipv6: $v6, rules: $f}}}')"
}
probe() { ex "$1" /work/sysnettest probe "$2" 2>/dev/null; }
up1='{"type":"interface","interfaceName":"eth1","gateway":"10.77.31.10","gatewayV6":"fd77:31::10"}'
up2='{"type":"interface","interfaceName":"eth2","gateway":"10.77.32.10"}'
frule() { # frule ID SOURCES EGRESS MASQ [DESTS]
	jq -n --arg id "$1" --argjson s "$2" --argjson e "$3" --argjson m "$4" --argjson d "${5:-[]}" \
		'{id: $id, name: $id, enabled: true, ingressInterface: "eth0", sourceCidrs: $s, destinationCidrs: $d, egress: $e, masquerade: $m}'
}
fwd "$(jq -s . <(frule lan '["10.77.20.10/32","fd77:20::10/128"]' "$up1" false '["198.51.100.0/24","2001:db8:100::/48"]'))" true
[ "$(R cat /proc/sys/net/ipv4/ip_forward)" = 1 ] && pass "IPv4 forwarding enabled" || fail "IPv4 forwarding enabled"
if probe client 198.51.100.1:8080 >/dev/null; then fail "without NAT the upstream needs a return route" "connection unexpectedly succeeded"; else pass "without NAT and without a return route, replies are lost"; fi
ex up1 ip route add 10.77.20.0/24 via 10.77.31.2
got=$(probe client 198.51.100.1:8080)
[ "$got" = "up1 10.77.20.10" ] && pass "forwarded via eth1 with a return route (source kept: $got)" || fail "forwarding with return route" "got '$got'"
ex up1 ip route del 10.77.20.0/24 via 10.77.31.2
fwd "$(jq -s . <(frule lan '["10.77.20.10/32","fd77:20::10/128"]' "$up1" true '["198.51.100.0/24","2001:db8:100::/48"]'))" true
got=$(probe client 198.51.100.1:8080)
[ "$got" = "up1 10.77.31.2" ] && pass "masquerade: reply without a return route (source rewritten: $got)" || fail "masquerade" "got '$got'"
got=$(probe client2 198.51.100.1:8080)
[ -z "$got" ] && pass "unlisted LAN source 10.77.20.11 is not forwarded" || fail "source restriction" "client2 got '$got'"
got=$(probe client "[2001:db8:100::1]:8081")
[ "$got" = "up1v6 fd77:31::2" ] && pass "IPv6 forwarding with masquerade ($got)" || fail "IPv6 forwarding" "got '$got'"
fwd "$(jq -s . <(frule lan '["10.77.20.10/32"]' "$up2" true '["198.51.100.0/24"]'))"
got=$(probe client 198.51.100.1:8080)
[ "$got" = "up2 10.77.32.2" ] && pass "egress follows the selected interface (eth2)" || fail "egress selection" "got '$got'"
fwd "$(jq -s . <(frule lan '["10.77.20.10/32"]' "$tunA" false))"
expect_dev "forwarding to a Yuhaiin TUN: LAN traffic routed to TUN A" tuna route get 8.8.8.8 from 10.77.20.10 iif eth0
expect_not_dev "other LAN sources are not sent to TUN A" tuna route get 8.8.8.8 from 10.77.20.11 iif eth0

fwd "$(jq -n '[{id: "all", name: "all", enabled: true, ingressInterface: "eth0", sourceCidrs: [], egress: {type: "routes"}}]')"
R ip route add 198.51.100.0/24 via 10.77.31.10
ex up1 ip route add 10.77.20.0/24 via 10.77.31.2
got1=$(probe client 198.51.100.1:8080) got2=$(probe client2 198.51.100.1:8080)
[ "$got1" = "up1 10.77.20.10" ] && [ "$got2" = "up1 10.77.20.11" ] && pass "routes egress without sources: every LAN device follows the routing table" || fail "routes egress" "got '$got1' / '$got2'"
R ip route del 198.51.100.0/24 via 10.77.31.10
ex up1 ip route del 10.77.20.0/24 via 10.77.31.2

log "D. TProxy interception"
if R sh -c 'nft add table inet yhsn_probe && nft add chain inet yhsn_probe p "{ type filter hook prerouting priority mangle; }" && nft add rule inet yhsn_probe p meta l4proto tcp tproxy ip to :1 && nft delete table inet yhsn_probe' >/dev/null 2>&1; then
	apply "$(jq -n --argjson t "$TUNS" --argjson f "$(jq -s . <(frule tp '["10.77.20.10/32"]' '{"type":"tproxy","inboundId":"tp"}' false))" \
		'{tuns: $t, tproxy: [{"id":"tp","name":"tp","listen":"0.0.0.0:7893"}], config: {routes: [], forwarding: {ipv4: true, ipv6: false, rules: $f}}}')"
	got=$(probe client 198.51.100.1:8080)
	if [[ "$got" == "tproxy 198.51.100.1:8080 10.77.20.10:"* ]]; then
		pass "TProxy: connection intercepted with its original destination ($got)"
	else
		fail "TProxy interception" "got '$got'"
		R sh -c 'nft list table inet yuhaiin_sysnet; ip rule; ip route show table 6299; ss -ltn' >&2
	fi
	got=$(probe client2 198.51.100.1:8080)
	[[ "$got" != tproxy* ]] && pass "TProxy only for the selected source" || fail "TProxy source restriction" "client2 got '$got'"
else
	skip "TProxy interception" "kernel lacks nft TPROXY support (nft_tproxy)"
fi

log "cleanup on stop"
R sh -c 'kill -TERM $(pidof sysnettest)'
wait_status '.version' -1 || fail "harness did not stop cleanly"
[ -z "$(R ip route show table 63)" ] && pass "table 63 empty after stop" || fail "routes left in table 63" "$(R ip route show table 63)"
[ "$(R ip rule show | sort)" = "$INITIAL_RULES" ] && pass "policy rules restored" || fail "policy rules left" "$(R ip rule show)"
tables=$(R /work/sysnettest nft-tables)
[[ " $tables " != *" yuhaiin_sysnet "* ]] && pass "Yuhaiin nftables table removed" || fail "nftables table left" "$tables"
[ "$(R cat /proc/sys/net/ipv4/ip_forward)" = 0 ] && [ "$(R cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] && pass "forwarding sysctls restored" || fail "sysctls not restored"
[ "$(host_state)" = "$HOST_STATE" ] && pass "host routing rules, table 63 and ip_forward unchanged" || fail "host network state changed"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
for f in "${FAILED[@]}"; do printf '  failed: %s\n' "$f"; done
[ "$FAIL" = 0 ]
