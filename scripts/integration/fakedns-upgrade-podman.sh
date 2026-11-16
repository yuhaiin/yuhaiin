#!/usr/bin/env bash
# Upgrade test for FakeDNS shared lists (schema migration 26).
#
# A Core from before the migration stores the FakeDNS whitelist and skip-check
# list inline. This script runs that Core in a Podman container, adds inline
# entries, records its DNS answers, then starts the Core from this checkout on
# the same data directory and checks that:
#   - the inline entries became the shared lists "FakeDNS whitelist" and
#     "FakeDNS skip check" (order kept, an existing list with the same name
#     left untouched) and FakeDNS references them;
#   - DNS answers keep their kind: whitelisted names get the upstream answer,
#     other names a fake IP;
#   - a restart does not convert anything twice.
# Nothing on the host changes; the container only needs outbound DNS for the
# answer checks, which are skipped without it.
#
# Usage: scripts/integration/fakedns-upgrade-podman.sh
#   FAKEDNS_BASE_REF=REF  Core to upgrade from (default: the last main commit
#                         before the migration).
# Results are PASS, FAIL or SKIP; the script exits non-zero on any FAIL and
# never reports a check it could not run as passed.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BASE_REF=${FAKEDNS_BASE_REF:-3137215683bfb325dff33b915b9b3dd60d5d197d}
BASE_IMAGE=${FAKEDNS_BASE_IMAGE:-docker.io/library/debian:trixie-slim}
IMAGE=localhost/yuhaiin-fakedns-upgrade-test:1
C=yhfd$$
WORK=$(mktemp -d "${TMPDIR:-/tmp}/yuhaiin-fakedns.XXXXXX")
PASS=0 FAIL=0 SKIP=0
FAILED=()

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); FAILED+=("$1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
skip() { SKIP=$((SKIP + 1)); printf '  \033[33mSKIP\033[0m %s (%s)\n' "$1" "$2"; }

cleanup() {
	log "cleanup"
	podman rm -f -t 2 "$C" >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

for tool in podman go git; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
podman info >/dev/null 2>&1 || { echo "podman is not usable here" >&2; exit 2; }

log "build Cores ($BASE_REF -> working tree)"
mkdir -p "$WORK/base"
git -C "$ROOT" archive "$BASE_REF" | tar -x -C "$WORK/base" || { echo "cannot read $BASE_REF" >&2; exit 2; }
TAGS="$(cd "$ROOT" && go run ./cmd/buildtags/...),stdlibjson,fts5" || { echo "cannot compute build tags" >&2; exit 1; }
build() { (cd "$1" && CGO_ENABLED=0 GOOS=linux go build -trimpath -tags="$TAGS" -o "$2" ./cmd/yuhaiin); }
build "$WORK/base" "$WORK/yuhaiin-old" && build "$ROOT" "$WORK/yuhaiin-new" || { echo "build failed" >&2; exit 1; }

log "prepare test image"
if ! podman image exists "$IMAGE"; then
	# The Core loads SQLite through purego, so it needs glibc (no Alpine).
	printf 'FROM %s\nRUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y --no-install-recommends sqlite3 dnsutils procps && rm -rf /var/lib/apt/lists/*\n' "$BASE_IMAGE" |
		podman build -q -t "$IMAGE" -f - "$WORK" >/dev/null ||
		{ echo "cannot build $IMAGE (needs network access to Debian packages once)" >&2; exit 2; }
fi
podman run -d --name "$C" -v "$WORK:/work:z" "$IMAGE" sleep infinity >/dev/null || { echo "cannot start the container" >&2; exit 2; }

ctr() { podman exec "$C" sh -c "$1"; }
sql() { ctr "sqlite3 -batch /data/state.db \"$1\""; }
start() { # start old|new
	ctr "(setsid /work/yuhaiin-$1 -path /data -host 127.0.0.1:50051 >>/data/$1.log 2>&1 &)"
	for _ in $(seq 1 30); do
		ctr "dig +short +time=1 +tries=1 @127.0.0.1 -p 5353 localhost A" >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
stop() { # stop old|new
	ctr "kill \$(pidof yuhaiin-$1) 2>/dev/null"
	for _ in $(seq 1 20); do ctr "pidof yuhaiin-$1" >/dev/null || return 0; sleep 0.5; done
	ctr "kill -9 \$(pidof yuhaiin-$1) 2>/dev/null"
}
# answer NAME: the A record the Core returns, or empty.
answer() { ctr "dig +short +time=5 +tries=1 @127.0.0.1 -p 5353 $1 A" | grep -E '^[0-9.]+$' | tail -1; }
fake() { [[ "$1" == 198.18.* ]]; }

WHITELISTED=(mask.icloud.com login.tailscale.com time.apple.com)
OTHERS=(example.com github.com)

log "start the old Core and add inline entries"
ctr "mkdir -p /data"
start old || { fail "old Core did not start" "$(ctr 'tail -5 /data/old.log')"; exit 1; }
schema=$(sql "SELECT value FROM metadata WHERE key='schema_version'")
if [ "$schema" -ge 26 ] 2>/dev/null; then
	skip "upgrade" "$BASE_REF already has schema $schema; set FAKEDNS_BASE_REF to a Core before migration 26"
	exit 0
fi
pass "old Core created schema $schema"
stop old
sql "INSERT INTO dns_fakedns_lists(kind, value) VALUES
	('whitelist', '*.tailscale.com'), ('whitelist', '*.oray.com'), ('whitelist', 'time.apple.com'),
	('skip_check', '*.yuubinsya.com'), ('skip_check', 'time.apple.com');
	UPDATE dns_settings SET fakedns_enabled = 1, fakedns_ipv4_range = '198.18.0.0/16';
	INSERT INTO route_lists_v2(id, name, owner_rule_id, list_type, source_type, updated_at, data_json)
	VALUES ('mine', 'FakeDNS whitelist', NULL, 'host', 'local', 1,
		'{\\\"id\\\":\\\"mine\\\",\\\"name\\\":\\\"FakeDNS whitelist\\\",\\\"type\\\":\\\"host\\\",\\\"source\\\":{\\\"type\\\":\\\"local\\\",\\\"local\\\":{\\\"lists\\\":[\\\"keep.example\\\"]}}}');" ||
	{ fail "seed inline entries"; exit 1; }
WANT_WHITELIST=$(sql "SELECT json_group_array(value) FROM (SELECT value FROM dns_fakedns_lists WHERE kind = 'whitelist' ORDER BY rowid)")
WANT_SKIP=$(sql "SELECT json_group_array(value) FROM (SELECT value FROM dns_fakedns_lists WHERE kind = 'skip_check' ORDER BY rowid)")

start old || { fail "old Core did not restart" "$(ctr 'tail -5 /data/old.log')"; exit 1; }
DNS=1
if [ -z "$(ctr 'dig +short +time=5 +tries=1 @8.8.8.8 example.com A' 2>/dev/null)" ]; then
	DNS=0
	skip "DNS answers" "the container has no outbound DNS"
else
	declare -A BEFORE
	for d in "${WHITELISTED[@]}" "${OTHERS[@]}"; do BEFORE[$d]=$(answer "$d"); done
	ok=1
	for d in "${WHITELISTED[@]}"; do [ -n "${BEFORE[$d]}" ] && ! fake "${BEFORE[$d]}" || ok=0; done
	for d in "${OTHERS[@]}"; do fake "${BEFORE[$d]}" || ok=0; done
	[ "$ok" = 1 ] && pass "old Core: whitelisted names get upstream answers, others fake IPs" ||
		fail "old Core baseline" "$(for d in "${!BEFORE[@]}"; do printf '%s=%s ' "$d" "${BEFORE[$d]}"; done)"
fi
stop old

log "upgrade to the new Core"
start new || { fail "new Core did not start" "$(ctr 'tail -5 /data/new.log')"; exit 1; }
[ "$(sql "SELECT value FROM metadata WHERE key='schema_version'")" -ge 26 ] && pass "schema migrated" || fail "schema not migrated"
inline=$(sql "SELECT count(*) FROM dns_fakedns_lists WHERE kind IN ('whitelist', 'skip_check')")
[ "$inline" = 0 ] && pass "no inline entries remain" || fail "inline entries remain" "$inline"
refs=$(sql "SELECT group_concat(kind || '=' || value, ' ') FROM (SELECT kind, value FROM dns_fakedns_lists ORDER BY kind)")
[ "$refs" = "skip_check_list=fakedns-skip-check whitelist_list=fakedns-whitelist" ] && pass "FakeDNS references the converted lists" || fail "FakeDNS references" "$refs"
list() { sql "SELECT name || '|' || json_extract(data_json, '\$.source.local.lists') FROM route_lists_v2 WHERE id = '$1' AND owner_rule_id IS NULL AND list_type = 'host'"; }
got=$(list fakedns-whitelist)
[ "$got" = "FakeDNS whitelist 2|$WANT_WHITELIST" ] && pass "whitelist entries moved in order (free name chosen)" || fail "whitelist list" "got '$got', want 'FakeDNS whitelist 2|$WANT_WHITELIST'"
got=$(list fakedns-skip-check)
[ "$got" = "FakeDNS skip check|$WANT_SKIP" ] && pass "skip-check entries moved in order" || fail "skip-check list" "got '$got', want 'FakeDNS skip check|$WANT_SKIP'"
got=$(list mine)
[ "$got" = 'FakeDNS whitelist|["keep.example"]' ] && pass "existing list with the same name untouched" || fail "existing list changed" "$got"

if [ "$DNS" = 1 ]; then
	for d in "${WHITELISTED[@]}"; do
		a=$(answer "$d")
		[ -n "$a" ] && ! fake "$a" && pass "$d still gets an upstream answer ($a)" || fail "$d answer" "got '$a', old Core '${BEFORE[$d]}'"
	done
	for d in "${OTHERS[@]}"; do
		a=$(answer "$d")
		fake "$a" && pass "$d still gets a fake IP ($a)" || fail "$d answer" "got '$a', old Core '${BEFORE[$d]}'"
	done
fi

log "restart the new Core"
lists=$(sql "SELECT count(*) FROM route_lists_v2")
stop new
start new || { fail "new Core did not restart" "$(ctr 'tail -5 /data/new.log')"; exit 1; }
[ "$(sql "SELECT count(*) FROM route_lists_v2")" = "$lists" ] && [ "$(sql "SELECT count(*) FROM dns_fakedns_lists")" = 2 ] &&
	pass "restart converts nothing twice" || fail "restart changed lists or references"
stop new

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
for f in "${FAILED[@]}"; do printf '  failed: %s\n' "$f"; done
[ "$FAIL" = 0 ]
