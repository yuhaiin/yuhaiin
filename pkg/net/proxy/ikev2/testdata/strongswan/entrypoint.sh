#!/bin/sh
set -eu

ipsec start --nofork &
pid=$!
for _ in $(seq 1 50); do
	if swanctl --load-all >/tmp/swanctl-load.log 2>&1; then
		cat /tmp/swanctl-load.log
		break
	fi
	if ! kill -0 "$pid" 2>/dev/null; then
		cat /tmp/swanctl-load.log
		exit 1
	fi
	sleep 0.2
done
if ! swanctl --list-conns | grep -q roadwarrior; then
	cat /tmp/swanctl-load.log
	exit 1
fi

exec tail -f /dev/null
