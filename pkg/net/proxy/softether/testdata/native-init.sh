#!/bin/sh
set -eu
SERVER="${SERVER:-server}"
SPW="${SPW:-seadmin}"
VPNCMD_TIMEOUT_SECONDS="${VPNCMD_TIMEOUT_SECONDS:-5}"
READY_ATTEMPTS="${READY_ATTEMPTS:-24}"
case "$VPNCMD_TIMEOUT_SECONDS" in
    ''|*[!0-9]*) echo "VPNCMD_TIMEOUT_SECONDS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$VPNCMD_TIMEOUT_SECONDS" -eq 0 ]; then echo "VPNCMD_TIMEOUT_SECONDS must be positive" >&2; exit 1; fi
case "$READY_ATTEMPTS" in
    ''|*[!0-9]*) echo "READY_ATTEMPTS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$READY_ATTEMPTS" -eq 0 ]; then echo "READY_ATTEMPTS must be positive" >&2; exit 1; fi

run_vpncmd() {
    timeout -k 2 "$VPNCMD_TIMEOUT_SECONDS" vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" "$@"
}

i=0
echo "Waiting for SoftEther server '$SERVER' (up to $READY_ATTEMPTS attempts, ${VPNCMD_TIMEOUT_SECONDS}s per command)"
until run_vpncmd /CMD ServerInfoGet >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge "$READY_ATTEMPTS" ]; then
        echo "vpncmd could not reach SoftEther server '$SERVER' after $READY_ATTEMPTS attempts" >&2
        exit 1
    fi
    if [ $((i % 5)) -eq 0 ]; then
        echo "Still waiting for SoftEther server '$SERVER' ($i/$READY_ATTEMPTS attempts)"
    fi
    sleep 2
done
echo "SoftEther server '$SERVER' is ready"
run_vpncmd <<EOF
Hub DEFAULT
UserCreate alice /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet alice /PASSWORD:s3cret
SecureNatEnable
exit
EOF
if [ -n "${LEASE_SECONDS:-}" ]; then
    case "$LEASE_SECONDS" in
        *[!0-9]*) echo "LEASE_SECONDS must be a positive integer" >&2; exit 1 ;;
    esac
    if [ "$LEASE_SECONDS" -eq 0 ]; then echo "LEASE_SECONDS must be positive" >&2; exit 1; fi
    run_vpncmd <<EOF
Hub DEFAULT
DhcpSet /START:192.168.30.10 /END:192.168.30.200 /MASK:255.255.255.0 /EXPIRE:$LEASE_SECONDS /GW:192.168.30.1 /DNS:192.168.30.1 /DNS2:none /DOMAIN:none /LOG:yes
exit
EOF
fi
run_vpncmd <<EOF | grep -q '^User Name.*alice'
Hub DEFAULT
UserGet alice
exit
EOF
echo "Official SoftEther server is ready"
