#!/bin/sh
set -eu
SERVER="${SERVER:-server}"
SPW="${SPW:-seadmin}"
i=0
until vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" /CMD ServerInfoGet >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge 60 ]; then echo "vpncmd timeout" >&2; exit 1; fi
    sleep 2
done
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF
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
    vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF
Hub DEFAULT
DhcpSet /START:192.168.30.10 /END:192.168.30.200 /MASK:255.255.255.0 /EXPIRE:$LEASE_SECONDS /GW:192.168.30.1 /DNS:192.168.30.1 /DNS2:none /DOMAIN:none /LOG:yes
exit
EOF
fi
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF | grep -q '^User Name.*alice'
Hub DEFAULT
UserGet alice
exit
EOF
echo "Official SoftEther server is ready"
