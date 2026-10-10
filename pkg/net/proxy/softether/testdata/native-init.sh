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
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF | grep -q '^User Name.*alice'
Hub DEFAULT
UserGet alice
exit
EOF
echo "Official SoftEther server is ready"
