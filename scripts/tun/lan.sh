#!/bin/sh

set -x

TABLE=${TABLE:-30002}
LAN_IPS=${LAN_IPS:-"192.168.2.145"}
TUN_NAME=${TUN_NAME:-tun0}


sudo ip route flush table ${TABLE}

sudo ip route replace default dev ${TUN_NAME} table ${TABLE}

for lan in ${LAN_IPS}; do
    case "${lan}" in
        *:*) family=-6 ;;
        *) family=-4 ;;
    esac
    # ip rule has no replace operation. Check the exact priority/source/table
    # so restarting the TUN doesn't try to add an identical policy rule.
    if ! sudo ip "${family}" rule show | awk -v src="${lan}" -v table="${TABLE}" \
        '$1 == "30000:" && $2 == "from" && $3 == src && $4 == "lookup" && $5 == table { found = 1 } END { exit !found }'; then
        sudo ip "${family}" rule add from "${lan}" lookup "${TABLE}" priority 30000
    fi
done

sudo iptables -C FORWARD -o ${TUN_NAME} -j ACCEPT
if [ $? -ne 0 ]; then
    sudo iptables -I FORWARD -o ${TUN_NAME} -j ACCEPT
fi
sudo iptables -C FORWARD -i ${TUN_NAME} -j ACCEPT
if [ $? -ne 0 ]; then
    sudo iptables -I FORWARD -i ${TUN_NAME} -j ACCEPT
fi
