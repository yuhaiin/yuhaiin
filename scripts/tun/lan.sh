#!/bin/sh

set -x

TABLE=${TABLE:-30002}
LAN_IPS=${LAN_IPS:-"192.168.2.145"}
TUN_NAME=${TUN_NAME:-tun0}


sudo ip route flush table ${TABLE}

sudo ip route replace default dev tun0 table ${TABLE}

for lan in ${LAN_IPS}; do
    sudo ip rule add from ${lan} lookup ${TABLE} priority 30000
done

sudo iptables -C FORWARD -o ${TUN_NAME} -j ACCEPT
if [ $? -ne 0 ]; then
    sudo iptables -I FORWARD -o ${TUN_NAME} -j ACCEPT
fi
sudo iptables -C FORWARD -i ${TUN_NAME} -j ACCEPT
if [ $? -ne 0 ]; then
    sudo iptables -I FORWARD -i ${TUN_NAME} -j ACCEPT
fi
