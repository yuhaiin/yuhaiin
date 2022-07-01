#

add a tun device tun0

```shell
ip tuntap add mode tun dev tun0 
```

set a gateway for tun device

```shell
ip addr add 172.19.0.1/15 dev tun0
```

set tun device up

```shell
ip link set dev tun0 up
```

add tun device config

```json
"tun": {
    "name": "",
    "tun": {
      "name": "tun://tun0",
      "mtu": 1500,
      "gateway": "172.19.0.1",
      "dns_hijacking": true
    }
  }
```

set net_interface to origin net device

```json
"net_interface": "wlo1"
```

recommend to enabled fakedns

```json
"fakedns": true
```

delete default route and add tun device route

```shell
ip route del default
ip route add default via 172.19.0.1 dev tun0 metric 1
ip route add default via 192.168.100.1 dev wlo1 metric 10
```
