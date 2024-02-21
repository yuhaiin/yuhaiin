#

set address for tun `utun10`

```shell
sudo ifconfig utun10 172.16.0.1/32 172.16.0.1 up
```

add route for proxy address

```shell
sudo route add -net 10.0.2.1/24 172.16.0.1

sudo route add -net 1.0.0.0/8 172.16.0.1
sudo route add -net 2.0.0.0/7 172.16.0.1
sudo route add -net 4.0.0.0/6 172.16.0.1
sudo route add -net 8.0.0.0/5 172.16.0.1
sudo route add -net 16.0.0.0/4 172.16.0.1
sudo route add -net 32.0.0.0/3 172.16.0.1
sudo route add -net 64.0.0.0/2 172.16.0.1
sudo route add -net 128.0.0.0/1 172.16.0.1
sudo route add -net 198.18.0.0/15 172.16.0.1
```
