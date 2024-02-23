#

```cmd
netsh interface ipv4 set address name="wintun" source=static addr=172.16.0.2 mask=255.255.255.255 gateway=172.16.0.1
netsh interface ipv4 set dnsservers name="wintun" static address=8.8.8.8 register=none validate=no
netsh interface ipv4 add route 0.0.0.0/0 "wintun" 172.16.0.1 metric=1
```
