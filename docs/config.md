# config

```json
{
  "ipv6": false, // enabled ipv6
  "net_interface": "", // unix network interface name, eg: wlo0, eno1
  "system_proxy": { // auto apply proxy setting to system, Windows only support http
    "http": true, 
    "socks5": false
  },
  "bypass": {
    "tcp": "bypass", // tcp proxy mode, support: bypass, direct, proxy, block
    "udp": "bypass", // udp proxy mode, same as tcp
    "bypass_file": "/mnt/share/Work/code/shell/ACL/yuhaiin/yuhaiin_my.conf",
    // bypass file location
    // support format
    // example.com block
    // 10.0.2.1/24 direct
    // 127.0.0.1 proxy
    "custom_rule": { // custom rule, same as bypass file, for temporary use
      "120.53.53.53": "direct",
      "223.5.5.5": "direct",
      "dns.google": "proxy",
      "dns.nextdns.io": "proxy",
      "exmaple.block.domain.com": "block"
    }
  },
  "dns": {
    "server": "127.0.0.1:5353", // dns server listener(tcp&udp), empty to disabled
    "fakedns": false, // fakedns switch
    "fakedns_ip_range": "172.19.0.1/24", // fakedns ip pool cidr
    "resolve_remote_domain": false, // if enabled,
    // the proxy domain will use remote dns resolve domain to ip instead of
    // pass domain to proxy server
    "remote": { // remote dns
      "host": "https://dns.nextdns.io/xxxx",
      // host eg:
      // https://dns.nextdns.io
      // dns.nextdns.io
      // 8.8.8.8
      // 8.8.8.8:53
      "type": "doh", // support type: udp,tcp,doh,dot,doq,doh3
      "subnet": "223.5.5.5/24", // edns subnet
      "tls_servername": "" // tls server name, set domain in tls(doh,dot,doq,doh3)
    },
    "local": {
      "host": "dns.google",
      "type": "doh",
      "subnet": "223.5.5.5/24",
      "tls_servername": ""
    },
    "bootstrap": {
      "host": "223.5.5.5",
      "type": "udp",
      "subnet": "223.5.5.5/24",
      "tls_servername": "doh.pub"
    },
    "hosts": {
    // eg:
    // "example.com": "127.0.0.1"
    // "127.0.0.1": "192.168.2.1"
    // "google.cn": "google.com"
    // "8.8.8.8": "dns.google"
      "10.2.2.49": "192.168.11.201",
      "example.com": "example.com"
    }
  },
  "server": { // local listener
    "servers": {
      "http": { // http proxy server
        "name": "http",
        "enabled": true,
        "http": {
          "host": "0.0.0.0:8188", // listener host
          "username": "",
          "password": ""
        }
      },
      "redir": { // linux redir
        "name": "redir",
        "enabled": false,
        "redir": {
          "host": "127.0.0.1:8088"
        }
      },
      "socks5": { // socks5 proxy server
        "name": "socks5",
        "enabled": true,
        "socks5": {
          "host": "0.0.0.0:1080", // listener host
          "username": "",
          "password": ""
        }
      },
      "tun": { // tun network
        "name": "tun",
        "enabled": false,
        "tun": {
          "name": "tun://tun0",// tun name or fd, eg: tun://tun0, fd://89
          "mtu": 1500,
          "gateway": "172.19.0.1", // tun gateway
          "dns_hijacking": true, // dns_hijacking, will hijacking request for port 53
          "skip_multicast": true,
          "driver": "fdbased" // tun gvisor driver, support: fdbased, channel
        }
      }
    }
  },
  "logcat": {
    "level": "debug", // log level, support: verbose, debug, info, warning, error, fatal
    "save": true // save log to file switch
  }
}
```
