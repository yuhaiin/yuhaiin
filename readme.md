#

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
[![Go Reference](https://pkg.go.dev/badge/github.com/Asutorufa/yuhaiin.svg)](https://pkg.go.dev/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg)  
  
- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or [Build](https://github.com/Asutorufa/yuhaiin/wiki/build).  
- Android [yuhaiin-android](https://github.com/Asutorufa/yuhaiin-android).  
- Supported Protocol  
  - Shadowsocksr, Shadowsocks, Vmess, trojan  
  - Websocket, Quic, obfs-http  
  - Socks5, HTTP, Linux/Mac Redir
  - TUN([gvisor](https://github.com/google/gvisor))
- support DNS:
  - DNS, EDNS
  - FakeDNS
  - DNS Server
  - DNS over UDP
  - DNS over HTTPS(3)
  - DNS over Quic
  - DNS over TLS
  - DNS over TCP
- Auto Set System Proxy.  
- a Simple web page can to configure.
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)  
- [config & protocols Docs](https://github.com/Asutorufa/yuhaiin/tree/main/docs).  
- icon from プロ生ちゃん.アイコンがプロ生ちゃんから、ご注意ください。  

```shell
# host: grpc and http listen address, default: 127.0.0.1:50051
# path: Store application data path, default:
#   linux ~/.config/yuhaiin/, windows %APPDATA%/yuhaiin/
yuhaiin -host="127.0.0.1:50051" -path=$HOME/.config/yuhaiin
```

![web_page](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/web_page.png)

<details>
<summary>Acknowledgement</summary>

- [Golang](https://golang.org)  
- [therecipe/qt](https://github.com/therecipe/qt)  
- [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)(now change to json)  
- [breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
- [akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  
- [mzz2017/shadowsocksR](https://github.com/mzz2017/shadowsocksR)  
- [Dreamacro/clash](https://github.com/Dreamacro/clash)  
- [shadowsocks/go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)  
- [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin)  
- [vmess-client](https://github.com/gitsrc/vmess-client)  
- [v2ray](https://v2ray.com/)  
- [gRPC](https://grpc.io/)  
- [protobuf](https://github.com/golang/protobuf)  
- [プロ生ちゃん](https://kei.pronama.jp/)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)
- [google/gvisor](https://github.com/google/gvisor)

</details>
