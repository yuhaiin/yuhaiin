#

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
[![Go Reference](https://pkg.go.dev/badge/github.com/Asutorufa/yuhaiin.svg)](https://pkg.go.dev/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg) [![Go](https://github.com/Asutorufa/yuhaiin/actions/workflows/go.yml/badge.svg)](https://github.com/Asutorufa/yuhaiin/actions/workflows/go.yml)  
  
- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or [Build](https://github.com/Asutorufa/yuhaiin/wiki/build).  
- Android [yuhaiin-android](https://github.com/Asutorufa/yuhaiin-android).  
- Inbound
  - yuubinsya(experimental)
  - Socks5, HTTP, Linux/Mac Redir
  - TUN
    - [gvisor(Symmetric NAT)](https://github.com/google/gvisor)
    - tun2socket(hijack tun TCP to a local TCP listener)
- Outbound
  - yuubinsya(experimental)
  - Socks5, HTTP, TCP
  - Shadowsocksr, Shadowsocks, Vmess, trojan  
  - Websocket, Quic, obfs-http  
- support DNS:
  - DNS, EDNS
  - FakeDNS
  - DNS Server
  - DNS over UDP
  - DNS over HTTPS(3)
  - DNS over Quic
  - DNS over TLS
  - DNS over TCP
- Full cone NAT.
- auto set Linux(KDE/Plasma,gnome),Windows Proxy  
- [bypass rule](https://github.com/Asutorufa/yuhaiin/tree/ACL)  
- [config & protocols docs](https://github.com/Asutorufa/yuhaiin/tree/main/docs)  
- icon from プロ生ちゃん. アイコンがプロ生ちゃんから、ご注意ください。  

```shell
# host: grpc and http listen address, default: 127.0.0.1:50051
# path: Store application data path, default:
#   linux ~/.config/yuhaiin/, windows %APPDATA%/yuhaiin/
yuhaiin -host="127.0.0.1:50051" -path=$HOME/.config/yuhaiin
```

![web_page2](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/web_page2.png)

<details>
<summary>Acknowledgement</summary>

- [Golang](https://golang.org)  
- [google/gVisor](https://github.com/google/gvisor)
- [gRPC](https://grpc.io/)  
- [protobuf-go](https://github.com/protocolbuffers/protobuf-go)  
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)
- [プロ生ちゃん](https://kei.pronama.jp/)
- [mzz2017/shadowsocksR](https://github.com/mzz2017/shadowsocksR)  
- [shadowsocks/go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)  

History:

- [therecipe/qt](https://github.com/therecipe/qt)  
- [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)  
- [breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
- [akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  
- [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin)  
- [vmess-client](https://github.com/gitsrc/vmess-client)  

</details>
