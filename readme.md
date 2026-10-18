# Yuhaiin

<p align="center">
  <img src="assets/icon-candidates/17-packet-rhythm.svg" alt="Yuhaiin icon" width="128" />
</p>

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
[![Go Reference](https://pkg.go.dev/badge/github.com/Asutorufa/yuhaiin.svg)](https://pkg.go.dev/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg) [![Go](https://github.com/Asutorufa/yuhaiin/actions/workflows/go.yml/badge.svg)](https://github.com/Asutorufa/yuhaiin/actions/workflows/go.yml)  
  
- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or [Build](https://yuhaiin.github.io/documents/guides/build/).  
- Android [yuhaiin-android](https://github.com/Asutorufa/yuhaiin-android).  
- Inbound
  - yuubinsya(experimental)
  - Reality, HTTP2, Quic, Websocket, TLS, ECH(Encrypted SNI)
  - [Hysteria 2](docs/hysteria2.md)
  - Socks5, Socks4A, HTTP
  - TUN(gso,gro support), Linux/Mac Redir, Tproxy
    - [gvisor](https://github.com/google/gvisor)
    - tun2socket(hijack tun TCP to a local TCP listener)
  - yamux  
- [WireGuard inbound](docs/wireguard-inbound.md) (userspace lightweight TCP/IP stack, no system TUN)
- Outbound
  - yuubinsya(experimental)
  - [SSH direct-tcpip](pkg/net/proxy/ssh/README.md) (TCP only, host-key pinning, password/key authentication)
  - Socks5, HTTP, TCP, [Wireguard](https://github.com/yuhaiin/yuhaiin/wiki/Wireguard)
  - Shadowsocksr, Shadowsocks, Vmess, trojan, Vless  
  - [Hysteria 2](docs/hysteria2.md) (TCP and UDP)
  - [OpenVPN](pkg/net/proxy/openvpn/README.md) (native TCP/UDP, IPv4/IPv6, AEAD, rekey)
  - [GlobalProtect SSL](pkg/net/proxy/globalprotect/README.md) (experimental SSL or optional ESP/UDP; gateway routes and DNS are informational and are not applied automatically)
  - [AmneziaWG](pkg/net/proxy/amneziawg/README.md) (WireGuard with Amnezia obfuscation)
  - [IKEv2](pkg/net/proxy/ikev2/README.md) (IKEv2/IPsec with PSK and EAP-MSCHAPv2)
  - [AnyConnect](pkg/net/proxy/anyconnect/README.md) (CSTP over TLS with optional DTLS)
  - [SSTP](pkg/net/proxy/sstp/README.md) (PPP over TLS with MS-CHAPv2)
  - [Fortinet SSL VPN](pkg/net/proxy/fortinet/README.md) (TLS or optional DTLS data channel)
  - [SoftEther native SSL-VPN](pkg/net/proxy/softether/README.md) (experimental; distinct from SSTP and OpenVPN compatibility modes)
  - Websocket, Quic, obfs-http, Reality, HTTP2, TLS, ECH(Encrypted SNI)
  - yamux  
  - reverse HTTP, reverse TCP
  - Tailscale(tsnet)
  - Cloudflare Warp/zero trust (wireguard & Masque) [tools: [usque](https://github.com/Diniboy1123/usque)]
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
- Ping(yuubinsya, Tailscale, Socks5(custom cmd), Wireguard(TODO))
- Trace Process of Connections
  - Linux: netlink + /proc
  - Windows, Darwin: syscall
- Support Proxy Chain Warp
- auto set Linux(KDE/Plasma,Gnome),Windows,MacOS Proxy  
- [Rules](https://github.com/yuhaiin/kitte)  

```shell
# make or download from releases
make yuhaiin
# or
go install github.com/Asutorufa/yuhaiin@latest
# for macos
# remove quarantine
xattr -rd com.apple.quarantine yuhaiin
# optional, sign with ad-hoc
codesign -s - yuhaiin
# or
brew tap yuhaiin/yuhaiin
brew install yuhaiin
# host: http listen address, default: 127.0.0.1:50051
# path: Store application data path, default:
#   linux ~/.config/yuhaiin/, windows %APPDATA%/yuhaiin/
yuhaiin -host="127.0.0.1:50051" -path=$HOME/.config/yuhaiin
```

![webuiv2.1-1](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/webuiv2.1-1.png)
![webuiv2.1-2](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/webuiv2.1-2.png)

<details>
<summary>Acknowledgement</summary>

- [Golang](https://golang.org)  
- [google/gVisor](https://github.com/google/gvisor)
- [プロ生ちゃん](https://kei.pronama.jp/)
- [tailscale](https://github.com/tailscale/tailscale)
- [usque](https://github.com/Diniboy1123/usque)

Reference:

- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)
- [mzz2017/shadowsocksR](https://github.com/mzz2017/shadowsocksR)  
- [shadowsocks/go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)  
- [vmess-client](https://github.com/gitsrc/vmess-client)  

</details>
