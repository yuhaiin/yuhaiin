#

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
[![Go Reference](https://pkg.go.dev/badge/github.com/Asutorufa/yuhaiin.svg)](https://pkg.go.dev/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg)  
  
- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or [Build](https://github.com/Asutorufa/yuhaiin/wiki/build).  
- Supported Protocol  
  - Shadowsocksr  
  - Shadowsocks(plugin: Obfs-Http, v2ray-plugin[websocket, quic])  
  - Vmess, trojan
  - Socks5, HTTP, Linux/Mac Redir
  - TODO: TUN
- support DNS:
  - DNS, EDNS
  - DNS over UDP
  - DNS over HTTPS(3)
  - DNS over Quic
  - DNS over TLS
  - DNS over TCP
- Auto Set System Proxy.  
- a Simple web page can to configure.
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)  
- icon from プロ生ちゃん.アイコンがプロ生ちゃんから、ご注意ください。  
- Others Please Check [Wiki](https://github.com/Asutorufa/yuhaiin/wiki).  

<!-- 
![v0.2.12-beta_linux](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/v0.2.12-beta_linux.png)  
![v0.2.12-beta_windows](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/v0.2.12-beta_windows.png)   -->

```shell
# host: grpc and http listen address, default: 127.0.0.1:50051
# path: Store application data path, default:
#   linux ~/.config/yuhaiin/, windows %APPDATA%/yuhaiin/
yuhaiin -host="127.0.0.1:50051" -path=$HOME/.config/yuhaiin/config.json
```

![web_page](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/assets/img/web_page.png)

a simple cli tools supported

```shell
// list all connections
yh conn ls
// close connections by id
yh conn close <id1> <id2> ...
// close all connections
yh conn close all

// list group
yh ls
// list all nodes
yh ls all
// list all nodes in a group
yh ls <group-number>
// list info of a node
yh ls <group-number> <node-number>
yh ls <node-hash>
// list info of now use node
yh ls now

// check config
yh config
// set config
yh config set <xxx>.<xxx>.<xxx>=<xxx>
// for example set remote dns host
// yh config set dns.remote.host=1.1.1.1

// see stream data
yh data

// get a node latency
yh lat <group-number> <node-number>
yh lat <node-hash>
// get all node latency of a group
yh lat all <group-number>

// use a node
yh use <group-number> <node-number>
yh use <node-hash>
// set a node config
yh set <group-number> <node-number> <xxx>.<xxx>.<xxx>=<xxx>
yh set <node-hash> <xxx>.<xxx>.<xxx>=<xxx>

// list all subscriptions
yh sub ls
// add a subscription
yh sub add <name> <sub-link>
// update all subscriptions
yh sub update
```

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

</details>
