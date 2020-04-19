```shell
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg)  
How to use:

- download the [releases](https://github.com/Asutorufa/yuhaiin/releases) binary or build.

- Build

    ```shell script
    git clone https://github.com/Asutorufa/yuhaiin.git
    cd yuhaiin
    export GO111MODULE=on
    go get -v github.com/therecipe/qt
    go install -v -tags=no_env github.com/therecipe/qt/cmd/...
    go mod vendor
    git clone https://github.com/therecipe/env_linux_amd64_513.git vendor/github.com/therecipe/env_linux_amd64_513
    $(go env GOPATH)/bin/qtsetup
    qtdeploy
    ```
  
- Support Protocol
    - Shadowsocksr <- need to install a external client(like shadowsocksr-libev)
    - Shadowsocks
        - Support Plugin: obfs-http
    - internal Support: Socks5, HTTP
- Support Subscription: Shadowsocksr, SSD
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)
- [For Developer](https://github.com/Asutorufa/yuhaiin/blob/master/for_developer.md) <- outdated
- Memory(Just a Reference)
    - Bypass = 8472 CIDR + 75296 domain = 50MB.
    - Bypass + Gui = 70MB.
    
<details>
<summary>Screenshots</summary>

![image](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/gui_by_qt_dev1.png)  

</details>

<details>
<summary>Acknowledgement</summary>

- [Golang](https://golang.org)  
- [therecipe/qt](https://github.com/therecipe/qt)  
- [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)(now change to json)  
- [breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
- [akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  
- [Dreamacro/clash](https://github.com/Dreamacro/clash)  
- [shadowsocks/go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)  
- [miekg/dns](https://github.com/miekg/dns)

</details>

<details>
<summary>Todo</summary>

- [x] add bypass
- [x] ss link compatible.  
  - [x] need more ss link template.
- [x] support http proxy.  
- [ ] add `-h` argument to show help.
- [x] add DOH.
- [x] have a GUI.
- [x] add shadowsocks client protocol.
- [ ] add TProxy, REDIRECT.
- [ ] add software disguise.
- [ ] add shadowsocks v2ray plugin.
- [ ] widget exchange to qml.

</details>
