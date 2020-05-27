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

    linux
    ```shell script
    git clone https://github.com/Asutorufa/yuhaiin.git
    cd yuhaiin
    export GO111MODULE=on
    go install -v -tags=no_env github.com/therecipe/qt/cmd/...
    go mod vendor
    git clone https://github.com/therecipe/env_linux_amd64_513.git vendor/github.com/therecipe/env_linux_amd64_513
    $(go env GOPATH)/bin/qtdeploy
    ```
    windows
    
    ```cmd
    git clone https://github.com/Asutorufa/yuhaiin.git
    cd yuhaiin
    set GO111MODULE=on
    go install -v -tags=no_env github.com/therecipe/qt/cmd/... 
    go mod vendor
    git clone https://github.com/therecipe/env_windows_amd64_513.git vendor/github.com/therecipe/env_windows_amd64_513
    for /f %v in ('go env GOPATH') do %v\bin\qtdeploy
    ```
  
- Support Protocol
    - Shadowsocksr <- need to install a external client(like shadowsocksr-libev)
    - Shadowsocks
        - Support Plugin: Obfs-Http
        - Support Plugin: v2ray-plugin( not support mux,it's too complicated(:, I need some time to understand )
    - internal Support: Socks5, HTTP, Linux/Mac Redir
- Support Subscription: Shadowsocksr, SSD
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)
- [For Developer](https://github.com/Asutorufa/yuhaiin/blob/master/for_developer.md) <- outdated
- Memory(Just a Reference)
    - Bypass = 8472 CIDR + 75296 domain = 50MB.
    - Bypass + Gui = 70MB.
    - Because of the Go GC, Reimport Rule will make the memory big, but this is not memory leak, it has a limit(e.g: above-mentioned example is 180M).
        - > [Do I need to set a map to nil in order for it to be garbage collected?](https://stackoverflow.com/questions/36747776/do-i-need-to-set-a-map-to-nil-in-order-for-it-to-be-garbage-collected)
    
<details>
<summary>Screenshots</summary>

![image](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/gui_by_qt_v0.2.11.3.png)  
![image](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/gui_windows_v0.2.11.3.png)  

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
- [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin)  
- [v2ray](https://v2ray.com/)  
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
- [x] add linux REDIRECT.
- [x] add shadowsocks v2ray plugin.
- [ ] widget exchange to qml.
- [ ] new api for android(or others).
- [ ] change qt gui to use new api.
- [ ] add software disguise.

</details>
