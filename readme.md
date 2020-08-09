```shell
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg)  
How to use:

- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or build.

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
    windows amd64
    
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
    - Shadowsocksr
        - Support Protocol see: [mzz2017/shadowsocksR](https://github.com/mzz2017/shadowsocksR)
    - Shadowsocks
        - Support Plugin: Obfs-Http
        - Support Plugin: v2ray-plugin( not support mux,it's too complicated(:, I need some time to understand )
    - internal Support: Socks5, HTTP, Linux/Mac Redir
    - DNS: Normal DNS,EDNS,DNSSEC,DNS over HTTPS 
- Support Subscription: Shadowsocksr, SSD
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)
- Memory(Just a Reference)
    - Bypass = 8472 CIDR + 75296 domain = 50MB.
    - Bypass + Gui = 70MB.
    - Because of the Go GC, Reimport Rule will make the memory big, but this is not memory leak, it has a limit(e.g: above-mentioned example is 180M).
        - > [Do I need to set a map to nil in order for it to be garbage collected?](https://stackoverflow.com/questions/36747776/do-i-need-to-set-a-map-to-nil-in-order-for-it-to-be-garbage-collected)
- icon from プロ生ちゃん.
- アイコンがプロ生ちゃんから、ご注意ください。

![image](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/gui_by_qt_v0.2.11.4.png)  
![image](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/gui_windows_v0.2.11.4.png)  


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
- [v2ray](https://v2ray.com/)  
- [gRPC](https://grpc.io/)  
- [protobuf](https://github.com/golang/protobuf)  
- [プロ生ちゃん](https://kei.pronama.jp/)

</details>

<details>
<summary>TODO</summary>

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
- [x] ~~widget exchange to qml.~~(now already change to gridLayout)
- [x] ~~change qt gui to use new api.~~
- [X] new api for android(or others). <- use grpc.
- [ ] add disguise.

```single instance
          single instance
  +-----+
  | gui |
  +-----+
    ^
    | grpc
    v
+--------+    create     +----------+
| server | ------------> | lockfile |
+--------+  write host   +----------+
      ^                         ^
      | open gui                | check lockfile is locked
      | and exit new process    |         and
+--------------------+          | get already running grpc server host
| new gui and server |----------+
+--------------------+
```

</details>
