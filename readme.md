```shell
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```

[![GitHub license](https://img.shields.io/github/license/Asutorufa/yuhaiin)](https://github.com/Asutorufa/yuhaiin/blob/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/yuhaiin.svg)](https://github.com/Asutorufa/yuhaiin/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/yuhaiin)](https://goreportcard.com/report/github.com/Asutorufa/yuhaiin)
![languages](https://img.shields.io/github/languages/top/asutorufa/yuhaiin.svg)  
How to use:

- download [releases](https://github.com/Asutorufa/yuhaiin/releases) or [Build](https://github.com/Asutorufa/yuhaiin/wiki/build).  
- Support Protocol  
    - Shadowsocksr  
        - Support Protocol see: [mzz2017/shadowsocksR](https://github.com/mzz2017/shadowsocksR)  
    - Shadowsocks  
        - Support Plugin: Obfs-Http  
        - Support Plugin: v2ray-plugin( not support mux,it's too complicated(:, I need some time to understand )  
    - internal Support: Socks5, HTTP, Linux/Mac Redir  
    - DNS: Normal DNS,EDNS,DNSSEC,DNS over HTTPS   
- Support Subscription: Shadowsocksr, SSD  
- Support Auto Set System Proxy for Linux/Windows.  
- [Bypass File](https://github.com/Asutorufa/yuhaiin/tree/ACL)  
- Memory(Just a Reference)  
    - kernel = 10486 CIDR + 127598 domain + DNS/Match cache = 54MB.  
    - Qt Gui = 20MB.  
    - Because of the Go GC, Reimport Rule will make the memory big, but this is not memory leak, it has a limit(e.g: above-mentioned example is 180M).  
        - > [Do I need to set a map to nil in order for it to be garbage collected?](https://stackoverflow.com/questions/36747776/do-i-need-to-set-a-map-to-nil-in-order-for-it-to-be-garbage-collected)  
- icon from プロ生ちゃん.  
- アイコンがプロ生ちゃんから、ご注意ください。  
- [TODO](https://github.com/Asutorufa/yuhaiin/wiki/TODO).  
- Others Please Check [Wiki](https://github.com/Asutorufa/yuhaiin/wiki).  

![v0.2.12-beta_linux](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/v0.2.12-beta_linux.png)  
![v0.2.12-beta_windows](https://raw.githubusercontent.com/Asutorufa/yuhaiin/master/img/v0.2.12-beta_windows.png)  

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

