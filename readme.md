# SsrMicroClient
```
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```
[![license](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/SsrMicroClient)](https://goreportcard.com/report/github.com/Asutorufa/SsrMicroClient)
![languages](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  
<!-- [![codebeat badge](https://codebeat.co/badges/ce94a347-64b1-4ee3-9b18-b95858e1c6b4)](https://codebeat.co/projects/github-com-asutorufa-ssrmicroclient-master) -->
How to use:

- download the [releases](https://github.com/Asutorufa/SsrMicroClient/releases) binary file.if not have your platform ,please build it by yourself.
- if you use windows,you need to read [how to install libsodium to windows](https://github.com/Asutorufa/SsrMicroClient/blob/master/windows_use_ssr_python.md).  
  Or move the two files of [windowsDepond](https://github.com/Asutorufa/SsrMicroClient/tree/OtherLanguage/Old/windowsDepond) to C:\Windows\SysWOW64.  
- build

at first,install [therecipe/qt#Installation](https://github.com/therecipe/qt#installation)

```shell script
git clone https://github.com/Asutorufa/SsrMicroClient.git
cd SsrMicroClient
go build SSRSub.go
./SSRSub
```
or use this:[if-you-just-want-to-compile-an-application](https://github.com/therecipe/qt/wiki/Installation-on-Linux#if-you-just-want-to-compile-an-application)  

no gui:

```shell script
git clone https://github.com/Asutorufa/SsrMicroClient.git
cd SsrMicroClient
go build -tags noGui SSRSub_nogui.go
./SSRSub
```
- config file  
  it will auto create at first run,path at `~/.config/SSRSub`,windows at Documents/SSRSub.

- [Bypass File](https://github.com/Asutorufa/SsrMicroClient/tree/ACL)

<!--
```
#config path at ~/.config/SSRSub
#config file,first run auto create,# to note
#python_path /usr/bin/python3
#ssr_path /shadowsocksr-python/shadowsocks/local.py
#local_port 1080
#local_address 127.0.0.1
#connect-verbose-info
workers 8
fast-open
daemon
#pid-file /home/xxx/.config/SSRSub/shadowsocksr.pid
#log-file /dev/null
```
-->
<details>
<summary>gui version screenshots</summary>
  
![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/gui_by_qt_dev1.png)  

</details>

<details>
<summary>no gui version screenshots</summary>

![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/SSRSubV0.2.3beta.png)

</details>

<!-- [日本語](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md) [中文](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_cn.md) [other progrmammer language vision](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md)    -->

## for developer

use socks5 proxy at your program

```golang
import github.com/Asutorufa/SsrMicroClient/net/Socks5Client
socks5Conn, err := (&socks5client.Socks5Client{
// <your socks5 server ip/domain>
 Server: "x.x.x.x",
//  <your socks5 server port>
 Port: "xxxx",
// socks5 proxy Username
 Username: "xxxxx",
// socks5 proxy password
 Password: "xxxxx",
//  <keep alive timeout>
 KeepAliveTimeout: x * time.Second,
//  <what domain/ip your want to access across socks5,format like xxx.com:443>
 Address: "www.xxx.xxx:xx"}).NewSocks5Client()
 if err != nil {
  log.Println(err)
  return
}
```

use DNS

```golang
import github.com/Asutorufa/SsrMicroClient/net/dns
// for example,get google's ip from google public dns(ipv6 can also get)
ip,isSuccessful := dns.DNS("8.8.8.8:53","www.google.com")
// it will return string{},false when get failed
```

use cidr match

```golang
// get a new matcher from a cidr file

// the file like
/* 
   x.x.x.x/xx
   x.x.x.x/xx
     ...
   x.x.x.x/xx
*/

import github.com/Asutorufa/SsrMicroClient/net/cidrmatch
newMatcher,err := cidrmatch.NewCidrMatchWithTrie("path/to/your/cidrfile")
if err != nil{
  log.Println(err)
  return
}

// match a ip
isMatch := newMatcher.MatchWithTrie("x.x.x.x")

// insert a new cidr
if err := newMatcher.InsertOneCIDR("x.x.x.x/xx"); err != nil{
 log.Println(err) 
 return
}
```

use domain matcher

```golang
import github.com/Asutorufa/SsrMicroClient/net/domainmatch
newMatcher := domainmatch.NewDomainMatcher()
// insert a domain
newMatcher.Insert("www.xxx.com")
// insert domains from file
// the file like
/*
  www.xxx.com
  www.xxx.net
  ...
  www.xxx.io
*/
newMatcher.InsertWithFile("path/to/file")
// match a domain
isMatch := newMatcher.Search("www.xxx.com")
```

## Thanks

[Golang](https://golang.org)  
[therecipe/qt](https://github.com/therecipe/qt)  
[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)(now change to json)  
[breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
[akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  

<!--
## already know issue

ssr python version at mac may be not support,please test by yourself.
-->

## Others

<!--
Make a simple gui([Now Dev](https://github.com/Asutorufa/SsrMicroClient/tree/dev)):
![gui](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/dev/img/gui_dev.png) 
-->
<details>
<summary>Todo:</summary>

- [x] (give up)use shadowsocksr write by golang(sun8911879/shadowsocksR),or use ssr_libev share libraries.  
      write a half of [http proxy](https://github.com/Asutorufa/SsrMicroClient/blob/OtherLanguage/Old/SSR_http_client/client.go) find sun8911879/shadowsocksR is not support auth_chain*...oof.  
      when i use ssr_libev i cant run it in the golang that has so many error,i fix a little but more and more error appear.

<!-- ```error
      # command-line-arguments
    /tmp/go-build379176400/b001/_x002.o：在函数‘main’中：
    ./local.c:1478: `main'被多次定义
    # command-line-arguments
    .........
    .........
    .........
    ./local.c:438:36: warning: comparison between pointer and       integer
                         if (perror == EINPROGRESS) {
                                    ^~
``` -->

- [x] add bypass
  - add bypass by socks5 to socks5 and socks5 to http.I need more information about iptables redirection and ss-redir.
- [x] ss link compatible.  
  - [ ] need more ss link template.
- [x] support http proxy.  
  - already know bug: telegram cant use,the server repose "request URI to long",I don't know how to fix.
- [ ] create shortcut at first run,auto move or copy file to config path.
- [ ] add `-h` argument to show help.

<!--
fixed issue:

- process android is not linux.
- sh should use which to get.  
- support windows.
- can setting timeout.
-->
</details>
