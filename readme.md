# SsrMicroClient

```shell
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```

[![license](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/SsrMicroClient)](https://goreportcard.com/report/github.com/Asutorufa/SsrMicroClient)
![languages](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  
<!-- [![codebeat badge](https://codebeat.co/badges/ce94a347-64b1-4ee3-9b18-b95858e1c6b4)](https://codebeat.co/projects/github-com-asutorufa-ssrmicroclient-master) -->
How to use:

- download the [releases](https://github.com/Asutorufa/SsrMicroClient/releases) binary file.if have not your platform,please build it yourself.
- if use Windows,need to read [how to install libsodium to windows](https://github.com/Asutorufa/SsrMicroClient/blob/master/windows_use_ssr_python.md).  
  Or move the two files [windowsDepond](https://github.com/Asutorufa/SsrMicroClient/tree/OtherLanguage/Old/windowsDepond) to C:\Windows\SysWOW64.  
- build

at first,install [therecipe/qt#Installation](https://github.com/therecipe/qt#installation)

```shell script
git clone https://github.com/Asutorufa/SsrMicroClient.git
cd SsrMicroClient
go build SSRSub.go
./SSRSub
```
or use this:[if-you-just-want-to-compile-an-application](https://github.com/therecipe/qt/wiki/Installation-on-Linux#if-you-just-want-to-compile-an-application)  

- config file  
  it will auto create at first run,path at `~/.config/SSRSub`,windows at Documents/SSRSub.

- [Bypass File](https://github.com/Asutorufa/SsrMicroClient/tree/ACL)

<details>
<summary>screenshots</summary>
  
![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/gui_by_qt_dev1.png)  

</details>

<!-- [日本語](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md) [中文](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_cn.md) [other progrmammer language vision](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md)    -->

## for developer

use socks5 proxy at your program

```golang
import github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client
socks5Conn, err := (&socks5client.Socks5Client{
// <your socks5 server ip/domain>
 Server: "x.x.x.x",
//  <your socks5 server port>
 Port: "xxxx",
// socks5 proxy Username
 Username: "xxxxx",
// socks5 proxy password
 Password: "xxxxx",
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

use DNSOverHTTPS

```golang
import github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client
import github.com/Asutorufa/SsrMicroClient/net/dns
// for example,get google's ip from google public dns(ipv6 can also get)
ip,isSuccessful := dns.DNSOverHTTPS("https://dns.google/resolve","www.google.com",nil)
// if you want to use doh across a proxy
// for example: use socks5 from the aforementioned
proxy := func(ctx context.Context, network, addr string) (net.Conn, error) {
  x := &client.Socks5Client{Server: "127.0.0.1", Port: "1080", Address:addr}
  return x.NewSocks5Client()
}
ip,isSuccessful := dns.DNSOverHTTPS("https://dns.google/resolve","www.google.com",proxy)
// it will return string{},false when get failed
```

use cidr match

```golang
// get a new matcher from a cidr file

// the file like
/* 
   x.x.x.x/xx flag
   x.x.x.x/xx flag
     ...
   x.x.x.x/xx flag
*/

import github.com/Asutorufa/SsrMicroClient/net/matcher/cidrmatch
newMatcher,err := cidrmatch.NewCidrMatchWithTrie("path/to/your/cidrfile")
if err != nil{
  log.Println(err)
  return
}

// match a ip
isMatch,flag := newMatcher.MatchWithTrie("x.x.x.x","flag")

// insert a new cidr
if err := newMatcher.InsertOneCIDR("x.x.x.x/xx","flag"); err != nil{
 log.Println(err)
 return
}
```

use domain matcher

```golang
import github.com/Asutorufa/SsrMicroClient/net/matcher/domainmatch
newMatcher := domainmatch.NewDomainMatcher()
// insert a domain
newMatcher.Insert("www.xxx.com","flag")
// insert domains from file
// the file like
/*
  www.xxx.com flag
  www.xxx.net flag
  ...
  www.xxx.io flag
*/
newMatcher.InsertWithFile("path/to/file")
// match a domain
isMatch,flag := newMatcher.Search("www.xxx.com")
```

use Matcher(include cidr and domain)

```golang
import github.com/Asutorufa/SsrMicroClient/net/matcher
import github.com/Asutorufa/SsrMicroClient/net/dns
//the dnsFunc is get ip when the domain is not match,then match the ip.
//you can use the aforementioned
matcher, err = matcher.NewMatcherWithFile(dns.DNS, "path/to/file")
// the file like
/*
  www.xxx.com flag
  www.xxx.net flag
  ...
  www.xxx.io flag
  ...
  x.x.x.x/xx flag
  x.x.x.x/xx flag
  ...
  x.x.x.x/xx flag
*/
if err != nil {
  log.Println(err, rulePath)
}
//or not use the file
matcher, err := matcher.NewMatcher(dns.DNS)
if err != nil {
  log.Println(err, rulePath)
}
// insert a domain or cidr
if err := matcher.Insert("www.xxxx.xxx","flag");err != nil{
  log.Println(err)
}
if err := matcher.Insert("xxx.xxx.xxx.xxx/xx","flag");err != nil{
  log.Println(err)
}
// match domain or ip
target,flag := mather.MatchStr("www.xxx.xxx")
// if a domain match successful,the target is only include domain
// if not match successful,the target include the domain and ips from dns
```

## Thanks

[Golang](https://golang.org)  
[therecipe/qt](https://github.com/therecipe/qt)  
[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)(now change to json)  
[breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
[akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  

## Others

<details>
<summary>Todo:</summary>
- [x] add bypass
  - add bypass by socks5 to socks5 and socks5 to http.I need more information about iptables redirection and ss-redir.
- [x] ss link compatible.  
  - [ ] need more ss link template.
- [x] support http proxy.  
  - already know bug: telegram cant use,the server repose "request URI to long",I don't know how to fix.
- [ ] create shortcut at first run,auto move or copy file to config path.
- [ ] add `-h` argument to show help.
</details>
