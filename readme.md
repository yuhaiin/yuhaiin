# SsrMicroClient

```shell
２０世紀 郵便配達員が運ぶのは幸福だから、手紙は人間に幸せ届ける
２１世紀 インターネットが運ぶのは幸福だから、アクセスできないなら人間に幸せ届けない
```

[![license](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/SsrMicroClient)](https://goreportcard.com/report/github.com/Asutorufa/SsrMicroClient)
![languages](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  
How to use:

- download the [releases](https://github.com/Asutorufa/SsrMicroClient/releases) binary or build.

<!-- - For Windows Users
  - [how to install libsodium to windows](https://github.com/Asutorufa/SsrMicroClient/blob/master/windows_use_ssr_python.md).  
  - Or move the two files [windowsDepond](https://github.com/Asutorufa/SsrMicroClient/tree/OtherLanguage/Old/windowsDepond) to C:\Windows\SysWOW64.   -->

- Build

  - At first [therecipe/qt#Installation](https://github.com/therecipe/qt#installation)

    ```shell script
    git clone https://github.com/Asutorufa/SsrMicroClient.git
    cd SsrMicroClient
    qtdeploy
    ```

  - Or [if-you-just-want-to-compile-an-application](https://github.com/therecipe/qt/wiki/Installation-on-Linux#if-you-just-want-to-compile-an-application)  

<!-- - config file  
  it will auto create at first run,path at `~/.config/SSRSub`,windows at Documents/SSRSub. -->

- [Bypass File](https://github.com/Asutorufa/SsrMicroClient/tree/ACL)
- [For Developer](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/for_developer.md)

<details>
<summary>Screenshots</summary>
  
![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/gui_by_qt_dev1.png)  

</details>

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
  - [x] fixed,problem is http's keep-alive.~~already know bug: telegram cant use,the server repose "request URI to long",I don't know how to fix.~~
- [ ] create shortcut at first run,auto move or copy file to config path.
- [ ] add `-h` argument to show help.
- [x] add DOH.
- [x] have a GUI.

</details>
