# SsrMicroClient  
[![](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![codebeat badge](https://codebeat.co/badges/2cd0e124-3207-4453-8bd1-7bfc50ad68c9)](https://codebeat.co/projects/github-com-asutorufa-ssrmicroclient-master)
![](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  

issue:
- [ ] now only can run in bash,cmd is not test.
- [ ] not test path exist or not(now everything is normal).

Todo:
- [ ] use shadowsocksr write by golang(sun8911879/shadowsocksR),or use ssr_libev share libraries.  
      write a half of http proxy find sun8911879/shadowsocksR is not support auth_chain*...oof.  
- [ ] add bypass.
- [ ] support http proxy.
- [ ] create shortcut at first run,auto move or copy file to config path.
- [ ] add enter function while creating config file.
- [ ] add `-h` argument to show help.
- [ ] ssr link compatible. 

```
#config path at ~/.config/SSRSub
#config file,first run auto create,# to note
python_path /usr/bin/python3 #if use ssr_libev plese note this
ssr_path /shadowsocksr-python/shadowsocks/local.py
local_port 1080
local_address 127.0.0.1
connect-verbose-info #if use ssr_libev plese note this
workers 8 #if use ssr_libev plese note this
fast-open
deamon #if use ssr_libev plese note this
pid-file /home/xxx/.config/SSRSub/shadowsocksr.pid #if use ssr_libev plese note this
log-file /dev/null #if use ssr_libev plese note this
acl aacl-none.acl #if use ssr_python plese note this
```
[日本語](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md) [中文](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_cn.md) [other progrmammer language vision](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md) 
![](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/SSRSubv0.1alpha.png)