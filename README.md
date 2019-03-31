<!--**SSRSub.go:** go语言版 ([农民日语版说明](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md)) 可生成可执行文件 无需安装一堆软件库 更轻便 基本完成-->
# SsrMicroClient  
[![](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![codebeat badge](https://codebeat.co/badges/2cd0e124-3207-4453-8bd1-7bfc50ad68c9)](https://codebeat.co/projects/github-com-asutorufa-ssrmicroclient-master)
![](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  
已知问题:  
- [x]  配置文件的读取路径有问题   
- [x] 数据库为空时未设置说明及跳过(更换query为queryrow)  
- [x] 对数据库中没有的内容进行空判断
- [x] 输入错误未设置处理程序  
- [x] 第一次运行程序要检测目录是否存在,不存在则创建  
- [ ] 执行文件未分bash和cmd 且执行文件路径有问题  
- [ ] 防止出错 对配置文件内的目录进行检测(目测现在即使不检测也没问题) 

Todo:  
- [x] 使用tcp延迟检测  
   目前测得是在给socks5代理发送请求后从远程服务器读取数据的时间,个人认为这样更接近实际的使用情况,本来想用icmp,有人说icmp不够准,且需要root权限所以就先这样了.   
- [x] 使用sqlite存储节点信息(todo:数据库为空是node.List会出错,初始化时追加空白内容)  
- [x] 未使用多线程的sql使用事务(使用go自带的开启事务，非数据库语言)(实测事务比go多线程快500倍,已使用事务)
- [x] 多线程处理更新订阅连接
- [x] 更换节点的SQLite语句合并为一句
- [x] (已放弃)使用go自带事务语句(自测sqlite使用了自带的事务语句与没有使用所用时间相同所以放弃使用go自带事务语句)
- [ ] 使用原生go语言版ssr(准备使用sun8911879/shadowsocksR,初学golang写不出ssr来...)  
- [ ] 分流  
- [ ] 实现http代理  
- [ ] 第一次运行自动创建桌面快捷方式,自动移动/复制程序到相应位置
- [ ] 使用接口(重写read_config,防止性能浪费)
- [ ] 初次生成配置文件时,进行自定义输入操作,防止某些人不会修改
- [ ] 加入`-h`参数对各种操作进行简短的说明(特别是配置文件的修改)
```
#go版配置文件格式,第一次运行自动生成 #可以注释语句
python_path /usr/bin/python3 #使用ssr_libev请关闭此项
ssr_path /shadowsocksr-python/shadowsocks/local.py
local_port 1080
local_address 127.0.0.1
connect-verbose-info #使用ssr_libev请关闭此项
workers 8 #使用ssr_libev请关闭此项
fast-open
deamon #使用ssr_libev请关闭此项
pid-file /home/xxx/.config/SSRSub/shadowsocksr.pid #使用ssr_libev请关闭此项
log-file /dev/null #使用ssr_libev请关闭此项
acl aacl-none.acl #使用ssr_python请关闭此项
```
[农民日语版说明](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md)  [其他语言版本说明](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md) 
![](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/SSRSubv0.1alpha.png)
