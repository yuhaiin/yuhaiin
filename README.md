**SSRSub.go:** go语言版 ([农民日语版说明](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md)) 可生成可执行文件 无需安装一堆软件库 更轻便 基本完成  
  
已知问题:  
- [x]  配置文件的读取路径有问题  
- [ ] 执行文件未分bash和cmd 且执行文件路径有问题  
- [x] 输入错误未设置处理程序  
- [x] 第一次运行程序要检测目录是否存在,不存在则创建  

Todo:  
- [x] 使用tcp延迟检测  
   目前测得是在给socks5代理发送请求后从远程服务器读取数据的时间,个人认为这样更接近实际的使用情况,本来想用icmp,有人说icmp不够准,且需要root权限所以就先这样了.   
- [ ] 使用原生go语言版ssr(准备使用sun8911879/shadowsocksR,初学golang写不出ssr来...)  
- [ ] 分流  
- [ ] 实现http代理  
- [x] 使用sqlite存储节点信息(todo:数据库为空是node.List会出错,初始化时追加空白内容)  
- [x] 未使用多线程的sql使用事务(自测不使用多线程的话事务相当好用 不知道sql事务和go多线程哪个快 目前未作测试)
- [ ] 第一次运行自动创建桌面快捷方式,自动移动/复制程序到相应位置
- [x] 多线程处理更新订阅连接
- [ ] 使用接口
- [x] 更换节点的SQLite语句合并为一句
```
go版配置文件格式(目前与执行文件放在同一个目录)
python_path /usr/bin/python3
ssr_path /home/xxx/program/shadowsocksr-python/shadowsocks/local.py
config_path config.txt
local_port 1080
local_address 127.0.0.1
connect-verbose-info
workers 8
fast-open
deamon
pid-file /home/xxx/.cache/SSRSub/shadowsocksr.pid
log-file /dev/null
acl /media/xxx/D/code/ACL/aacl-none.acl
```
![](https://raw.githubusercontent.com/Asutorufa/SSRSubscriptionDecode/master/Screenshot_20190322_162414.png)
[其他版本](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md) 
