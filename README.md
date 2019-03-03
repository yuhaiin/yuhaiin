# SSR_Subscription_analysis
**SSRSub.go:** go语言版 可生成可执行文件 无需安装一堆软件库 更轻便 基本完成  
  
已知问题:  
- [x]  配置文件的读取路径有问题  
- [ ] 执行文件未分bash和cmd 且执行文件路径有问题  
- [x] 输入错误未设置处理程序  

Todo:  
- [x] 使用tcp延迟检测(目前还没有整合到文件中,只有单独的文件)  
   之前忘记转发数据了 只进行了socks5连接验证 所以是微秒级别的....  
   目前测得是在给socks5代理发送请求后从远程服务器读取数据的时间,个人认为这样更接近实际的使用情况,本来想用icmp,有人说icmp不够准,且需要root权限所以就先这样了.  
   ~~(_完成一半,但是不知道为啥延迟都是微秒级别的,明显有问题_)~~  
- [ ] 使用原生go语言版ssr  
- [ ] 分流  
- [ ] 实现http代理  
- [x] 使用sqlite存储节点信息(目前还没有整合到文件中,只有单独的文件)

```
go版配置文件格式(目前与执行文件放在同一个目录)
python_path /usr/bin/python3
ssr_path /home/xxx/program/shadowsocksr-python/shadowsocks/local.py
config_path config.txt
config_url #程序内更新
local_port 1080
local_address 127.0.0.1
ssr_config 
connect-verbose-info
workers 8
fast-open
deamon
pid-file /home/asutorufa/.cache/SSRSub/shadowsocksr.pid
log-file /dev/null
```

**SSRSub.py:** 解析经base64多层加密的订阅链接 可进行ping测试 python3版 读取速度更快  
**SSRSub:** 解析经base64多层加密的订阅链接  
**SSRConfig_json:** 利用jq解析json文件  
ssr_libev  
![](https://raw.githubusercontent.com/Asutorufa/a-simple-menu-for-shadowsocksr-python/master/libev_run.png)  
ssr_python  
![](https://raw.githubusercontent.com/Asutorufa/a-simple-menu-for-shadowsocksr-python/master/start_1.png)  
![](https://raw.githubusercontent.com/Asutorufa/a-simple-menu-for-shadowsocksr-python/master/start_2.png)  
![](https://raw.githubusercontent.com/Asutorufa/a-simple-menu-for-shadowsocksr-python/master/stop.png)  
