|文件|默认连接方式|直连|屏蔽广告|地址|
|:--:|:--:|:--:|:--:|:--:|
|[aacl.acl](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/aacl.acl)|默认代理<br />[gfwlist](https://github.com/gfwlist/gfwlist)远程解析dns   | [ipblocks](http://www.ipdeny.com/ipblocks/)<br />[geoip](http://geolite.maxmind.com/download/geoip/)<br/>[apnic(ipv4+ipv6)](http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)|[StevenBlack/hosts](https://github.com/StevenBlack/hosts)<br />[serverlist](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext)<br />自己抓包<br />**(广告包含较多可能会误杀正常的网站)**|右键复制文件名地址|
|[aacl-light.acl](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/aacl-light.acl) |   默认代理<br />[gfwlist](https://github.com/gfwlist/gfwlist)远程解析dns|[ipblocks](http://www.ipdeny.com/ipblocks/)<br/>[geoip](http://geolite.maxmind.com/download/geoip/)<br/>[apnic(ipv4+ipv6)](http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)|1.国内广告和侵犯隐私网址(baidu,tencent,ali....)<br />2.自己抓包的<br />3.部分(谷歌,雅虎..)广告|右键复制文件名地址|
|[aacl-none.acl](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/aacl-none.acl)|默认代理<br />[gfwlist](https://github.com/gfwlist/gfwlist)远程解析dns|[ipblocks](http://www.ipdeny.com/ipblocks/)<br/>[geoip](http://geolite.maxmind.com/download/geoip/)<br/>[apnic(ipv4+ipv6)](http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)|无|右键复制文件名地址|
|[aacl-none-simple.acl](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/aacl-none-simple.acl)|默认代理<br />|[ipblocks](http://www.ipdeny.com/ipblocks/)<br/>[geoip](http://geolite.maxmind.com/download/geoip/)<br/>[apnic(ipv4)](http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)|无|右键复制文件名地址|
|[bypass.acl](https://raw.githubusercontent.com/Asutorufa/ACL/master/bypass.acl)(**几乎不更新,不用**)|默认直连|默认直连|只包含自己抓包的|右键复制文件名地址|


**中国ip来自 [ipblock](http://www.ipdeny.com/ipblocks/ ),[geoip](http://geolite.maxmind.com/download/geoip/),[apnic(ipv4+ipv6)](http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)**  
**注意:广告过滤使用 [StevenBlack/hosts](https://github.com/StevenBlack/hosts),[serverlist](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext)转化而来,转化方法可在脚本文件中查看,还有部分自己抓包弄得,可以在抓包列表查看**  
**bypass proxy网址来自[gfwlist](https://github.com/gfwlist/gfwlist)**

此产品包含MaxMind公司出品的GeoLite数据库，地址为
  <a href="http://www.maxmind.com">http://www.maxmind.com</a>.
