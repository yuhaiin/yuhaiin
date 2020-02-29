# for developer

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
