package main

import (
	"flag"
	"log"
	"time"

	"SsrMicroClient/net/httpserver"
	"SsrMicroClient/net/socks5Server"
)

func start(dns *string) {
	httpS := httpserver.Socks5ToHTTP{
		ToHTTP:           true,
		HTTPServer:       "127.0.0.1",
		HTTPPort:         "8189",
		ByPass:           true,
		Socks5Server:     "127.0.0.1",
		Socks5Port:       "1080",
		CidrFile:         "/home/asutorufa/.config/SSRSub/cidrBypass.conf",
		DNSServer:        *dns,
		KeepAliveTimeout: 15 * time.Second,
	}
	// if err := httpS.HTTPProxy(); err != nil {
	// 	log.Println(err)
	// 	return
	// }
	_ = httpS.HTTPProxy()
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	dns := flag.String("dns", "127.0.0.1:53", "dns")
	flag.Parse()
	//start(dns)

	socks5S := socks5server.ServerSocks5{
		Server:           "127.0.0.1",
		Port:             "1084",
		Bypass:           true,
		CidrFile:         "/home/asutorufa/.config/SSRSub/cidrBypass.conf",
		BypassDomainFile: "/home/asutorufa/.config/SSRSub/domainBypass.conf",
		DirectProxyFile:  "/home/asutorufa/.config/SSRSub/domainProxy.conf",
		DiscordDomainFile:"/home/asutorufa/.config/SSRSub/discordDomain.conf",
		ToShadowsocksr:   true,
		Socks5Server:     "127.0.0.1",
		Socks5Port:       "1080",
		//208.67.222.222#5353
		//208.67.222.220#5353
		//58.132.8.1 beijing edu DNS server
		//101.6.6.6 beijing tsinghua dns server
		DNSServer:        *dns,
		KeepAliveTimeout: 15 * time.Second,
		Timeout:          10 * time.Second,
	}
	if err := socks5S.Socks5(); err != nil {
		log.Println(err)
		return
	}

	// newMatch, err := cidrmatch.NewCidrMatchWithTrie("/mnt/share/code/golang/cn_rules.conf")
	// if err != nil {
	// 	log.Println(err)
	// }
	// t1 := time.Now() // get current time
	// newMatch.MatchWithTrie("60.165.116.76")
	// newMatch.MatchWithTrie("192.168.0.1")
	// newMatch.MatchWithTrie("223.255.0.1")
	// elapsed := time.Since(t1)
	// fmt.Println("App elapsed: ", elapsed/3)
}
