package socks5server

import (
	microlog "../../log"
	"../cidrmatch"
	"../dns"
	"../socks5client"
	"log"
	"net"
	"runtime"
	"strconv"
	"time"
)

// ServerSocks5 <--
type ServerSocks5 struct {
	Server             string
	Port               string
	conn               *net.TCPListener
	ToHTTP             bool
	HTTPServer         string
	HTTPPort           string
	Username           string
	Password           string
	ToShadowsocksr     bool
	ShadowsocksrServer string
	ShadowsocksrPort   string
	Socks5Server       string
	Socks5Port         string
	Bypass             bool
	cidrmatch          *cidrmatch.CidrMatch
	CidrFile           string
	DNSServer          string
	dnscache           dns.Cache
	KeepAliveTimeout   time.Duration
	Timeout            time.Duration
	UseLocalResolveIp  bool
}

// Socks5 <--
func (socks5Server *ServerSocks5) Socks5() error {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	//socks5Server.dns = map[string]bool{}
	socks5Server.dnscache = dns.Cache{
		DNSServer: socks5Server.DNSServer,
	}
	var err error
	socks5Server.cidrmatch, err = cidrmatch.NewCidrMatchWithTrie(socks5Server.CidrFile)
	if err != nil {
		return err
	}
	socks5ServerIp := net.ParseIP(socks5Server.Server)
	socks5ServerPort, err := strconv.Atoi(socks5Server.Port)
	if err != nil {
		// log.Panic(err)
		return err
	}
	socks5Server.conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: socks5ServerIp, Port: socks5ServerPort})
	if err != nil {
		// log.Panic(err)
		return err
	}
	for {
		client, err := socks5Server.conn.AcceptTCP()
		if err != nil {
			// log.Panic(err)
			// return err
			microlog.Debug(err)
			_ = socks5Server.conn.Close()
			//socks5Server.conn, err = net.Listen("tcp", socks5Server.Server+":"+socks5Server.Port)
			//if err != nil {
			// log.Panic(err)
			//return err
			//}
			//time.Sleep(time.Second * 1)
			continue
		}
		if socks5Server.KeepAliveTimeout != 0 {
			_ = client.SetKeepAlivePeriod(socks5Server.KeepAliveTimeout)
		}
		//if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		//	log.Println(err)
		//}

		go func() {
			// log.Println(runtime.NumGoroutine())
			if client == nil {
				return
			}
			defer client.Close()
			socks5Server.handleClientRequest(client)
		}()
	}
}

func (socks5Server *ServerSocks5) handleClientRequest(client net.Conn) {
	var b [1024]byte
	_, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	if b[0] == 0x05 { //只处理Socks5协议
		_, _ = client.Write([]byte{0x05, 0x00})
		if b[1] == 0x01 {
			// 对用户名密码进行判断
			if b[2] == 0x02 {
				_, err = client.Read(b[:])
				if err != nil {
					log.Println(err)
					return
				}
				username := b[2 : 2+b[1]]
				password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
				if socks5Server.Username == string(username) && socks5Server.Password == string(password) {
					_, _ = client.Write([]byte{0x01, 0x00})
				} else {
					_, _ = client.Write([]byte{0x01, 0x01})
					return
				}
			}
		}

		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host, port, hostTemplate string
		switch b[3] {
		case 0x01: //IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
			hostTemplate = "ip"
		case 0x03: //域名
			host = string(b[5 : n-2]) //b[4]表示域名的长度
			hostTemplate = "domain"
		case 0x04: //IP V6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
			hostTemplate = "ip"
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

		switch b[1] {
		case 0x01:
			switch socks5Server.Bypass {
			case true:
				if hostTemplate != "ip" {
					getDns, isSuccess := dns.DNSv4(socks5Server.DNSServer, host)
					if isSuccess {
						isMatch := socks5Server.cidrmatch.MatchWithTrie(getDns[0])
						microlog.Debug(host, isMatch, getDns[0])
						if isMatch {
							socks5Server.toTCP(client, host, net.JoinHostPort(getDns[0], port))
						} else {
							if socks5Server.UseLocalResolveIp == true {
								socks5Server.toSocks5(client, net.JoinHostPort(getDns[0], port), b[:n])
							} else {
								socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
							}
						}
					} else {
						microlog.Debug(runtime.NumGoroutine(), host, "dns false")
						socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
					}
				} else {
					isMatch := socks5Server.cidrmatch.MatchWithTrie(host)
					microlog.Debug(runtime.NumGoroutine(), host, isMatch)
					if isMatch {
						socks5Server.toTCP(client, host, net.JoinHostPort(host, port))
					} else {
						socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
					}
				}
				//switch socks5Server.dnscache.Match(host, hostTemplate, socks5Server.cidrmatch.MatchWithTrie) {
				//case false:
				//	if socks5Server.ToHTTP == true {
				//		socks5Server.toHTTP(client, host, port)
				//	} else if socks5Server.ToShadowsocksr == true {
				//		socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
				//	} else {
				//		socks5Server.toTCP(client, net.JoinHostPort(host, port))
				//	}
				//case true:
				//	socks5Server.toTCP(client, net.JoinHostPort(host, port))
				//}

			case false:
				if socks5Server.ToHTTP == true {
					socks5Server.toHTTP(client, host, port)
				} else if socks5Server.ToShadowsocksr == true {
					socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
				} else {
					socks5Server.toTCP(client, host, net.JoinHostPort(host, port))
				}
			}

		case 0x02:
			// log.Println("bind 请求 " + net.JoinHostPort(host, port))
			microlog.Debug("bind 请求 " + net.JoinHostPort(host, port))

		case 0x03:
			// log.Println("udp 请求 " + net.JoinHostPort(host, port))
			microlog.Debug("udp 请求 " + net.JoinHostPort(host, port))
			socks5Server.udp(client, net.JoinHostPort(host, port))
		}
	}
}

func (socks5Server *ServerSocks5) connect() {
	// do something
}

func (socks5Server *ServerSocks5) udp(client net.Conn, domain string) {
	// log.Println()
	server, err := net.Dial("udp", domain)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //respond to connect successful

	// forward
	forward(server, client)
	//go io.Copy(server, client)
	//io.Copy(client, server)

}

func (socks5Server *ServerSocks5) toTCP(client net.Conn, domain, ip string) {
	var server net.Conn
	var dialer net.Dialer
	if socks5Server.KeepAliveTimeout != 0 {
		dialer = net.Dialer{KeepAlive: socks5Server.KeepAliveTimeout, Timeout: socks5Server.Timeout}
	} else {
		dialer = net.Dialer{Timeout: 10 * time.Second}
	}
	server, err := dialer.Dial("tcp", ip)
	if err != nil {
		log.Println(err)
		server, err = dialer.Dial("tcp", domain)
		if err != nil {
			log.Println(err)
			return
		}
	}
	defer server.Close()
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //respond to connect successful

	// forward
	forward(server, client)
	//microlog.Debug("close")
}

func (socks5Server *ServerSocks5) toHTTP(client net.Conn, host, port string) {
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //respond to connect successful
	var dialer net.Dialer
	if socks5Server.KeepAliveTimeout != 0 {
		dialer = net.Dialer{KeepAlive: socks5Server.KeepAliveTimeout, Timeout: socks5Server.Timeout}
	} else {
		dialer = net.Dialer{Timeout: socks5Server.Timeout}
	}
	server, err := dialer.Dial("tcp", socks5Server.HTTPServer+":"+socks5Server.HTTPPort)
	if err != nil {
		log.Println(err)
	}
	defer server.Close()
	// if port == "443" {
	_, _ = server.Write([]byte("CONNECT " + host + ":" + port + " HTTP/1.1\r\n\r\n"))
	httpConnect := make([]byte, 1024)
	_, _ = server.Read(httpConnect[:])
	log.Println(string(httpConnect))
	// }
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])

	// forward
	forward(server, client)
}

func (socks5Server *ServerSocks5) toShadowsocksr(client net.Conn) {
	server, err := net.Dial("tcp", socks5Server.ShadowsocksrServer+":"+socks5Server.ShadowsocksrPort)
	if err != nil {
		log.Println(err)
	}
	defer server.Close()
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //respond to connect successful

	// forward
	forward(server, client)
}

func (socks5Server *ServerSocks5) toSocks5(client net.Conn, host string, b []byte) {
	socks5Conn, err := (&socks5client.Socks5Client{
		Server:           socks5Server.Socks5Server,
		Port:             socks5Server.Socks5Port,
		KeepAliveTimeout: socks5Server.KeepAliveTimeout,
		Address:          host}).NewSocks5ClientOnlyFirstVerify()
	if err != nil {
		log.Println(err)
		socks5Server.toTCP(client, host, host)
		return
	}

	defer socks5Conn.Close()
	_, _ = socks5Conn.Write(b)

	// forward
	forward(client, socks5Conn)
}

func forward(src, dst net.Conn) {
	srcToDstCloseSig, dstToSrcCloseSig := make(chan error, 1), make(chan error, 1)
	go pipe(src, dst, srcToDstCloseSig)
	go pipe(dst, src, dstToSrcCloseSig)
	<-srcToDstCloseSig
	close(srcToDstCloseSig)
	<-dstToSrcCloseSig
	close(dstToSrcCloseSig)
	microlog.Debug(runtime.NumGoroutine(), "close")
}

func pipe(src, dst net.Conn, closeSig chan error) {
	buf := make([]byte, 0x400*32)
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			return
		}
		_, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			return
		}
	}
}
