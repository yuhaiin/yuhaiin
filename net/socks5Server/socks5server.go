package socks5server

import (
	"log"
	"net"
	"runtime"
	"strconv"
	"time"

	"SsrMicroClient/microlog"
	"SsrMicroClient/net/matcher"
	"SsrMicroClient/net/socks5client"
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
	CidrFile           string
	BypassDomainFile   string
	DirectProxyFile    string
	DiscordDomainFile  string
	DNSServer          string
	KeepAliveTimeout   time.Duration
	Timeout            time.Duration
	UseLocalResolveIp  bool
	matcher            *matcher.Match
}

func (socks5Server *ServerSocks5) Socks5Init() error {

	var err error
	socks5Server.matcher, err = matcher.NewMatch(socks5Server.DNSServer, socks5Server.CidrFile, socks5Server.BypassDomainFile, socks5Server.DirectProxyFile, socks5Server.DiscordDomainFile)
	if err != nil {
		return err
	}

	socks5ServerIP := net.ParseIP(socks5Server.Server)
	socks5ServerPort, err := strconv.Atoi(socks5Server.Port)
	if err != nil {
		return err
	}
	socks5Server.conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: socks5ServerIP, Port: socks5ServerPort})
	if err != nil {
		return err
	}
	return nil
}

func (socks5Server *ServerSocks5) Socks5AcceptARequest() error {
	client, err := socks5Server.conn.AcceptTCP()
	if err != nil {
		microlog.Debug(err)
		return err
	}
	if socks5Server.KeepAliveTimeout != 0 {
		_ = client.SetKeepAlivePeriod(socks5Server.KeepAliveTimeout)
	}

	go func() {
		if client == nil {
			return
		}
		defer client.Close()
		socks5Server.handleClientRequest(client)
	}()
	return nil
}

// Socks5 <--
func (socks5Server *ServerSocks5) Socks5() error {
	if err := socks5Server.Socks5Init(); err != nil {
		return err
	}

	for {
		if err := socks5Server.Socks5AcceptARequest(); err != nil {
			microlog.Debug(err)
			continue
		}
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
			toTCP, toSocks5, toHTTP := socks5Server.toTCP, socks5Server.toSocks5, socks5Server.toHTTP
			isMatch := socks5Server.matcher.Matcher(host, port, hostTemplate == "domain")
			switch {
			case isMatch.Discord:
				return
			case isMatch.Proxy && !socks5Server.ToHTTP:
				toSocks5(client, net.JoinHostPort(isMatch.Host, port), b[:n])
			case isMatch.Proxy && socks5Server.ToHTTP:
				toHTTP(client, isMatch.Host, port)
			default:
				toTCP(client, net.JoinHostPort(host, port), net.JoinHostPort(isMatch.Host, port))
			}

		case 0x02:
			microlog.Debug("bind 请求 " + net.JoinHostPort(host, port))

		case 0x03:
			microlog.Debug("udp 请求 " + net.JoinHostPort(host, port))
			socks5Server.udp(client, net.JoinHostPort(host, port))
		}
	}
}

func (socks5Server *ServerSocks5) connect() {
	// do something
}

func (socks5Server *ServerSocks5) udp(client net.Conn, domain string) {
	server, err := net.Dial("udp", domain)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //respond to connect successful

	// forward
	forward(server, client)
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
	_, _ = server.Write([]byte("CONNECT " + host + ":" + port + " HTTP/1.1\r\n\r\n"))
	httpConnect := make([]byte, 1024)
	_, _ = server.Read(httpConnect[:])
	log.Println(string(httpConnect))

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
