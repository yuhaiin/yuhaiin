package httpserver

import (
	"log"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"../../microlog"
	"../cidrmatch"
	"../dns"
	"../domainmatch"
	"../socks5client"
)

// Socks5ToHTTP like name
type Socks5ToHTTP struct {
	ToHTTP            bool
	HTTPListener      *net.TCPListener
	HTTPServer        string
	HTTPPort          string
	Socks5Server      string
	Socks5Port        string
	ByPass            bool
	cidrmatch         *cidrmatch.CidrMatch
	CidrFile          string
	bypassDomainMatch *domainmatch.DomainMatcher
	BypassDomainFile  string
	directProxy       *domainmatch.DomainMatcher
	DirectProxyFile   string
	DNSServer         string
	// dns          map[string]bool
	// dns      sync.Map
	dnscache          dns.Cache
	KeepAliveTimeout  time.Duration
	Timeout           time.Duration
	UseLocalResolveIp bool
}

func (socks5ToHttp *Socks5ToHTTP) HTTPProxyInit() error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// socks5ToHttp.dns = map[string]bool{}
	socks5ToHttp.dnscache = dns.Cache{
		DNSServer: socks5ToHttp.DNSServer,
	}
	var err error
	if socks5ToHttp.ByPass == true {
		socks5ToHttp.cidrmatch, err = cidrmatch.NewCidrMatchWithTrie(socks5ToHttp.CidrFile)
		if err != nil {
			return err
		}
		socks5ToHttp.bypassDomainMatch = domainmatch.NewDomainMatcherWithFile(socks5ToHttp.BypassDomainFile)
		socks5ToHttp.directProxy = domainmatch.NewDomainMatcherWithFile(socks5ToHttp.DirectProxyFile)
	}

	socks5ToHTTPServerIP := net.ParseIP(socks5ToHttp.HTTPServer)
	socks5ToHTTPServerPort, err := strconv.Atoi(socks5ToHttp.HTTPPort)
	if err != nil {
		// log.Panic(err)
		return err
	}
	socks5ToHttp.HTTPListener, err = net.ListenTCP("tcp",
		&net.TCPAddr{IP: socks5ToHTTPServerIP, Port: socks5ToHTTPServerPort})
	if err != nil {
		return err
	}
	return nil
}

func (socks5ToHttp *Socks5ToHTTP) HTTPProxyAcceptARequest() error {
	HTTPConn, err := socks5ToHttp.HTTPListener.AcceptTCP()
	if err != nil {
		// return err
		microlog.Debug(err)
		//time.Sleep(time.Second * 1)
		//_ = socks5ToHttp.HTTPListener.Close()
		//socks5ToHttp.HTTPListener, err = net.Listen("tcp", socks5ToHttp.HTTPServer+":"+socks5ToHttp.HTTPPort)
		//if err != nil {
		//	return err
		//}
		return err
	}
	if socks5ToHttp.KeepAliveTimeout != 0 {
		_ = HTTPConn.SetKeepAlivePeriod(socks5ToHttp.KeepAliveTimeout)
	}
	//if err := HTTPConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
	//	log.Println(err)
	//}

	go func() {
		if HTTPConn == nil {
			return
		}
		defer HTTPConn.Close()
		// log.Println("线程数:", runtime.NumGoroutine())
		err := socks5ToHttp.httpHandleClientRequest(HTTPConn)
		if err != nil {
			microlog.Debug(err)
			return
		}
	}()
	return nil
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (socks5ToHttp *Socks5ToHTTP) HTTPProxy() error {
	if err := socks5ToHttp.HTTPProxyInit(); err != nil {
		return err
	}
	for {
		if err := socks5ToHttp.HTTPProxyAcceptARequest(); err != nil {
			microlog.Debug(err)
			continue
		}
	}
}

func (socks5ToHttp *Socks5ToHTTP) httpHandleClientRequest(HTTPConn net.Conn) error {
	requestData := make([]byte, 1024*4)
	requestDataSize, err := HTTPConn.Read(requestData[:])
	if err != nil {
		return err
	}
	//microlog.Debug("all Data",string(requestData[:requestDataSize]),"end All data",strings.Split(string(requestData[:requestDataSize]), "\r\n\r\n"),"end split Data")
	headerAndData := strings.Split(string(requestData[:requestDataSize]), "\r\n\r\n")
	var header, data string
	if len(headerAndData) > 0 {
		header = headerAndData[0]
	} else {
		return microlog.ErrErr{Err: "no header"}
	}
	if len(headerAndData) > 1 {
		data = headerAndData[1]
	} else {
		log.Println("no data")
	}

	//microlog.Debug(strings.Split(header, "\r\n")[0], len(data))
	headerRequest := strings.Split(header, "\r\n")[0]
	var requestMethod string
	headerRequestSplit := strings.Split(headerRequest, " ")
	requestMethod = headerRequestSplit[0]
	headerArgs := make(map[string]string)
	for index, line := range strings.Split(header, "\r\n") {
		if index != 0 {
			//_, _ = fmt.Sscanf(line, "%s%s", &method, &host)
			tmp := strings.Split(line, ": ")
			key := tmp[0]
			value := tmp[1]
			if key == "Proxy-Connection" {
				headerArgs["Connection"] = value
				continue
			}
			headerArgs[key] = value
		}
	}

	if requestMethod == "CONNECT" {
		headerArgs["Host"] = headerRequestSplit[1]
	}
	hostPortURL, err := url.Parse("//" + headerArgs["Host"])
	if err != nil {
		microlog.Debug(err)
		return err
	}
	var address string
	if hostPortURL.Port() == "" {
		address = hostPortURL.Hostname() + ":80"
		headerRequest = strings.ReplaceAll(headerRequest, "http://"+address, "")
	} else {
		address = hostPortURL.Host
		microlog.Debug("address:", address)
	}
	headerRequest = strings.ReplaceAll(headerRequest, "http://"+headerArgs["Host"], "")
	//microlog.Debug(headerArgs)
	//microlog.Debug("requestMethod:",requestMethod)
	//microlog.Debug("headerRequest ",headerRequest,"headerRequest end")
	//microlog.Debug("address:", address)

	for key, value := range headerArgs {
		headerRequest += "\r\n" + key + ": " + value
	}
	headerRequest += "\r\n\r\n" + data

	getSocks5Conn := func(Server, Port string, KeepAliveTimeout time.Duration, Address string) (net.Conn, error) {
		return (&socks5client.Socks5Client{
			Server:           socks5ToHttp.Socks5Server,
			Port:             socks5ToHttp.Socks5Port,
			KeepAliveTimeout: socks5ToHttp.KeepAliveTimeout,
			Address:          Address}).NewSocks5Client()
	}

	var Conn net.Conn
	switch socks5ToHttp.ByPass {
	case false:
		Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
			socks5ToHttp.KeepAliveTimeout, address)
		if err != nil {
			return err
		}
	case true:
		var hostTemplate string
		if net.ParseIP(hostPortURL.Hostname()) != nil {
			hostTemplate = "ip"
		}

		var domainPort string
		if net.ParseIP(hostPortURL.Hostname()) == nil {
			domainPort = strings.Split(address, ":")[1]
		} else if net.ParseIP(hostPortURL.Hostname()).To4() != nil {
			domainPort = strings.Split(address, ":")[1]
		} else {
			domainPort = strings.Split(address, "]:")[1]
		}

		if hostTemplate != "ip" {
			if socks5ToHttp.bypassDomainMatch.Search(hostPortURL.Hostname()) {
				Conn, err = net.Dial("tcp", address)
				if err != nil {
					log.Println(address, err)
					return err
				}
			} else if socks5ToHttp.directProxy.Search(hostPortURL.Hostname()) {
				Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
					socks5ToHttp.KeepAliveTimeout, address)
				if err != nil {
					microlog.Debug(err)
					return err
				}
			} else {
				getDns, isSuccess := dns.DNS(socks5ToHttp.DNSServer, hostPortURL.Hostname())
				if isSuccess {
					isMatch := socks5ToHttp.cidrmatch.MatchWithTrie(getDns[0])
					microlog.Debug(runtime.NumGoroutine(), hostPortURL.Hostname(), isMatch, getDns[0])
					if isMatch {
						Conn, err = net.Dial("tcp", net.JoinHostPort(getDns[0], domainPort))
						if err != nil {
							Conn, err = net.Dial("tcp", address)
							if err != nil {
								log.Println(err)
								return err
							}
						}
					} else {
						if socks5ToHttp.UseLocalResolveIp == true {
							Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
								socks5ToHttp.KeepAliveTimeout, net.JoinHostPort(getDns[0], domainPort))
						} else {
							Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
								socks5ToHttp.KeepAliveTimeout, address)
						}
						if err != nil {
							// log.Println(err)
							microlog.Debug(err)
							return err
						}
					}
				} else {
					microlog.Debug(runtime.NumGoroutine(), address, "dns false")
					Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
						socks5ToHttp.KeepAliveTimeout, address)
					if err != nil {
						// log.Println(err)
						microlog.Debug(err)
						return err
					}
				}
			}
		} else {
			//microlog.Debug("Hostname",hostPortURL.Hostname())
			isMatch := socks5ToHttp.cidrmatch.MatchWithTrie(hostPortURL.Hostname())
			microlog.Debug(runtime.NumGoroutine(), hostPortURL.Hostname(), isMatch, hostPortURL.Hostname())
			if isMatch {
				var dialer net.Dialer
				if socks5ToHttp.KeepAliveTimeout != 0 {
					dialer = net.Dialer{Timeout: socks5ToHttp.Timeout, KeepAlive: socks5ToHttp.KeepAliveTimeout}
				} else {
					dialer = net.Dialer{Timeout: socks5ToHttp.Timeout}
				}
				Conn, err = dialer.Dial("tcp", net.JoinHostPort(hostPortURL.Hostname(), domainPort))
				if err != nil {
					Conn, err = dialer.Dial("tcp", address)
					if err != nil {
						log.Println(err)
						return err
					}
				}
			} else {
				Conn, err = getSocks5Conn(socks5ToHttp.Socks5Server, socks5ToHttp.Socks5Port,
					socks5ToHttp.KeepAliveTimeout, net.JoinHostPort(hostPortURL.Hostname(), domainPort))
				if err != nil {
					// log.Println(err)
					microlog.Debug("..", hostPortURL.Hostname(), domainPort, "\n", err)
					return err
				}
			}
		}
	}
	defer Conn.Close()

	switch {
	case requestMethod == "CONNECT":
		//microlog.Debug(headerRequest)
		_, _ = HTTPConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	default:
		//microlog.Debug(headerRequest)
		if _, err := Conn.Write([]byte(headerRequest)); err != nil {
			return err
		}
	}

	ConnToHTTPConnCloseSig, HTTPConnToConnCloseSig := make(chan error, 1), make(chan error, 1)
	go pipe(Conn, HTTPConn, ConnToHTTPConnCloseSig)
	go pipe(HTTPConn, Conn, HTTPConnToConnCloseSig)
	<-ConnToHTTPConnCloseSig
	close(ConnToHTTPConnCloseSig)
	<-HTTPConnToConnCloseSig
	close(HTTPConnToConnCloseSig)
	return nil

	//go io.Copy(Conn, HTTPConn)
	//_, _ = io.Copy(HTTPConn, Conn)
	//return nil
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
