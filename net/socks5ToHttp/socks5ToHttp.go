package socks5ToHttp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	microlog "../../log"
	"../cidrmatch"
	"../dns"
)

type errErr struct {
	err string
}

func (e errErr) Error() string {
	return fmt.Sprintf(e.err)
}

// Socks5ToHTTP like name
type Socks5ToHTTP struct {
	ToHTTP       bool
	HTTPListener net.Listener
	HTTPServer   string
	HTTPPort     string
	Socks5Server string
	Socks5Port   string
	ByPass       bool
	cidrmatch    *cidrmatch.CidrMatch
	CidrFile     string
	DNSServer    string
	// dns          map[string]bool
	// dns      sync.Map
	dnscache dns.DnsCache
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (socks5ToHttp *Socks5ToHTTP) HTTPProxy() error {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	// socks5ToHttp.dns = map[string]bool{}
	socks5ToHttp.dnscache = dns.DnsCache{
		DNSServer: socks5ToHttp.DNSServer,
	}
	var err error
	if socks5ToHttp.ByPass == true {
		socks5ToHttp.cidrmatch, err = cidrmatch.NewCidrMatchWithMap(socks5ToHttp.CidrFile)
		if err != nil {
			return err
		}
	}
	socks5ToHttp.HTTPListener, err = net.Listen("tcp", socks5ToHttp.HTTPServer+":"+socks5ToHttp.HTTPPort)
	if err != nil {
		return err
	}
	for {
		HTTPConn, err := socks5ToHttp.HTTPListener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if HTTPConn == nil {
				return
			}
			defer HTTPConn.Close()
			// log.Println("线程数:", runtime.NumGoroutine())
			err := socks5ToHttp.httpHandleClientRequest(HTTPConn)
			if err != nil {
				// log.Println(err)
				microlog.Debug(err)
				return
			}
		}()
	}
}

func (socks5ToHttp *Socks5ToHTTP) httpHandleClientRequest(HTTPConn net.Conn) error {
	requestData := make([]byte, 1024*4)
	requestDataSize, err := HTTPConn.Read(requestData[:])
	if err != nil {
		return err
	}

	var indexByte int
	if bytes.Contains(requestData[:], []byte("\n")) {
		indexByte = bytes.IndexByte(requestData[:], '\n')
	} else {
		return errErr{"request not completely!"}
	}

	var method, host, address string
	// log.Println(string(requestData[:indexByte]))
	if _, err = fmt.Sscanf(string(requestData[:indexByte]), "%s%s", &method, &host); err != nil {
		return err
	}

	var hostPortURL *url.URL
	if strings.Contains(host, "http://") || strings.Contains(host, "https://") {
		if hostPortURL, err = url.Parse(host); err != nil {
			return err
		}
	} else {
		if hostPortURL, err = url.Parse("//" + host); err != nil {
			return err
		}
	}

	if hostPortURL.Opaque == "443" { //https访问
		address = hostPortURL.Scheme + ":443"
	} else { //http访问
		if strings.Index(hostPortURL.Host, ":") == -1 { //host不带端口， 默认80
			address = hostPortURL.Host + ":80"
		} else {
			address = hostPortURL.Host
		}
	}

	var Conn net.Conn
	switch socks5ToHttp.ByPass {
	case false:
		Conn, err = (&Socks5Client{
			Server:  socks5ToHttp.Socks5Server,
			Port:    socks5ToHttp.Socks5Port,
			Address: address}).NewSocks5Client()
		if err != nil {
			return err
		}
	case true:
		var hostTemplate string
		if net.ParseIP(hostPortURL.Hostname()) != nil {
			hostTemplate = "ip"
		}
		// var isMatched bool
		// if _, exist := socks5ToHttp.dns.Load(host); exist == false {
		// 	ip, isSuccess := dns.DNSv4(socks5ToHttp.DNSServer, hostPortURL.Hostname())
		// 	if isSuccess == true {
		// 		isMatched = socks5ToHttp.cidrmatch.MatchWithMap(ip[0])
		// 	} else {
		// 		isMatched = false
		// 	}

		// 	// if socks5ToHttp.dns. > 10000 {
		// 	// 	i := 0
		// 	// 	for key := range socks5ToHttp.dns {
		// 	// 		delete(socks5ToHttp.dns, key)
		// 	// 		i++
		// 	// 		if i > 0 {
		// 	// 			break
		// 	// 		}
		// 	// 	}
		// 	// }
		// 	// socks5ToHttp.dns[hostPortURL.Hostname()] = isMatched
		// 	socks5ToHttp.dns.Store(host, isMatched)
		// 	fmt.Println(runtime.NumGoroutine(), string(requestData[:indexByte-9]), isMatched)
		// } else {
		// 	// isMatched = socks5ToHttp.dns[hostPortURL.Hostname()]
		// 	isMatchedTmp, _ := socks5ToHttp.dns.Load(host)
		// 	isMatched = isMatchedTmp.(bool)
		// 	fmt.Println(runtime.NumGoroutine(), "use cache", string(requestData[:indexByte-9]), isMatched)
		// }

		isMatched := socks5ToHttp.dnscache.Match(hostPortURL.Hostname(), hostTemplate, socks5ToHttp.cidrmatch.MatchWithMap)
		if socks5ToHttp.ToHTTP == true && isMatched == false {
			Conn, err = (&Socks5Client{
				Server:  socks5ToHttp.Socks5Server,
				Port:    socks5ToHttp.Socks5Port,
				Address: address}).NewSocks5Client()
			if err != nil {
				// log.Println(err)
				microlog.Debug(err)
				return err
			}
		} else {
			Conn, err = net.Dial("tcp", address)
			if err != nil {
				return err
			}
		}
	}
	defer Conn.Close()

	switch {
	case method == "CONNECT":
		HTTPConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	case method == "GET" || method == "POST":
		new := requestData[:requestDataSize]
		if bytes.Contains(new[:], []byte("http://"+address)) {
			new = bytes.ReplaceAll(new[:], []byte("http://"+address), []byte(""))
		} else if bytes.Contains(new[:], []byte("http://"+hostPortURL.Host)) {
			new = bytes.ReplaceAll(new[:], []byte("http://"+hostPortURL.Host), []byte(""))
		}
		// re, _ := regexp.Compile("User-Agent: .*\r\n")
		// newBefore = re.ReplaceAll(newBefore, []byte("Expect: 100-continue\r\n"))
		// var new []byte
		if bytes.Contains(new[:], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(new[:], []byte("Proxy-Connection:"), []byte("Connection:"))
		}
		if _, err := Conn.Write(new[:]); err != nil {
			return err
		}
	// case method == "POST":
	// 	new := requestData[:requestDataSize]
	// 	if bytes.Contains(new[:], []byte("http://"+address)) {
	// 		new = bytes.ReplaceAll(new[:], []byte("http://"+address), []byte(""))
	// 	} else if bytes.Contains(new[:], []byte("http://"+hostPortURL.Host)) {
	// 		new = bytes.ReplaceAll(new[:], []byte("http://"+hostPortURL.Host), []byte(""))
	// 	}
	// 	// re, _ := regexp.Compile("User-Agent: .*\r\n")
	// 	// newBefore = re.ReplaceAll(newBefore, []byte("Expect: 100-continue\r\n"))
	// 	// var new []byte
	// 	if bytes.Contains(new[:], []byte("Proxy-Connection:")) {
	// 		new = bytes.ReplaceAll(new[:], []byte("Proxy-Connection:"), []byte("Connection:"))
	// 	}
	// 	if _, err := socks5Conn.Write(new[:]); err != nil {
	// 		return err
	// 	}
	default:
		if _, err := Conn.Write(requestData[:requestDataSize]); err != nil {
			return err
		}
	}

	go io.Copy(Conn, HTTPConn)
	io.Copy(HTTPConn, Conn)
	return nil
}
