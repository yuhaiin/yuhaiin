package socks5ToHttp

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"runtime"
	"strings"

	"../cidrmatch"
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
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (socks5ToHttp *Socks5ToHTTP) HTTPProxy() error {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
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
			log.Println("线程数:", runtime.NumGoroutine())
			err := socks5ToHttp.httpHandleClientRequest(HTTPConn)
			if err != nil {
				log.Println(err)
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
	log.Println(string(requestData[:indexByte]))
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
	// addressB, err := url.Parse("//" + address)
	// if err != nil {
	// 	return err
	// }
	// ip, err := net.LookupHost(hostPortURL.Hostname())
	// if err == nil && ip[0] != "0.0.0.0" {
	// 	address = ip[0] + ":" + addressB.Port()
	// 	log.Println(address)
	// }

	var socks5Conn net.Conn
	if socks5ToHttp.ByPass == false {
		socks5Conn, err = (&Socks5Client{
			Server:  socks5ToHttp.Socks5Server,
			Port:    socks5ToHttp.Socks5Port,
			Address: address}).NewSocks5Client()
		if err != nil {
			log.Println(err)
			return err
		}
	} else {
		ip, err := net.LookupHost(hostPortURL.Hostname())
		if err != nil {
			return err
		}
		var isMatched bool
		if len(ip) == 0 {
			isMatched = false
		} else {
			isMatched = socks5ToHttp.cidrmatch.MatchWithMap(ip[0])
		}
		log.Println("isMatched", isMatched)

		if socks5ToHttp.ToHTTP == true && isMatched == false {
			socks5Conn, err = (&Socks5Client{
				Server:  socks5ToHttp.Socks5Server,
				Port:    socks5ToHttp.Socks5Port,
				Address: address}).NewSocks5Client()
			if err != nil {
				log.Println(err)
				return err
			}
		} else {
			socks5Conn, err = net.Dial("tcp", address)
			if err != nil {
				log.Println(err)
				return err
			}
		}
	}
	defer socks5Conn.Close()

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
		if _, err := socks5Conn.Write(new[:]); err != nil {
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
		// var new []byte
		// if bytes.Contains(requestData[:requestDataSize], []byte("Proxy-Connection:")) {
		// 	new = bytes.ReplaceAll(requestData[:requestDataSize], []byte("Proxy-Connection:"), []byte("Connection:"))
		// } else {
		// 	new = requestData[:requestDataSize]
		// }
		// if _, err := socks5Conn.Write(new[:]); err != nil {
		// 	return err
		// }
		// log.Println(string(new))
		if _, err := socks5Conn.Write(requestData[:requestDataSize]); err != nil {
			return err
		}
	}

	// go func() {
	// 	for {
	// 		socks5Data := make([]byte, 1024*2)
	// 		n, err := socks5Conn.Read(socks5Data[:])
	// 		if err != nil {
	// 			return
	// 		}
	// 		HTTPConn.Write(socks5Data[:n])
	// 	}
	// }()
	// func() {
	// 	for {
	// 		socks5Data := make([]byte, 1024*2)
	// 		n, err := HTTPConn.Read(socks5Data[:])
	// 		if err != nil {
	// 			return
	// 		}
	// 		socks5Conn.Write(socks5Data[:n])
	// 	}
	// }()
	go io.Copy(socks5Conn, HTTPConn)
	io.Copy(HTTPConn, socks5Conn)
	return nil
}

// func (socks5ToHttp *Socks5ToHTTP) httpMethodAnalyze(method, address string, hostPortURL *url.URL,
// 	requestData []byte, requestDataSize int, socks5Conn, HTTPConn net.Conn) error {
// 	switch {
// 	case method == "CONNECT":
// 		HTTPConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
// 	case method == "GET" || method == "POST":
// 		new := requestData[:requestDataSize]
// 		if bytes.Contains(new[:], []byte("http://"+address)) {
// 			new = bytes.ReplaceAll(new[:], []byte("http://"+address), []byte(""))
// 		} else if bytes.Contains(new[:], []byte("http://"+hostPortURL.Host)) {
// 			new = bytes.ReplaceAll(new[:], []byte("http://"+hostPortURL.Host), []byte(""))
// 		}
// 		// re, _ := regexp.Compile("User-Agent: .*\r\n")
// 		// newBefore = re.ReplaceAll(newBefore, []byte("Expect: 100-continue\r\n"))
// 		// var new []byte
// 		if bytes.Contains(new[:], []byte("Proxy-Connection:")) {
// 			new = bytes.ReplaceAll(new[:], []byte("Proxy-Connection:"), []byte("Connection:"))
// 		}
// 		if _, err := socks5Conn.Write(new[:]); err != nil {
// 			return err
// 		}
// 	// case method == "POST":
// 	// 	new := requestData[:requestDataSize]
// 	// 	if bytes.Contains(new[:], []byte("http://"+address)) {
// 	// 		new = bytes.ReplaceAll(new[:], []byte("http://"+address), []byte(""))
// 	// 	} else if bytes.Contains(new[:], []byte("http://"+hostPortURL.Host)) {
// 	// 		new = bytes.ReplaceAll(new[:], []byte("http://"+hostPortURL.Host), []byte(""))
// 	// 	}
// 	// 	// re, _ := regexp.Compile("User-Agent: .*\r\n")
// 	// 	// newBefore = re.ReplaceAll(newBefore, []byte("Expect: 100-continue\r\n"))
// 	// 	// var new []byte
// 	// 	if bytes.Contains(new[:], []byte("Proxy-Connection:")) {
// 	// 		new = bytes.ReplaceAll(new[:], []byte("Proxy-Connection:"), []byte("Connection:"))
// 	// 	}
// 	// 	if _, err := socks5Conn.Write(new[:]); err != nil {
// 	// 		return err
// 	// 	}
// 	default:
// 		// var new []byte
// 		// if bytes.Contains(requestData[:requestDataSize], []byte("Proxy-Connection:")) {
// 		// 	new = bytes.ReplaceAll(requestData[:requestDataSize], []byte("Proxy-Connection:"), []byte("Connection:"))
// 		// } else {
// 		// 	new = requestData[:requestDataSize]
// 		// }
// 		// if _, err := socks5Conn.Write(new[:]); err != nil {
// 		// 	return err
// 		// }
// 		// log.Println(string(new))
// 		if _, err := socks5Conn.Write(requestData[:requestDataSize]); err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
