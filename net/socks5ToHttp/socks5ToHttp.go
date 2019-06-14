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
)

type errErr struct {
	err string
}

func (e errErr) Error() string {
	return fmt.Sprintf(e.err)
}

// Socks5ToHTTP like name
type Socks5ToHTTP struct {
	HTTPListener             net.Listener
	HTTPServer, HTTPPort     string
	Socks5Server, Socks5Port string
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (socks5ToHttp *Socks5ToHTTP) HTTPProxy() error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var err error
	socks5ToHttp.HTTPListener, err = net.Listen("tcp", socks5ToHttp.HTTPServer+":"+socks5ToHttp.HTTPPort)
	if err != nil {
		return err
	}
	for {
		HTTPConn, err := socks5ToHttp.HTTPListener.Accept()
		if err != nil {
			return err
		}
		go socks5ToHttp.httpHandleClientRequest(HTTPConn)
	}
}

func (socks5ToHttp *Socks5ToHTTP) httpHandleClientRequest(HTTPConn net.Conn) {
	if HTTPConn == nil {
		return
	}
	defer HTTPConn.Close()

	var requestData [1024 * 4]byte
	requestDataSize, err := HTTPConn.Read(requestData[:])
	if err != nil {
		log.Println("请求长度:", requestDataSize, err)
		return
	}
	log.Println("请求长度:", requestDataSize, "线程数:", runtime.NumGoroutine())
	// log.Println(string(b[:]))
	// log.Println([]byte("Proxy-Connection"))
	var method, host, address string
	// log.Println(b)
	var indexByte int
	if bytes.Contains(requestData[:], []byte("\n")) {
		indexByte = bytes.IndexByte(requestData[:], '\n')
	} else {
		log.Println("请求不完整")
		return
	}
	// if indexByte >= 3072 && indexByte < 0 {
	// 	log.Println("越界错误")
	// 	return
	// }
	log.Println(string(requestData[:indexByte]))
	_, err = fmt.Sscanf(string(requestData[:indexByte]), "%s%s", &method, &host)
	if err != nil {
		log.Println(err)
		return
	}

	var hostPortURL *url.URL
	if strings.Contains(host, "http://") || strings.Contains(host, "https://") {
		if hostPortURL, err = url.Parse(host); err != nil {
			log.Println(err)
			log.Println(string(requestData[:]))
			return
		}
	} else {
		hostPortURL, err = url.Parse("//" + host)
		if err != nil {
			log.Println(err)
			log.Println(string(requestData[:]))
			return
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
	// log.Println(address, method)
	socks5Conn, err := (&Socks5Client{
		Server:  socks5ToHttp.Socks5Server,
		Port:    socks5ToHttp.Socks5Port,
		Address: address}).NewSocks5Client()
	if err != nil {
		log.Println(err)
		return
	}
	defer socks5Conn.Close()

	socks5ToHttp.httpMethodAnalyze(method, address, hostPortURL, requestData[:],
		requestDataSize, socks5Conn, HTTPConn)

	// go func() {
	// 	for {
	// 		var socks5Data [1024 * 2]byte
	// 		n, err := socks5Conn.Read(socks5Data[:])
	// 		if err != nil {
	// 			return
	// 		}
	// 		HTTPConn.Write(socks5Data[:n])
	// 	}
	// }()
	// func() {
	// 	for {
	// 		var socks5Data [1024 * 2]byte
	// 		n, err := HTTPConn.Read(socks5Data[:])
	// 		if err != nil {
	// 			return
	// 		}
	// 		socks5Conn.Write(socks5Data[:n])
	// 	}
	// }()
	go io.Copy(socks5Conn, HTTPConn)
	io.Copy(HTTPConn, socks5Conn)
}

func (socks5ToHttp *Socks5ToHTTP) httpMethodAnalyze(method, address string, hostPortURL *url.URL,
	requestData []byte, requestDataSize int, socks5Conn, HTTPConn net.Conn) {
	if method == "CONNECT" {
		HTTPConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	} else if method == "GET" {
		log.Println(address, hostPortURL.Host)
		newBefore := bytes.ReplaceAll(requestData[:requestDataSize], []byte("http://"+address), []byte(""))
		newBefore = bytes.ReplaceAll(newBefore[:], []byte("http://"+hostPortURL.Host), []byte(""))
		var new []byte
		if bytes.Contains(newBefore[:], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(newBefore[:], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = newBefore
		}
		if _, err := socks5Conn.Write(new[:]); err != nil {
			log.Println(err)
			return
		}
	} else if method == "POST" {

		newBefore := bytes.ReplaceAll(requestData[:requestDataSize], []byte("http://"+address), []byte(""))
		newBefore = bytes.ReplaceAll(newBefore[:], []byte("http://"+hostPortURL.Host), []byte(""))
		// re, _ := regexp.Compile("User-Agent: .*\r\n")
		// newBefore = re.ReplaceAll(newBefore, []byte("Expect: 100-continue\r\n"))
		var new []byte
		if bytes.Contains(newBefore[:], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(newBefore[:], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = newBefore
		}
		if _, err := socks5Conn.Write(new[:]); err != nil {
			log.Println(err)
			return
		}
	} else {
		var new []byte
		if bytes.Contains(requestData[:requestDataSize], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(requestData[:requestDataSize], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = requestData[:requestDataSize]
		}
		if _, err := socks5Conn.Write(new[:]); err != nil {
			log.Println(err)
			return
		}
	}
}

// func main() {
// var test delay
// conn := test.creat_dial("127.0.0.1", "1080")
// err := test.socks5_first_verify(conn)
// if err != nil {
// 	log.Println(err)
// }
// err = test.socks5_second_verify(conn)
// if err != nil {
// 	log.Println(err)
// }
// err = test.socks5_send_and_read(conn)
// if err != nil {
// 	log.Println(err)
// }
// conn.Close()

// if err := Http("", "8081", "", "1080"); err != nil {
// 	log.Println(err)
// }

// test := 443
// fmt.Println(test >> 8)
// fmt.Println(test & 255)

// server := "google.com:443"

/* 判断是域名还是ip
s, err := url.Parse(server)
if err != nil {
	log.Println(err)
}
log.Println(s)
*/
// port := "443"
// serverB := []byte(server)
// portI, err := strconv.Atoi(port)
// if err != nil {
// 	fmt.Println(err)
// }
// sendData := []byte{0x5, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38}
// sendData := []byte{0x5, 0x01, 0x00, 0x03, byte(len(server))}
// sendData = append(sendData, serverB...)
// sendData = append(sendData, byte(portI>>8), byte(portI&255))
// log.Println(sendData)
// }

//
//
//
//
//
//
//
//
//
//
//
//
/*
func socks5_send_and_read(conn net.Conn) error {
	//进行数据请求
	re := "GET / HTTP/2.0\r\nHost: www.google.com\r\nConnection: close\r\nUser-agent: Mozilla/5.0\r\nAccept-Language: cn"
	_, err := conn.Write([]byte(re))
	if err != nil {
		fmt.Println(err)
		return err
	}
	var d [1024]byte

	temp := time.Now()
	_, err = conn.Read(d[:])
	if err != nil {
		fmt.Println(err)
		return err
	}
	delay := time.Since(temp)
	fmt.Println(delay)
	fmt.Println(string(d[:]))
	return nil
}
*/
// func Get_delay(local_server, local_port string) {
// 	var delay delay
// 	conn := delay.creat_dial(local_server, local_port)
// 	err := delay.socks5_first_verify(conn)
// 	if err != nil {
// 		log.Println("socks5 first verify error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	// err = delay.socks5_second_verify(conn)
// 	if err != nil {
// 		log.Println("socks5 second verify error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	err = delay.socks5_send_and_read(conn)
// 	if err != nil {
// 		log.Println("get delay last error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	conn.Close()
// }
