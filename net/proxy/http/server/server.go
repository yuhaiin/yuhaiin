package httpserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"github.com/Asutorufa/yuhaiin/net/common"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Server http server
type Server struct {
	Username string
	Password string
	listener net.Listener
	closed   bool
}

// NewHTTPServer create new HTTP server
// host: http listener host
// port: http listener port
// username: http server username
// password: http server password
func NewHTTPServer(host, port, username, password string) (s *Server, err error) {
	s = &Server{}
	s.listener, err = net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	s.Username, s.Password = username, password
	go func() { s.HTTPProxy() }()
	return s, nil
}

func (h *Server) UpdateListenHost(host, port string) (err error) {
	if h.listener.Addr().String() == net.JoinHostPort(host, port) {
		return nil
	}
	if err = h.listener.Close(); err != nil {
		return err
	}
	h.listener, err = net.Listen("tcp", net.JoinHostPort(host, port))
	return
}

func (h *Server) GetListenHost() string {
	return h.listener.Addr().String()
}

// Close close http server listener
func (h *Server) Close() error {
	h.closed = true
	return h.listener.Close()
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (h *Server) HTTPProxy() {
	for {
		client, err := h.listener.Accept()
		if err != nil {
			if h.closed {
				break
			}
			continue
		}
		_ = client.(*net.TCPConn).SetKeepAlive(true)

		go func() {
			defer client.Close()
			h.httpHandleClientRequest(client)
		}()
	}
}

func (h *Server) httpHandleClientRequest(client net.Conn) {
	/*
		use golang http
	*/
	inBoundReader := bufio.NewReader(client)
	req, err := http.ReadRequest(inBoundReader)
	if err != nil {
		log.Println(err)
		return
	}

	if h.Username != "" {
		authorization := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
		if len(authorization) != 2 {
			_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			return
		}
		dst := make([]byte, base64.URLEncoding.DecodedLen(len(authorization[1])))
		if _, err = base64.StdEncoding.Decode(dst, []byte(authorization[1])); err != nil {
			log.Println(err)
			return
		}
		uap := bytes.Split(dst, []byte(":"))
		if len(uap) != 2 {
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
		if string(uap[0]) != h.Username || string(uap[1]) != h.Password {
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	host := req.Host
	if req.URL.Port() == "" {
		host = req.Host + ":80"
	}

	server, err := common.ForwardTarget(host)
	if err != nil {
		log.Println(host, err)
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}
	defer server.Close()

	if req.Method == http.MethodConnect {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			log.Println(err)
			return
		}
		common.Forward(client, server)
		return
	}

	outboundReader := bufio.NewReader(server)
	for {
		//log.Println(req.Header)
		//log.Println(req.Header.Get("Proxy-Connection"), ":", req.Header.Get("Connection"))
		keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive" || strings.TrimSpace(strings.ToLower(req.Header.Get("Connection"))) == "keep-alive"
		if len(req.URL.Host) > 0 {
			req.Host = req.URL.Host
		}
		//req.URL.Host = ""
		//req.URL.Scheme = ""
		req.RequestURI = ""
		req.Header.Set("Connection", "close")
		req.Header = removeHeader(req.Header)
		//log.Println(req.Header,req.Body)
		if err := req.Write(server); err != nil {
			break
		}

		resp, err := http.ReadResponse(outboundReader, req)
		if err != nil {
			//log.Println(err)
			//resp503(client)
			break
		}
		resp.Header = removeHeader(resp.Header)
		if resp.ContentLength >= 0 {
			resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		} else {
			resp.Header.Del("Content-Length")
		}

		te := ""
		if len(resp.TransferEncoding) > 0 {
			if len(resp.TransferEncoding) > 1 {
				//ErrUnsupportedTransferEncoding
				break
			}
			te = resp.TransferEncoding[0]
		}
		if keepAlive && (resp.ContentLength >= 0 || te == "chunked") {
			resp.Header.Set("Connection", "Keep-Alive")
			//resp.Header.Set("Keep-Alive", "timeout=4")
			resp.Close = false
		} else {
			resp.Close = true
		}
		//log.Println(resp.Header, resp.Body)
		err = resp.Write(client)
		if err != nil || resp.Close {
			break
		}

		// from clash, thanks so much, if not have the code, the ReadRequest will error
		buf := common.BuffPool.Get().([]byte)
		_, err = io.CopyBuffer(client, resp.Body, buf)
		common.BuffPool.Put(buf[:cap(buf)])
		if err != nil && err != io.EOF {
			break
		}

		req, err = http.ReadRequest(inBoundReader)
		if err != nil {
			break
		}
	}
}

// https://github.com/go-httpproxy

func resp503(dst net.Conn) {
	resp := &http.Response{
		Status:        "Service Unavailable",
		StatusCode:    503,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(map[string][]string),
		Body:          nil,
		ContentLength: 0,
		Close:         true,
	}
	resp.Header.Set("Connection", "close")
	resp.Header.Set("Proxy-Connection", "close")
	_ = resp.Write(dst)
}

func resp400(dst net.Conn) {
	// RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
	response := &http.Response{
		Status:        "Bad Request",
		StatusCode:    400,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header(make(map[string][]string)),
		Body:          nil,
		ContentLength: 0,
		Close:         true,
	}
	response.Header.Set("Proxy-Connection", "close")
	response.Header.Set("Connection", "close")
	_ = response.Write(dst)
}

func removeHeader(h http.Header) http.Header {
	connections := h.Get("Connection")
	h.Del("Connection")
	if len(connections) != 0 {
		for _, x := range strings.Split(connections, ",") {
			h.Del(strings.TrimSpace(x))
		}
	}
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailers")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
	return h
}