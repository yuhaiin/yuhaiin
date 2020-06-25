package httpserver

import (
	"bufio"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/net/proxy/interfaces"

	"github.com/Asutorufa/yuhaiin/net/common"
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
func NewHTTPServer(host, username, password string) (interfaces.Server, error) {
	s := &Server{Username: username, Password: password}
	if host == "" {
		return s, nil
	}
	err := s.HTTPProxy(host)
	return s, err
}

func (h *Server) UpdateListen(host string) (err error) {
	//log.Println(host)
	if h.closed {
		if host == "" {
			return nil
		}
		h.closed = false
		return h.HTTPProxy(host)
	}

	if host == "" {
		return h.Close()
	}

	if h.listener.Addr().String() == host {
		return nil
	}

	if err = h.listener.Close(); err != nil {
		return err
	}
	h.listener, err = net.Listen("tcp", host)
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
func (h *Server) HTTPProxy(host string) (err error) {
	h.listener, err = net.Listen("tcp", host)
	if err != nil {
		return
	}
	go func() {
		for {
			client, err := h.listener.Accept()
			if err != nil {
				if h.closed {
					break
				}
				//log.Println(err)
				continue
			}
			_ = client.(*net.TCPConn).SetKeepAlive(true)

			go func() {
				defer client.Close()
				h.httpHandleClientRequest(client)
			}()
		}
	}()
	return
}

func (h *Server) httpHandleClientRequest(client net.Conn) {
	/*
		use golang http
	*/
	inBoundReader := bufio.NewReader(client)
	req, err := http.ReadRequest(inBoundReader)
	if err != nil {
		//log.Println(err)
		return
	}

	if h.Username != "" || h.Password != "" {
		user, pass, isHas := parseBasicAuth(req.Header.Get("Proxy-Authorization"))
		if !isHas {
			_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			return
		}
		if user != h.Username || pass != h.Password {
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	//log.Println("host", req.Host)
	host := req.Host
	if req.URL.Port() == "" {
		host = req.Host + ":80"
	}

	server, err := common.ForwardTarget(host)
	if err != nil {
		//log.Println(err)
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
		keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive" || strings.TrimSpace(strings.ToLower(req.Header.Get("Connection"))) == "keep-alive"
		if len(req.URL.Host) > 0 {
			req.Host = req.URL.Host
		}
		req.RequestURI = ""
		req.Header.Set("Connection", "close")
		req.Header = removeHeader(req.Header)
		if err := req.Write(server); err != nil {
			break
		}

		resp, err := http.ReadResponse(outboundReader, req)
		if err != nil {
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
		err = resp.Write(client)
		if err != nil || resp.Close {
			break
		}

		// from clash, thanks so much, if not have the code, the ReadRequest will error
		//buf := common.BuffPool.Get().([]byte)
		//_, err = io.CopyBuffer(client, resp.Body, buf)
		//common.BuffPool.Put(buf[:cap(buf)])
		err = common.SingleForward(resp.Body, client)
		if err != nil && err != io.EOF {
			break
		}

		req, err = http.ReadRequest(inBoundReader)
		if err != nil {
			break
		}
	}
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
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
