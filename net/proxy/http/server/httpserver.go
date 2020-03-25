package httpserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"github.com/Asutorufa/yuhaiin/net/common"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Server http server
type Server struct {
	Server      string
	Port        string
	Username    string
	Password    string
	ForwardFunc func(host string) (net.Conn, error)
	listener    net.Listener
	closed      bool
}

// NewHTTPServer create new HTTP server
// server: http listener host
// port: http listener port
// username: http server username
// password: http server password
// forwardTo: if you want to forward to another server,create a function that return net.Conn and use it,if not use nil
func NewHTTPServer(server, port, username, password string, forwardFunc func(host string) (net.Conn, error)) (*Server, error) {
	return &Server{
		Server:      server,
		Port:        port,
		Username:    username,
		Password:    password,
		ForwardFunc: forwardFunc,
	}, nil
}

// Close close http server listener
func (h *Server) Close() error {
	h.closed = true
	return h.listener.Close()
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (h *Server) HTTPProxy() error {
	var err error
	h.listener, err = net.Listen("tcp", net.JoinHostPort(h.Server, h.Port))
	if err != nil {
		return err
	}
	for {
		if err := h.httpProxyAcceptARequest(); err != nil {
			if h.closed {
				break
			}
			continue
		}
	}
	return nil
}

func (h *Server) httpProxyAcceptARequest() error {
	client, err := h.listener.Accept()
	if err != nil {
		return err
	}
	if err := client.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return err
	}

	go func() {
		defer func() {
			_ = client.Close()
		}()
		if err := h.httpHandleClientRequest(client); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF && err != io.ErrClosedPipe {
				//log.Println(err)
				return
			}
		}
	}()
	return nil
}

func (h *Server) httpHandleClientRequest(client net.Conn) error {
	/*
		use golang http
	*/
	inBoundReader := bufio.NewReader(client)
	req, err := http.ReadRequest(inBoundReader)
	if err != nil {
		return err
	}

	if h.Username != "" {
		authorization := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
		if len(authorization) != 2 {
			_, err = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			return err
		}
		dst := make([]byte, base64.URLEncoding.DecodedLen(len(authorization[1])))
		_, err = base64.StdEncoding.Decode(dst, []byte(authorization[1]))
		if err != nil {
			return err
		}
		uap := bytes.Split(dst, []byte(":"))
		if len(uap) != 2 {
			_, err = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return err
		}
		if string(uap[0]) != h.Username || string(uap[1]) != h.Password {
			_, err = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return err
		}
	}

	var server net.Conn
	if h.ForwardFunc != nil {
		if server, err = h.ForwardFunc(req.Host); err != nil {
			_, err = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return err
		}
	} else {
		if server, err = net.DialTimeout("tcp", req.Host, 5*time.Second); err != nil {
			_, err = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return err
		}
	}
	defer func() {
		_ = server.Close()
	}()

	switch req.Method {
	case http.MethodConnect:
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return err
		}
		common.Forward(client, server)
	default:
		if req.URL.Host == "" {
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
			return response.Write(client)
			//return errors.New("RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy")
		}
		outboundReader := bufio.NewReader(server)
		for {
			keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive"
			if len(req.URL.Host) > 0 {
				req.Host = req.URL.Host
			}
			//req.URL.Host = ""
			//req.URL.Scheme = ""
			req.Header.Set("Connection", "close")
			req.Header = removeHeader(req.Header)
			if err := req.Write(server); err != nil {
				return err
			}

			resp, err := http.ReadResponse(outboundReader, req)
			if err != nil {
				resp = &http.Response{
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
				return resp.Write(client)
			}
			if keepAlive || resp.ContentLength >= 0 {
				resp.Header.Set("Proxy-Connection", "keep-alive")
				resp.Header.Set("Connection", "keep-alive")
				resp.Header.Set("Keep-Alive", "timeout=4")
				resp.Close = false
			} else {
				resp.Close = true
			}
			resp.Header = removeHeader(resp.Header)
			err = resp.Write(client)
			if err != nil || resp.Close {
				//return err
				break
			}
			req, err = http.ReadRequest(inBoundReader)
			if err != nil {
				return err
			}
		}
	}
	return nil
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
