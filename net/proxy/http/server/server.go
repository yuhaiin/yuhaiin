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
	go func() {
		if err := s.HTTPProxy(); err != nil {
			log.Print(err)
			return
		}
	}()
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
func (h *Server) HTTPProxy() error {
	for {
		client, err := h.listener.Accept()
		if err != nil {
			if h.closed {
				break
			}
			continue
		}
		if err = client.(*net.TCPConn).SetKeepAlive(true); err != nil {
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
	}
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

	server, err := common.ForwardTarget(req.Host)
	if err != nil {
		_, err = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return err
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
