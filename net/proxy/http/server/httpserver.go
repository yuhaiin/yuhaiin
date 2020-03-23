package httpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Server http server
type Server struct {
	Listener    net.Listener
	Server      string
	Port        string
	Username    string
	Password    string
	ForwardFunc func(host string) (net.Conn, error)
	context     context.Context
	cancel      context.CancelFunc
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
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	h.cancel()
	return h.Listener.Close()
}

func (h *Server) httpProxyAcceptARequest() error {
	client, err := h.Listener.Accept()
	if err != nil {
		return err
	}
	if err := client.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return err
	}

	go func() {
		if client == nil {
			return
		}
		defer func() {
			_ = client.Close()
		}()
		if err := h.httpHandleClientRequest(client); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF && err != io.ErrClosedPipe {
				log.Println(err)
			}
		}
	}()
	return nil
}

// HTTPProxy http proxy
// server http listen server,port http listen port
// sock5Server socks5 server ip,socks5Port socks5 server port
func (h *Server) HTTPProxy() error {
	h.context, h.cancel = context.WithCancel(context.Background())
	var err error
	h.Listener, err = net.Listen("tcp", net.JoinHostPort(h.Server, h.Port))
	if err != nil {
		return err
	}
	for {
		select {
		case <-h.context.Done():
			return nil
		default:
			if err := h.httpProxyAcceptARequest(); err != nil {
				select {
				case <-h.context.Done():
					return err
				default:
					log.Println(err)
					continue
				}
			}
		}
	}
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
	//host := req.Host

	if h.Username != "" || h.Password != "" {
		authorization := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
		if len(authorization) != 2 {
			_, err = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			if err != nil {
				return err
			}
			client.Close()
		}
		var dst []byte
		_, err := base64.StdEncoding.Decode(dst, []byte(authorization[1]))
		if err != nil {
			return err
		}
		uap := bytes.Split(dst, []byte(":"))
		if len(uap) != 2 {
			if _, err := client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n")); err != nil {
				return err
			}
			client.Close()
		}
		if string(uap[0]) != h.Username || string(uap[1]) != h.Password {
			if _, err := client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n")); err != nil {
				return err
			}
			client.Close()
		}
	}

	var server net.Conn
	if h.ForwardFunc != nil {
		if server, err = h.ForwardFunc(req.Host); err != nil {
			return err
		}
	} else {
		if server, err = net.DialTimeout("tcp", req.Host, 5*time.Second); err != nil {
			return err
		}
	}
	defer func() {
		_ = server.Close()
	}()

	outboundReader := bufio.NewReader(server)

	switch req.Method {
	case http.MethodConnect:
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return err
		}
		forward(server, client)
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
			return errors.New("RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy")
		}
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
	//if connection := h.Get("Proxy-Connection"); connection != "" {
	//	h.Set("Connection", h.Get("Proxy-Connection"))
	//}
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailers")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
	return h
}
func forward(server, client net.Conn) {
	CloseSig := make(chan error, 0)
	go pipe(server, client, CloseSig)
	go pipe(client, server, CloseSig)
	<-CloseSig
	<-CloseSig
	close(CloseSig)
}

func pipe(src, dst net.Conn, closeSig chan error) {
	buf := make([]byte, 0x400*4)
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

func (h *Server) httpHandleClientRequest2(client net.Conn) error {
	/*
		use golang http
	*/
	//ss, _ := http.ReadRequest(bufio.NewReader(client))
	//log.Println("header",ss.Header)
	//log.Println("method",ss.Method)
	//if ss.Method == http.MethodConnect{
	//	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil{
	//		return err
	//	}
	//}
	//log.Println("form",ss.Form)

	requestData := make([]byte, 1024*4)
	requestDataSize, err := client.Read(requestData[:])
	if err != nil {
		return err
	}
	if requestDataSize <= 3 {
		return nil
	}
	headerAndData := strings.Split(string(requestData[:requestDataSize]), "\r\n\r\n")
	var header, data strings.Builder
	if len(headerAndData) > 0 {
		header.WriteString(headerAndData[0])
		if len(headerAndData) > 1 {
			data.WriteString(headerAndData[1])
		}
	} else {
		return errors.New("no header")
	}

	/*
		parse request header
	*/
	headerTmp := strings.Split(header.String(), "\r\n")
	headerArgs := make(map[string]string)
	for index, line := range headerTmp {
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

	headerRequestSplit := strings.Split(headerTmp[0], " ")
	requestMethod := headerRequestSplit[0]
	if requestMethod == "CONNECT" {
		headerArgs["Host"] = headerRequestSplit[1]
	}
	/*
		parse request host and port
	*/
	hostPortURL, err := url.Parse("//" + headerArgs["Host"])
	if err != nil {
		return err
	}
	var headerRequest strings.Builder
	headerRequest.WriteString(strings.ReplaceAll(headerTmp[0], "http://"+hostPortURL.Host, ""))
	if hostPortURL.Port() == "" {
		hostPortURL.Host = hostPortURL.Host + ":80"
	}
	//microlog.Debug(headerArgs)
	//microlog.Debug("requestMethod:",requestMethod)
	//microlog.Debug("headerRequest ",headerRequest,"headerRequest end")
	for key, value := range headerArgs {
		headerRequest.WriteString("\r\n" + key + ": " + value)
	}
	headerRequest.WriteString("\r\n\r\n" + data.String())
	//log.Println(headerRequest.String())
	var server net.Conn
	if h.ForwardFunc != nil {
		server, err = h.ForwardFunc(hostPortURL.Host)
		if err != nil {
			return err
		}
	} else {
		server, err = net.Dial("tcp", hostPortURL.Host)
		if err != nil {
			return err
		}
	}
	defer func() {
		_ = server.Close()
	}()

	switch {
	case requestMethod == "CONNECT":
		if _, err = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return err
		}
	default:
		if _, err := server.Write([]byte(headerRequest.String())); err != nil {
			return err
		}
	}

	forward(server, client)
	return nil
}
