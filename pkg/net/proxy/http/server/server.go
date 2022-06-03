package httpserver

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func handshake(dialer proxy.StreamProxy, username, password string) func(net.Conn) {
	return func(conn net.Conn) {
		dialer := func(addr string) (net.Conn, error) {
			address, err := proxy.ParseAddress("tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}
			return dialer.Conn(address)
		}
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer(addr)
				},
			},

			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		err := handle(username, password, conn, dialer, client)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Println("http server handle failed:", err)
		}
	}
}

func handle(user, key string, src net.Conn, dialer func(string) (net.Conn, error), client *http.Client) error {
	/*
		use golang http
	*/
	defer src.Close()
	reader := bufio.NewReader(src)

_start:
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read request failed: %w", err)
	}

	err = verifyUserPass(user, key, src, req)
	if err != nil {
		return fmt.Errorf("http verify user pass failed: %w", err)
	}

	if req.Method == http.MethodConnect {
		return connect(src, dialer, req)
	}

	keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive"

	if err = normal(src, client, req, keepAlive); err != nil {
		// only have resp write error
		return nil
	}

	if keepAlive {
		goto _start
	}

	return nil
}

func verifyUserPass(user, key string, client net.Conn, req *http.Request) error {
	if user == "" || key == "" {
		return nil
	}
	username, password, isHas := parseBasicAuth(req.Header.Get("Proxy-Authorization"))
	if !isHas {
		_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
		return errors.New("proxy Authentication Required")
	}
	if username != user || password != key {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return errors.New("user or password verify failed")
	}
	return nil
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

func connect(client net.Conn, f func(string) (net.Conn, error), req *http.Request) error {
	host := req.URL.Host
	if req.URL.Port() == "" {
		host = net.JoinHostPort(host, "80")
	}

	dst, err := f(host)
	if err != nil {
		// _, _ = src.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		er := resp503(client)
		if er != nil {
			err = fmt.Errorf("%v\nresp 503 failed: %w", err, er)
		}
		// _, _ = src.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		//_, _ = src.Write([]byte("HTTP/1.1 408 Request Timeout\n\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 451 Unavailable For Legal Reasons\n\n"))
		return fmt.Errorf("get conn [%s] from proxy failed: %w", host, err)
	}
	defer dst.Close()

	_, err = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("write to client failed: %w", err)
	}
	utils.Relay(dst, client)
	return nil
}

func normal(src net.Conn, client *http.Client, req *http.Request, keepAlive bool) error {
	modifyRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("http client do failed: %v\n", err)
		resp = resp502(src)
	} else {
		modifyResponse(resp, keepAlive)
	}

	err = resp.Write(src)
	if err != nil {
		return fmt.Errorf("resp write failed: %w", err)
	}

	return nil
}

func modifyRequest(req *http.Request) {
	if len(req.URL.Host) > 0 {
		req.Host = req.URL.Host
	}

	// Prevent UA from being set to golang's default ones
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "")
	}

	req.RequestURI = ""
	req.Header.Set("Connection", "close")
	removeHeader(req.Header)
}

func modifyResponse(resp *http.Response, keepAlive bool) {
	removeHeader(resp.Header)

	resp.Close = true
	if keepAlive && (resp.ContentLength >= 0) {
		resp.Header.Set("Proxy-Connection", "keep-alive")
		resp.Header.Set("Connection", "Keep-Alive")
		resp.Header.Set("Keep-Alive", "timeout=4")
		resp.Close = false
	}
}

// https://github.com/go-httpproxy

func resp503(dst net.Conn) error {
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
	return resp.Write(dst)
}

func resp400(dst net.Conn) error {
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
	return response.Write(dst)
}

func resp502(dst net.Conn) *http.Response {
	// RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
	response := &http.Response{
		Status:        "Bad Request",
		StatusCode:    http.StatusBadGateway,
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
	return response
}

func removeHeader(h http.Header) {
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
}

func NewServer(host, username, password string, dialer proxy.StreamProxy) (iserver.Server, error) {
	return server.NewTCPServer(host, handshake(dialer, username, password))
}
