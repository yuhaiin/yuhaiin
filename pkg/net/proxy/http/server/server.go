package httpserver

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Option struct {
	Username string
	Password string
}

func handshake(modeOption ...func(*Option)) func(net.Conn, proxy.Proxy) {
	o := &Option{}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}
	return func(conn net.Conn, f proxy.Proxy) {
		err := handle(o.Username, o.Password, conn, f)
		if err != nil {
			logasfmt.Println("http server handle failed:", err)
		}
	}
}

func handle(user, key string, src net.Conn, f proxy.Proxy) error {
	/*
		use golang http
	*/
	defer src.Close()
	inBoundReader := bufio.NewReader(src)

_start:
	req, err := http.ReadRequest(inBoundReader)
	if err != nil {
		return fmt.Errorf("read request failed: %v", err)
	}

	err = verifyUserPass(user, key, src, req)
	if err != nil {
		return fmt.Errorf("http verify user pass failed: %v", err)
	}

	host := req.Host
	if req.URL.Port() == "" {
		if strings.EqualFold(req.URL.Scheme, "https") {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}

	dstc, err := f.Conn(host)
	if err != nil {
		// _, _ = src.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		er := resp503(src)
		if er != nil {
			return fmt.Errorf("resp 503 failed: %v", er)
		}
		// _, _ = src.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		//_, _ = src.Write([]byte("HTTP/1.1 408 Request Timeout\n\n"))
		// _, _ = src.Write([]byte("HTTP/1.1 451 Unavailable For Legal Reasons\n\n"))
		return fmt.Errorf("get conn from proxy failed: %v", err)
	}

	if req.Method == http.MethodConnect {
		return connect(src, dstc)
	}

	keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive"

	err = normal(src, dstc, req, keepAlive)
	if err != nil {
		return fmt.Errorf("http normal proxy failed: %v", err)
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

func connect(client net.Conn, dst net.Conn) error {
	defer dst.Close()
	_, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("write to client failed: %v", err)
	}
	utils.Forward(dst, client)
	return nil
}

func normal(src, dst net.Conn, req *http.Request, keepAlive bool) error {
	defer dst.Close()
	modifyRequest(req)
	err := req.Write(dst)
	if err != nil {
		return fmt.Errorf("req write failed: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(dst), req)
	if err != nil {
		return fmt.Errorf("http read response failed: %v", err)
	}
	defer resp.Body.Close()

	err = modifyResponse(resp, keepAlive)
	if err != nil {
		return fmt.Errorf("modify response failed: %v", err)
	}

	err = resp.Write(src)
	if err != nil {
		return fmt.Errorf("resp write failed: %v", err)
	}

	return nil
}

func modifyRequest(req *http.Request) {
	if len(req.URL.Host) > 0 {
		req.Host = req.URL.Host
	}
	req.RequestURI = ""
	req.Header.Set("Connection", "close")
	req.Header = removeHeader(req.Header)
}

func modifyResponse(resp *http.Response, keepAlive bool) error {
	resp.Header = removeHeader(resp.Header)
	if resp.ContentLength >= 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	} else {
		resp.Header.Del("Content-Length")
	}

	te := ""
	if len(resp.TransferEncoding) > 0 {
		if len(resp.TransferEncoding) > 1 {
			// ErrUnsupportedTransferEncoding
			return errors.New("ErrUnsupportedTransferEncoding")
		}
		te = resp.TransferEncoding[0]
	}
	resp.Close = true
	if keepAlive && (resp.ContentLength >= 0 || te == "chunked") {
		resp.Header.Set("Proxy-Connection", "keep-alive")
		resp.Header.Set("Connection", "Keep-Alive")
		resp.Header.Set("Keep-Alive", "timeout=4")
		resp.Close = false
	}
	return nil
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

func NewServer(host, username, password string) (proxy.Server, error) {
	return proxy.NewTCPServer(host, proxy.TCPWithHandle(handshake(func(o *Option) {
		o.Password = password
		o.Username = username
	})))
}
