package httpserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type Option struct {
	Username string
	Password string
}

func HTTPHandle(modeOption ...func(*Option)) func(net.Conn, func(string) (net.Conn, error)) {
	o := &Option{}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}
	return func(conn net.Conn, f func(string) (net.Conn, error)) {
		handle(o.Username, o.Password, conn, f)
	}
}

func handle(user, key string, src net.Conn, dst func(string) (net.Conn, error)) {
	/*
		use golang http
	*/
	inBoundReader := bufio.NewReader(src)
	req, err := http.ReadRequest(inBoundReader)
	if err != nil {
		if err != io.EOF {
			log.Println(err)
		}
		return
	}

	err = verifyUserPass(user, key, src, req)
	if err != nil {
		log.Println(err)
		return
	}

	host := bytes.NewBufferString(req.Host)
	if req.URL.Port() == "" {
		host.WriteString(":80")
	}

	dstc, err := dst(host.String())
	if err != nil {
		fmt.Println(err)
		//_, _ = src.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		//_, _ = src.Write([]byte("HTTP/1.1 408 Request Timeout\n\n"))
		_, _ = src.Write([]byte("HTTP/1.1 451 Unavailable For Legal Reasons\n\n"))
		return
	}
	switch dstc.(type) {
	case *net.TCPConn:
		_ = dstc.(*net.TCPConn).SetKeepAlive(true)
	}
	defer dstc.Close()

	if req.Method == http.MethodConnect {
		connect(src, dstc)
		return
	}

	normal(src, dstc, req, inBoundReader)
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

func connect(client net.Conn, dst net.Conn) {
	_, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println(err)
		return
	}
	utils.Forward(client, dst)
}

func normal(src, dst net.Conn, req *http.Request, in *bufio.Reader) {
	outboundReader := bufio.NewReader(dst)
	for {
		keepAlive := modifyRequest(req)
		err := req.Write(dst)
		if err != nil {
			break
		}
		resp, err := http.ReadResponse(outboundReader, req)
		if err != nil {
			break
		}
		err = modifyResponse(resp, keepAlive)
		if err != nil {
			break
		}
		err = resp.Write(src)
		if err != nil || resp.Close {
			break
		}
		// from clash, thanks so much, if not have the code, the ReadRequest will error
		err = utils.SingleForward(resp.Body, src)
		if err != nil && err != io.EOF {
			break
		}
		req, err = http.ReadRequest(in)
		if err != nil {
			break
		}
	}
}

func modifyRequest(req *http.Request) (keepAlive bool) {
	keepAlive = strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive" ||
		strings.TrimSpace(strings.ToLower(req.Header.Get("Connection"))) == "keep-alive"
	if len(req.URL.Host) > 0 {
		req.Host = req.URL.Host
	}
	req.RequestURI = ""
	req.Header.Set("Connection", "close")
	req.Header = removeHeader(req.Header)
	return
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
			//ErrUnsupportedTransferEncoding
			return errors.New("ErrUnsupportedTransferEncoding")
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
	return nil
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
