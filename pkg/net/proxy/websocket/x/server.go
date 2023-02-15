// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func NewServerConn(rwc net.Conn, buf *bufio.ReadWriter, req *http.Request, handshake func(*http.Request) error) (conn *Conn, err error) {
	var hs = &ServerHandshaker{}
	code, err := hs.ReadHandshake(buf.Reader, req)
	if err != nil {
		fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n", code, http.StatusText(code))
		if err == ErrBadWebSocketVersion {
			fmt.Fprintf(buf, "Sec-WebSocket-Version: %s\r\n", SupportedProtocolVersion)
		}
		buf.WriteString("\r\n")
		buf.WriteString(err.Error())
		buf.Flush()
		return
	}

	if handshake != nil {
		err = handshake(req)
		if err != nil {
			fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n\r\n", http.StatusForbidden, http.StatusText(http.StatusForbidden))
			buf.Flush()
			return
		}
	}
	err = hs.AcceptHandshake(buf.Writer)
	if err != nil {
		fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n\r\n", http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		buf.Flush()
		return
	}
	conn = newHybiConn(buf, rwc, req)
	return
}

// A HybiServerHandshaker performs a server handshake using hybi draft protocol.
type ServerHandshaker struct {
	Header   http.Header
	Protocol []string
	accept   []byte
}

func (c *ServerHandshaker) ReadHandshake(buf *bufio.Reader, req *http.Request) (code int, err error) {
	if req.Method != "GET" {
		return http.StatusMethodNotAllowed, ErrBadRequestMethod
	}
	// HTTP version can be safely ignored.

	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || !strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return http.StatusBadRequest, ErrNotWebSocket
	}

	key := req.Header.Get("Sec-Websocket-Key")
	if key == "" {
		return http.StatusBadRequest, ErrChallengeResponse
	}

	version := req.Header.Get("Sec-Websocket-Version")
	switch version {
	case SupportedProtocolVersion:
	default:
		return http.StatusBadRequest, ErrBadWebSocketVersion
	}

	protocol := strings.TrimSpace(req.Header.Get("Sec-Websocket-Protocol"))
	if protocol != "" {
		protocols := strings.Split(protocol, ",")
		for i := 0; i < len(protocols); i++ {
			c.Protocol = append(c.Protocol, strings.TrimSpace(protocols[i]))
		}
	}
	c.accept, err = getNonceAccept([]byte(key))
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusSwitchingProtocols, nil
}

func (c *ServerHandshaker) AcceptHandshake(buf *bufio.Writer) (err error) {
	if len(c.Protocol) > 0 && len(c.Protocol) != 1 {
		// You need choose a Protocol in Handshake func in Server.
		return ErrBadWebSocketProtocol
	}

	buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(buf, "Sec-WebSocket-Accept: %s\r\n", string(c.accept))
	if len(c.Protocol) > 0 {
		fmt.Fprintf(buf, "Sec-WebSocket-Protocol: %s\r\n", c.Protocol[0])
	}
	// TODO(ukai): send Sec-WebSocket-Extensions.
	if c.Header != nil {
		err := c.Header.WriteSubset(buf, handshakeHeader)
		if err != nil {
			return err
		}
	}
	buf.WriteString("\r\n")
	return buf.Flush()
}
