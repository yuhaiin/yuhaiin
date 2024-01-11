// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Request struct {
	Request         *http.Request
	SecWebSocketKey string
	Protocol        []string
	Header          http.Header
}

func NewServerConn(w http.ResponseWriter, req *http.Request, handshake func(*Request) error) (conn *Conn, err error) {
	var hs = &ServerHandshaker{
		Request: &Request{
			Request: req,
		},
	}
	code, err := hs.ReadHandshake(req)
	if err != nil {
		if err == ErrBadWebSocketVersion {
			w.Header().Set("Sec-WebSocket-Version", SupportedProtocolVersion)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	if handshake != nil {
		err = handshake(hs.Request)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	err = hs.AcceptHandshake(w)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rwc, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		err = fmt.Errorf("failed to hijack connection: %w", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, err
	}

	if err := buf.Writer.Flush(); err != nil {
		return nil, err
	}

	rwc, err = netapi.MergeBufioReaderConn(rwc, buf.Reader)
	if err != nil {
		return nil, err
	}

	PutBufioReader(buf.Reader)
	putBufioWriter(buf.Writer)

	return newConn(rwc, true), nil
}

// A HybiServerHandshaker performs a server handshake using hybi draft protocol.
type ServerHandshaker struct {
	*Request
}

func (c *ServerHandshaker) ReadHandshake(req *http.Request) (code int, err error) {
	if req.Method != "GET" {
		return http.StatusMethodNotAllowed, ErrBadRequestMethod
	}
	// HTTP version can be safely ignored.

	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || !strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return http.StatusBadRequest, ErrNotWebSocket
	}

	c.SecWebSocketKey = req.Header.Get("Sec-Websocket-Key")
	if c.SecWebSocketKey == "" {
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
		for _, v := range strings.Split(protocol, ",") {
			c.Protocol = append(c.Protocol, strings.TrimSpace(v))
		}
	}

	return http.StatusSwitchingProtocols, nil
}

func (c *ServerHandshaker) AcceptHandshake(w http.ResponseWriter) (err error) {
	if len(c.Protocol) > 0 && len(c.Protocol) != 1 {
		// You need choose a Protocol in Handshake func in Server.
		return ErrBadWebSocketProtocol
	}

	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", getNonceAccept(c.SecWebSocketKey))
	if len(c.Protocol) > 0 {
		w.Header().Set("Sec-WebSocket-Protocol", c.Protocol[0])
	}
	// TODO(ukai): send Sec-WebSocket-Extensions.
	if c.Header != nil {
		for k, v := range c.Header {
			if handshakeHeader[k] {
				continue
			}
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	return nil
}

func ServeHTTP(w http.ResponseWriter, req *http.Request, Handler func(context.Context, *Conn) error) error {
	conn, err := NewServerConn(w, req, nil)
	if err != nil {
		return err
	}
	return Handler(req.Context(), conn)
}
