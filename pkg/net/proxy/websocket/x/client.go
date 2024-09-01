// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Config is a WebSocket configuration
type Config struct {
	Host string
	Path string

	// A Websocket client origin.
	OriginUrl string // eg: http://example.com/from/ws

	// WebSocket subprotocols.
	Protocol []string
}

// NewClient creates a new WebSocket client connection over rwc.
func (config *Config) NewClient(SecWebSocketKey string, rwc net.Conn, request func(*http.Request) error, handshake func(*http.Response) error) (ws *Conn, err error) {
	rwc, err = config.hybiClientHandshake(SecWebSocketKey, rwc, request, handshake)
	if err != nil {
		return
	}
	ws = newConn(rwc, false)
	return
}

//go:linkname putBufioWriter net/http.putBufioWriter
func putBufioWriter(br *bufio.Writer)

// Client handshake described in draft-ietf-hybi-thewebsocket-protocol-17
func (config *Config) hybiClientHandshake(SecWebSocketKey string, conn net.Conn, request func(*http.Request) error, handshake func(*http.Response) error) (net.Conn, error) {
	var nonce string
	if SecWebSocketKey != "" {
		nonce = SecWebSocketKey
	} else {
		nonce = generateNonce()
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+config.Host+config.Path, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if config.OriginUrl != "" {
		req.Header.Set("Origin", config.OriginUrl)
	}
	req.Header.Set("Sec-WebSocket-Key", nonce)
	req.Header.Set("Sec-WebSocket-Version", SupportedProtocolVersion)
	for _, p := range config.Protocol {
		req.Header.Add("Sec-WebSocket-Protocol", p)
	}
	if request != nil {
		if err := request(req); err != nil {
			return nil, err
		}
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reader := pool.NewBufioConnSize(conn, pool.DefaultSize)

	err = reader.BufioRead(func(r *bufio.Reader) error {
		resp, err := http.ReadResponse(r, req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusSwitchingProtocols {
			return ErrBadStatus
		}

		if strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" || strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
			return ErrBadUpgrade
		}

		if resp.Header.Get("Sec-WebSocket-Accept") != getNonceAccept(nonce) {
			return ErrChallengeResponse
		}

		if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
			return ErrUnsupportedExtensions
		}

		if err = verifySubprotocol(config.Protocol, resp); err != nil {
			return err
		}

		if handshake != nil {
			if err = handshake(resp); err != nil {
				return err
			}
		}

		return nil
	})

	return reader, err
}

func verifySubprotocol(subprotos []string, resp *http.Response) error {
	proto := resp.Header.Get("Sec-WebSocket-Protocol")
	if proto == "" {
		return nil
	}

	for _, sp2 := range subprotos {
		if strings.EqualFold(sp2, proto) {
			return nil
		}
	}

	return fmt.Errorf("WebSocket protocol violation: unexpected Sec-WebSocket-Protocol from server: %q", proto)
}

// generateNonce generates a nonce consisting of a randomly selected 16-byte
// value that has been base64-encoded.
func generateNonce() string {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
