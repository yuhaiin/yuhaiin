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
	"sync"
)

// DialError is an error that occurs while dialling a websocket server.
type DialError struct {
	*Config
	Err error
}

func (e *DialError) Error() string {
	return "websocket.Dial " + e.Config.Host + e.Config.Path + ": " + e.Err.Error()
}

// NewClient creates a new WebSocket client connection over rwc.
func NewClient(config *Config, rwc net.Conn) (ws *Conn, err error) {
	br := getBufioReader(rwc)
	bw := getBufioWriter(rwc)
	err = hybiClientHandshake(config, br, bw)
	if err != nil {
		return
	}
	buf := bufio.NewReadWriter(br, bw)
	ws = newHybiConn(buf, rwc, nil)
	return
}

var bufioReaderPool sync.Pool

func getBufioReader(r io.Reader) *bufio.Reader {
	br, ok := bufioReaderPool.Get().(*bufio.Reader)
	if !ok {
		return bufio.NewReader(r)
	}
	br.Reset(r)
	return br
}

func putBufioReader(br *bufio.Reader) {
	bufioReaderPool.Put(br)
}

var bufioWriterPool sync.Pool

func getBufioWriter(w io.Writer) *bufio.Writer {
	bw, ok := bufioWriterPool.Get().(*bufio.Writer)
	if !ok {
		return bufio.NewWriter(w)
	}
	bw.Reset(w)
	return bw
}

func putBufioWriter(bw *bufio.Writer) {
	bufioWriterPool.Put(bw)
}

// Client handshake described in draft-ietf-hybi-thewebsocket-protocol-17
func hybiClientHandshake(config *Config, br *bufio.Reader, bw *bufio.Writer) (err error) {
	fmt.Fprintf(bw, "GET %s HTTP/1.1\r\n", config.Path)

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	fmt.Fprintf(bw, "Host: %s\r\n", removeZone(config.Host))
	bw.WriteString("Upgrade: websocket\r\n")
	bw.WriteString("Connection: Upgrade\r\n")
	nonce := generateNonce()
	if config.handshakeData != nil {
		nonce = []byte(config.handshakeData["key"])
	}
	fmt.Fprintf(bw, "Sec-WebSocket-Key: %s\r\n", nonce)
	fmt.Fprintf(bw, "Origin: %s\r\n", config.OriginUrl)

	if config.Version != ProtocolVersionHybi13 {
		return ErrBadProtocolVersion
	}

	fmt.Fprintf(bw, "Sec-WebSocket-Version: %d\r\n", config.Version)
	if len(config.Protocol) > 0 {
		fmt.Fprintf(bw, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(config.Protocol, ", "))
	}
	// TODO(ukai): send Sec-WebSocket-Extensions.
	err = config.Header.WriteSubset(bw, handshakeHeader)
	if err != nil {
		return err
	}

	bw.WriteString("\r\n")
	if err = bw.Flush(); err != nil {
		return err
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return ErrBadStatus
	}
	if strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" || strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
		return ErrBadUpgrade
	}
	expectedAccept, err := getNonceAccept(nonce)
	if err != nil {
		return err
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != string(expectedAccept) {
		return ErrChallengeResponse
	}
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return ErrUnsupportedExtensions
	}
	offeredProtocol := resp.Header.Get("Sec-WebSocket-Protocol")
	if offeredProtocol != "" {
		protocolMatched := false
		for i := 0; i < len(config.Protocol); i++ {
			if config.Protocol[i] == offeredProtocol {
				protocolMatched = true
				break
			}
		}
		if !protocolMatched {
			return ErrBadWebSocketProtocol
		}
		config.Protocol = []string{offeredProtocol}
	}

	return nil
}

// generateNonce generates a nonce consisting of a randomly selected 16-byte
// value that has been base64-encoded.
func generateNonce() (nonce []byte) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	nonce = make([]byte, 24)
	base64.StdEncoding.Encode(nonce, key)
	return
}

// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}
