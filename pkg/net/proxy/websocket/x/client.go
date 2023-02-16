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
func NewClient(config *Config, SecWebSocketKey string, header http.Header, rwc net.Conn, handshake func(*http.Response) error) (ws *Conn, err error) {
	br := newBufioReader(rwc)
	bw := newBufioWriterSize(rwc, 4096)
	err = hybiClientHandshake(config, SecWebSocketKey, header, br, bw, handshake)
	if err != nil {
		return
	}
	ws = newHybiConn(bufio.NewReadWriter(br, bw), rwc, nil)
	return
}

//go:linkname newBufioReader net/http.newBufioReader
func newBufioReader(r io.Reader) *bufio.Reader

//go:linkname putBufioReader net/http.putBufioReader
func putBufioReader(br *bufio.Reader)

//go:linkname newBufioWriterSize net/http.newBufioWriterSize
func newBufioWriterSize(w io.Writer, size int) *bufio.Writer

//go:linkname putBufioWriter net/http.putBufioWriter
func putBufioWriter(br *bufio.Writer)

// Client handshake described in draft-ietf-hybi-thewebsocket-protocol-17
func hybiClientHandshake(config *Config, SecWebSocketKey string, header http.Header, br *bufio.Reader, bw *bufio.Writer, handshake func(*http.Response) error) (err error) {
	fmt.Fprintf(bw, "GET %s HTTP/1.1\r\n", config.Path)

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	fmt.Fprintf(bw, "Host: %s\r\n", removeZone(config.Host))
	bw.WriteString("Upgrade: websocket\r\n")
	bw.WriteString("Connection: Upgrade\r\n")

	var nonce string
	if SecWebSocketKey != "" {
		nonce = SecWebSocketKey
	} else {
		nonce = generateNonce()
	}

	fmt.Fprintf(bw, "Sec-WebSocket-Key: %s\r\n", nonce)
	fmt.Fprintf(bw, "Origin: %s\r\n", config.OriginUrl)

	fmt.Fprintf(bw, "Sec-WebSocket-Version: %s\r\n", SupportedProtocolVersion)
	if len(config.Protocol) > 0 {
		fmt.Fprintf(bw, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(config.Protocol, ", "))
	}

	if header != nil {
		// TODO(ukai): send Sec-WebSocket-Extensions.
		err = header.WriteSubset(bw, handshakeHeader)
		if err != nil {
			return err
		}
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
