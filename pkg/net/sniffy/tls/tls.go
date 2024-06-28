package tls

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type Conn struct {
	conn   net.Conn
	ctx    context.Context
	cancel func()

	dialer    func(ctx context.Context, network, addr string) (net.Conn, error)
	tlsDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	addr      string
	helloMsg  bool

	tls bool
}

func (c *Conn) Read(b []byte) (int, error) {
	<-c.ctx.Done()

	if c.conn == nil {
		return 0, nil
	}

	return c.conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if !c.helloMsg {
		c.tls = check(b)
		c.helloMsg = true
	}

	if c.conn == nil {
		var err error
		if c.tls {
			c.conn, err = c.tlsDialer(c.ctx, "tcp", c.addr)
		} else {
			c.conn, err = c.dialer(c.ctx, "tcp", c.addr)
		}
		if err != nil {
			return 0, err
		}
		c.cancel()
	}

	return c.conn.Write(b)
}

func (c *Conn) Close() error {
	c.cancel()
	if c.conn == nil {
		return nil
	}

	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	if c.conn == nil {
		return &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}

	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}

	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return nil
	}
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return nil
	}

	return c.conn.SetWriteDeadline(t)
}

func check(buf []byte) bool {
	n := len(buf)

	if n <= 5 {
		return false
	}

	// tls record type
	if recordType(buf[0]) != recordTypeHandshake {
		return false
	}

	// tls major version
	// fmt.Println("tls version", buf[1])
	// if buf[1] != 3 {
	// 	log.Println("TLS version < 3 not supported")
	// 	return false
	// }

	// payload length
	//l := int(buf[3])<<16 + int(buf[4])

	//log.Printf("length: %d, got: %d", l, n)

	// handshake message type
	if uint8(buf[5]) != typeClientHello {
		return false
	}

	msg := &clientHelloMsg{}

	// client hello message not include tls header, 5 bytes
	ret := msg.unmarshal(buf[5:n])
	if !ret {
		return false
	}

	fmt.Println("server name", msg.serverName)

	return true
}

func Get(str string) error {
	hc := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ctx, cancel := context.WithCancel(ctx)
				return &Conn{
					addr:      addr,
					ctx:       ctx,
					cancel:    cancel,
					dialer:    (&net.Dialer{}).DialContext,
					tlsDialer: (&net.Dialer{}).DialContext,
				}, nil
			},
		},
	}

	resp, err := hc.Get(str)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	fmt.Println("data length", len(data))
	return nil
}

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// this file is from $GOROOT/src/crypto/tls

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
)

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

type clientHelloMsg struct {
	serverName         string
	random             []byte
	sessionId          []byte
	compressionMethods []uint8
	vers               uint16
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}
