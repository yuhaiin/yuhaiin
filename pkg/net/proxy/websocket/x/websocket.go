// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package websocket implements a client and server for the WebSocket protocol
// as specified in RFC 6455.
//
// This package currently lacks some features found in an alternative
// and more actively maintained WebSocket package:
//
//	https://pkg.go.dev/nhooyr.io/websocket
package websocket // import "golang.org/x/net/websocket"

import (
	"crypto/sha1"
	"encoding/base64"
	"unsafe"
)

const (
	SupportedProtocolVersion = "13"
)

const (
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	closeStatusNormal            = 1000
	closeStatusGoingAway         = 1001
	closeStatusProtocolError     = 1002
	closeStatusUnsupportedData   = 1003
	closeStatusFrameTooLarge     = 1004
	closeStatusNoStatusRcvd      = 1005
	closeStatusAbnormalClosure   = 1006
	closeStatusBadMessageData    = 1007
	closeStatusPolicyViolation   = 1008
	closeStatusTooBigData        = 1009
	closeStatusExtensionMismatch = 1010

	maxControlFramePayloadLength = 125
)

var (
	ErrUnsupportedExtensions = &ProtocolError{"unsupported extensions"}

	handshakeHeader = map[string]bool{
		"Host":                   true,
		"Upgrade":                true,
		"Connection":             true,
		"Sec-Websocket-Key":      true,
		"Sec-Websocket-Origin":   true,
		"Sec-Websocket-Version":  true,
		"Sec-Websocket-Protocol": true,
		"Sec-Websocket-Accept":   true,
	}
)

// ProtocolError represents WebSocket protocol errors.
type ProtocolError struct {
	ErrorString string
}

func (err *ProtocolError) Error() string { return err.ErrorString }

var (
	ErrBadProtocolVersion   = &ProtocolError{"bad protocol version"}
	ErrBadScheme            = &ProtocolError{"bad scheme"}
	ErrBadStatus            = &ProtocolError{"bad status"}
	ErrBadUpgrade           = &ProtocolError{"missing or bad upgrade"}
	ErrBadWebSocketOrigin   = &ProtocolError{"missing or bad WebSocket-Origin"}
	ErrBadWebSocketLocation = &ProtocolError{"missing or bad WebSocket-Location"}
	ErrBadWebSocketProtocol = &ProtocolError{"missing or bad WebSocket-Protocol"}
	ErrBadWebSocketVersion  = &ProtocolError{"missing or bad WebSocket Version"}
	ErrChallengeResponse    = &ProtocolError{"mismatch challenge/response"}
	ErrBadFrame             = &ProtocolError{"bad frame"}
	ErrBadFrameBoundary     = &ProtocolError{"not on frame boundary"}
	ErrNotWebSocket         = &ProtocolError{"not websocket protocol"}
	ErrBadRequestMethod     = &ProtocolError{"bad method"}
	ErrNotSupported         = &ProtocolError{"not supported"}
)

// getNonceAccept computes the base64-encoded SHA-1 of the concatenation of
// the nonce ("Sec-WebSocket-Key" value) with the websocket GUID string.
func getNonceAccept(nonce string) string {
	h := sha1.New()
	h.Write(unsafe.Slice(unsafe.StringData(nonce), len(nonce)))
	h.Write([]byte(websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
