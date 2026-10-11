package anyconnect

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/dtls"
)

// The optional DTLS data channel.
//
// AnyConnect always establishes the TLS channel first and may then bring up a
// second, UDP one. Both carry the same packets; the point of the UDP channel is
// to avoid running a tunnel over TCP, where the outer retransmissions interact
// badly with the inner ones. The TLS channel stays open regardless — it carries
// control traffic, and it is what the tunnel falls back to whenever UDP is
// blocked, which is why an implementation without DTLS is still complete.
//
// On the wire the DTLS channel is the same packet types as CSTP but with a
// single header octet instead of the eight-octet framing: a datagram already has
// a length and a boundary, so there is nothing for a length field to add.
//
// The pre-shared key is not transmitted. Both ends derive it from the TLS
// session with an RFC 5705 exporter, so the UDP channel inherits the HTTPS
// channel's authentication without a second credential exchange.

// dtlsPSK derives the DTLS pre-shared key from an established TLS connection.
func dtlsPSK(conn net.Conn) ([]byte, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("anyconnect: DTLS requires a TLS carrier to key from")
	}
	state := tc.ConnectionState()
	psk, err := state.ExportKeyingMaterial(dtlsExporterLabel, nil, dtlsPSKLen)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: deriving the DTLS key: %w", err)
	}
	return psk, nil
}

// marshalDTLS frames a packet for the UDP channel: one type octet, then payload.
func marshalDTLS(typ byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, typ)
	return append(out, payload...)
}

// parseDTLS splits a UDP-channel datagram into its type and payload.
func parseDTLS(pkt []byte) (typ byte, payload []byte, ok bool) {
	if len(pkt) < 1 {
		return 0, nil, false
	}
	return pkt[0], pkt[1:], true
}

// dtlsChannel is a running UDP data channel.
type dtlsChannel struct {
	conn *dtls.Conn
	// up reports whether the channel is carrying traffic. Outbound packets check
	// it to decide between UDP and TLS, and it is cleared the moment the channel
	// fails so the tunnel falls back rather than blackholing.
	up atomic.Bool
}

// dialDTLS brings up the UDP data channel against the server the TLS connection
// is already talking to. A failure here is not fatal to the tunnel: the caller
// keeps running on TLS, which is what the protocol expects when UDP is blocked.
func dialDTLS(tlsConn net.Conn, p DTLSParams, timeout time.Duration) (*dtlsChannel, error) {
	psk, err := dtlsPSK(tlsConn)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(tlsConn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("anyconnect: server address: %w", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, fmt.Errorf("anyconnect: resolving the DTLS endpoint: %w", err)
	}
	udp, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: dialling the DTLS endpoint: %w", err)
	}
	conn, err := dtls.Client(udp, dtls.Config{
		PSK:         psk,
		PSKIdentity: []byte(pskNegotiate),
		// The server matches this UDP flow to the HTTPS session that authorised
		// it by the App-ID it handed out, echoed in the ClientHello's session-id.
		SessionID:        p.AppID,
		MTU:              p.MTU,
		HandshakeTimeout: timeout,
	})
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("anyconnect: DTLS handshake: %w", err)
	}
	ch := &dtlsChannel{conn: conn}
	ch.up.Store(true)
	return ch, nil
}

func (d *dtlsChannel) send(typ byte, payload []byte) error {
	_, err := d.conn.Write(marshalDTLS(typ, payload))
	return err
}

func (d *dtlsChannel) close() {
	d.up.Store(false)
	if d.conn != nil {
		_ = d.conn.Close()
	}
}
