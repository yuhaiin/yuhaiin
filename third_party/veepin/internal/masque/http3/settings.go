package http3

// The HTTP/3 SETTINGS frame (RFC 9114 §7.2.4) and the control/QPACK stream
// types, reduced to what a CONNECT tunnel negotiates.
//
// One setting actually matters here: SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC
// 9220). A server that does not advertise it will not accept an Extended
// CONNECT, so the client must see it in the server's SETTINGS before sending
// :protocol. The QPACK capacity settings are advertised as zero, which is what
// lets the encoder never touch the dynamic table.

import "fmt"

// Unidirectional stream type codes (RFC 9114 §6.2, RFC 9204 §4.2). Each uni
// stream opens with one of these as a varint.
const (
	StreamControl      = 0x00
	StreamQPACKEncoder = 0x02
	StreamQPACKDecoder = 0x03
)

// SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204 §5, RFC 9220).
const (
	SettingQPACKMaxTableCapacity = 0x01
	SettingMaxFieldSectionSize   = 0x06
	SettingQPACKBlockedStreams   = 0x07
	SettingEnableConnectProtocol = 0x08
	SettingH3Datagram            = 0x33
)

// Settings is a decoded SETTINGS frame: identifier -> value. Unknown identifiers
// are retained so a caller can inspect them, but only the ones above are acted
// on.
type Settings map[uint64]uint64

// DefaultSettings is what veepin advertises. The QPACK table is zero-capacity in
// both directions, blocked streams is zero, and Extended CONNECT is enabled so a
// peer may open a CONNECT tunnel to us. H3_DATAGRAM is deliberately absent: this
// build has no QUIC datagram transport, so HTTP Datagrams travel as capsules,
// which needs no setting.
func DefaultSettings() Settings {
	return Settings{
		SettingQPACKMaxTableCapacity: 0,
		SettingQPACKBlockedStreams:   0,
		SettingEnableConnectProtocol: 1,
	}
}

// Encode renders the settings as a SETTINGS frame payload: a sequence of
// (identifier, value) varint pairs.
func (s Settings) Encode() []byte {
	// A stable order keeps the wire bytes deterministic, which makes the codec
	// testable; the peer does not care about order.
	var out []byte
	for _, id := range []uint64{
		SettingQPACKMaxTableCapacity,
		SettingMaxFieldSectionSize,
		SettingQPACKBlockedStreams,
		SettingEnableConnectProtocol,
		SettingH3Datagram,
	} {
		if v, ok := s[id]; ok {
			out = AppendVarint(out, id)
			out = AppendVarint(out, v)
		}
	}
	return out
}

// ParseSettings decodes a SETTINGS frame payload. A truncated pair is an error;
// a duplicated identifier is one too, as RFC 9114 §7.2.4 requires.
func ParseSettings(b []byte) (Settings, error) {
	s := Settings{}
	for len(b) > 0 {
		var id, v uint64
		var err error
		id, b, err = ConsumeVarint(b)
		if err != nil {
			return nil, err
		}
		v, b, err = ConsumeVarint(b)
		if err != nil {
			return nil, err
		}
		if _, dup := s[id]; dup {
			return nil, fmt.Errorf("http3: duplicate setting %#x", id)
		}
		s[id] = v
	}
	return s, nil
}

// ConnectProtocolEnabled reports whether the peer will accept Extended CONNECT.
func (s Settings) ConnectProtocolEnabled() bool {
	return s[SettingEnableConnectProtocol] == 1
}
