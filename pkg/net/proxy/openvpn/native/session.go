package native

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/control"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/data"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/keys"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/wire"
)

// Session multiplexes the TLS control stream and encrypted IP packets on one
// caller-owned transport. Closing a session always closes its transport.
type Session struct {
	cfg         Config
	transport   *Transport
	channel     *control.Channel
	channels    [8]*control.Channel
	ciphers     [8]*data.Cipher
	expires     [8]time.Time
	keyID       uint8
	rekeying    bool
	wrapper     control.Wrapper
	lastRekey   atomic.Int64
	rekeyCount  atomic.Uint64
	info        Info
	cipher      *data.Cipher
	incoming    chan []byte
	ctx         context.Context
	cancel      context.CancelFunc
	once        sync.Once
	mu          sync.Mutex
	failure     error
	lastReceive atomic.Int64
}

func Connect(parent context.Context, cfg Config, transport *Transport) (_ *Session, err error) {
	success := false
	defer func() {
		if !success {
			_ = transport.Conn.Close()
		}
	}()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	wrapper, err := cfg.wrapper()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{cfg: cfg, transport: transport, incoming: make(chan []byte, 256), ctx: ctx, cancel: cancel, wrapper: wrapper}
	ch, err := control.New(s.sendControl, 0, time.Second, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	s.channel = ch
	s.channels[0] = ch
	defer func() {
		if !success {
			_ = s.Close()
		}
	}()
	go s.receive()
	handshake, stop := context.WithTimeout(parent, 30*time.Second)
	defer stop()
	stopClose := context.AfterFunc(handshake, func() { s.fail(handshake.Err()) })
	defer stopClose()
	if deadline, ok := handshake.Deadline(); ok {
		_ = ch.SetDeadline(deadline)
	}
	tlsConn := tls.Client(ch, tlsCfg)
	if err := tlsConn.HandshakeContext(handshake); err != nil {
		return nil, fmt.Errorf("openvpn: TLS handshake: %w", err)
	}
	source, err := keys.NewClientKeySource()
	if err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write(source.MarshalClient(s.occ(), cfg.Username, cfg.Password, s.peerInfo())); err != nil {
		return nil, err
	}
	server, err := readServerKeys(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("openvpn: key exchange: %w", err)
	}
	if _, err := tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(tlsConn)
	reply, err := readMessage(reader)
	if err != nil {
		return nil, err
	}
	info, err := ParsePush(reply, cfg)
	if err != nil {
		return nil, err
	}
	remote, ok := ch.RemoteSessionID()
	if !ok {
		return nil, errors.New("openvpn: missing remote session ID")
	}
	material := (&keys.KeySource2{Client: *source, Server: *server}).Derive(keys.SessionID(ch.LocalSessionID()), keys.SessionID(remote), false)
	cipher, err := data.NewAEAD(material, info.PeerID, 0, info.Cipher)
	if err != nil {
		return nil, err
	}
	if !stopClose() || handshake.Err() != nil {
		return nil, handshake.Err()
	}
	_ = ch.SetDeadline(time.Time{})
	s.mu.Lock()
	s.info, s.cipher = info, cipher
	s.ciphers[0] = cipher
	s.mu.Unlock()
	if err := s.Err(); err != nil {
		return nil, err
	}
	s.lastReceive.Store(time.Now().UnixNano())
	s.lastRekey.Store(time.Now().UnixNano())
	go s.monitorControl(reader, ch)
	go s.keepalive()
	success = true
	return s, nil
}

func (s *Session) Info() Info {
	info := s.info
	info.Prefixes = slices.Clone(info.Prefixes)
	info.DNS = slices.Clone(info.DNS)
	info.Routes = slices.Clone(info.Routes)
	return info
}
func (s *Session) RekeyCount() uint64    { return s.rekeyCount.Load() }
func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	return nil
}
func (s *Session) fail(err error) {
	s.mu.Lock()
	if s.failure == nil {
		s.failure = err
	}
	s.mu.Unlock()
	_ = s.Close()
}
func (s *Session) Close() error {
	s.once.Do(func() {
		s.cancel()
		_ = s.transport.Conn.Close()
		s.mu.Lock()
		channels := s.channels
		s.mu.Unlock()
		for _, ch := range channels {
			if ch != nil {
				_ = ch.Close()
			}
		}
	})
	return nil
}
func (s *Session) WriteIP(packet []byte) error {
	if err := s.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	cipher := s.cipher
	s.mu.Unlock()
	if cipher == nil {
		return errors.New("openvpn: data channel not ready")
	}
	sealed, err := cipher.Seal(packet)
	if err != nil {
		s.fail(err)
		return err
	}
	err = s.transport.WritePacket(sealed)
	if err != nil {
		s.fail(err)
	}
	return err
}
func (s *Session) ReadIP() ([]byte, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.Err()
	case p := <-s.incoming:
		return p, nil
	}
}
func (s *Session) receive() {
	buf := make([]byte, 65535)
	for {
		packet, err := s.transport.ReadPacket(buf)
		if err != nil {
			s.fail(err)
			return
		}
		op, keyID, ok := wire.Opcode(packet)
		if !ok {
			continue
		}

		if wire.IsControl(op) {
			if s.wrapper != nil {
				packet, err = s.wrapper.Unwrap(packet)
				if err != nil {
					continue
				}
			}
			s.mu.Lock()
			ch := s.channels[keyID]
			active := s.keyID
			activeChannel := s.channel
			s.mu.Unlock()
			if ch != nil {
				select {
				case <-ch.Closed():
					ch = nil
				default:
				}
			}
			if ch == nil && op == wire.PControlSoftResetV1 && keyID == nextKeyID(active) {
				parsed, err := wire.ParseControl(packet)
				remote, _ := activeChannel.RemoteSessionID()
				if err == nil && parsed.SessionID == remote {
					ch = s.beginRekey(keyID)
				}
			}
			if ch != nil {
				ch.Deliver(packet)
			}
			continue
		}
		if op != wire.PDataV2 {
			continue
		}
		s.mu.Lock()
		cipher := s.ciphers[keyID]
		expiry := s.expires[keyID]
		s.mu.Unlock()
		if cipher == nil || !expiry.IsZero() && time.Now().After(expiry) {
			continue
		}

		plain, err := cipher.Open(packet)
		if err != nil {
			continue
		}
		s.lastReceive.Store(time.Now().UnixNano())
		if data.IsPing(plain) {
			continue
		}
		plain = trimIP(plain, s.info.MTU)
		if plain == nil {
			continue
		}
		// UDP must not block the shared reader when the application is slow.
		copyPacket := append([]byte(nil), plain...)
		select {
		case s.incoming <- copyPacket:
		case <-s.ctx.Done():
			return
		default:
		}
	}
}
func (s *Session) monitorControl(reader *bufio.Reader, ch *control.Channel) {
	for {
		message, err := readMessage(reader)
		if err != nil {
			s.mu.Lock()
			active := s.channel == ch
			s.mu.Unlock()
			if active {
				s.fail(err)
			}
			return
		}
		switch {
		case message == "RESTART" || len(message) >= 8 && message[:8] == "RESTART,":
			s.fail(ErrRestart)
			return
		case len(message) >= 11 && message[:11] == "AUTH_FAILED":
			s.fail(ErrAuth)
			return
		}
	}
}
func (s *Session) keepalive() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	ping := s.info.Ping
	if ping == 0 {
		ping = 10 * time.Second
	}
	timeout := s.info.PingRestart
	if timeout == 0 && s.info.Ping > 0 {
		timeout = 6 * s.info.Ping
	}
	nextPing := time.Now()

	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-tick.C:
			if timeout > 0 && now.Sub(time.Unix(0, s.lastReceive.Load())) >= timeout {
				s.fail(errors.New("openvpn: ping-restart timeout"))
				return
			}
			if now.Sub(time.Unix(0, s.lastRekey.Load())) >= s.cfg.RenegotiateAfter {
				s.mu.Lock()
				id := nextKeyID(s.keyID)
				s.mu.Unlock()
				s.beginRekey(id)
			}
			if !now.Before(nextPing) {
				if err := s.WriteIP(data.Ping); err != nil {
					return
				}
				nextPing = now.Add(ping)
			}
		}
	}
}
func trimIP(p []byte, mtu int) []byte {
	if len(p) < 20 {
		return nil
	}
	var n int
	switch p[0] >> 4 {
	case 4:
		header := int(p[0]&15) * 4
		n = int(binary.BigEndian.Uint16(p[2:4]))
		if header < 20 || n < header {
			return nil
		}
	case 6:
		if len(p) < 40 {
			return nil
		}
		n = 40 + int(binary.BigEndian.Uint16(p[4:6]))
	default:
		return nil
	}
	if n > len(p) || n > mtu {
		return nil
	}
	return p[:n]
}
func readMessage(reader *bufio.Reader) (string, error) {
	buf := make([]byte, 0, 512)
	for len(buf) < 16384 {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			return string(buf), nil
		}
		buf = append(buf, b)
	}
	return "", errors.New("openvpn: control message too long")
}
func readServerKeys(reader io.Reader) (*keys.KeySource, error) {
	// Read exact length so a coalesced PUSH_REPLY remains in the TLS stream.
	head := make([]byte, 71)
	if _, err := io.ReadFull(reader, head); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(head[69:71]))
	if size < 1 || size > 8192 {
		return nil, errors.New("openvpn: invalid key message size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	// The stock server appends username, password and peer-info fields even
	// when all three are empty. Consume them without swallowing a PUSH_REPLY.
	for range 3 {
		var length [2]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n > 8192 {
			return nil, errors.New("openvpn: oversized server key field")
		}
		if _, err := io.CopyN(io.Discard, reader, int64(n)); err != nil {
			return nil, err
		}
	}
	source, _, err := keys.ParseServer(append(head, body...))
	return source, err
}
