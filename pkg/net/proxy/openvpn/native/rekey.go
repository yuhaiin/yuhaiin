package native

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/control"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/data"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/keys"
)

func nextKeyID(id uint8) uint8 { return id%7 + 1 }

func (s *Session) sendControl(packet []byte) error {
	if s.wrapper != nil {
		var err error
		packet, err = s.wrapper.Wrap(packet)
		if err != nil {
			return err
		}
	}
	return s.transport.WritePacket(packet)
}

// beginRekey installs a separate TLS reliability channel while the current data
// keys keep carrying traffic. Key ID zero is never reused in the session.
func (s *Session) beginRekey(id uint8) *control.Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.cipher == nil || id != nextKeyID(s.keyID) {
		return nil
	}
	if s.rekeying {
		return s.channels[id]
	}
	local := s.channel.LocalSessionID()
	remote, _ := s.channel.RemoteSessionID()
	ch, err := control.NewSoft(s.sendControl, id, local, remote)
	if err != nil {
		return nil
	}
	old := s.channels[id]
	if old != nil {
		_ = old.Close()
	}
	s.channels[id] = ch
	s.rekeying = true
	s.lastRekey.Store(time.Now().UnixNano())
	go s.negotiateRekey(ch, id)
	return ch
}

func (s *Session) negotiateRekey(ch *control.Channel, id uint8) {
	succeeded := false
	defer func() {
		s.mu.Lock()
		s.rekeying = false
		if !succeeded && s.channels[id] == ch {
			s.channels[id] = nil
		}
		s.mu.Unlock()
		if !succeeded {
			_ = ch.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	closeOnCancel := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer closeOnCancel()
	if deadline, ok := ctx.Deadline(); ok {
		_ = ch.SetDeadline(deadline)
	}
	cfg, err := s.cfg.TLSConfig()
	if err != nil {
		s.fail(err)
		return
	}
	conn := tls.Client(ch, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	source, err := keys.NewClientKeySource()
	if err != nil {
		s.fail(err)
		return
	}
	if _, err := conn.Write(source.MarshalClient(s.occ(), s.cfg.Username, s.cfg.Password, s.peerInfo())); err != nil {
		return
	}
	server, err := readServerKeys(conn)
	if err != nil {
		return
	}
	remote, ok := ch.RemoteSessionID()
	if !ok {
		return
	}
	material := (&keys.KeySource2{Client: *source, Server: *server}).Derive(keys.SessionID(ch.LocalSessionID()), keys.SessionID(remote), false)
	cipher, err := data.NewAEAD(material, s.info.PeerID, id, s.info.Cipher)
	if err != nil {
		s.fail(err)
		return
	}
	if !closeOnCancel() || ctx.Err() != nil {
		return
	}
	_ = ch.SetDeadline(time.Time{})
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	previous, previousID := s.channel, s.keyID
	s.channel, s.cipher, s.keyID = ch, cipher, id
	s.ciphers[id], s.expires[id] = cipher, time.Time{}
	// Accept late packets from the prior key only for OpenVPN's transition window.
	s.expires[previousID] = time.Now().Add(time.Minute)
	s.mu.Unlock()
	_ = previous.Close()
	s.rekeyCount.Add(1)
	succeeded = true
	go s.monitorControl(bufio.NewReader(conn), ch)
}

// Rekey is useful for deterministic interop tests. Automatic and server-driven
// renegotiation use the same path; established application sockets survive it.
func (s *Session) Rekey(ctx context.Context) error {
	s.mu.Lock()
	previous, id := s.channel, nextKeyID(s.keyID)
	s.mu.Unlock()
	if s.beginRekey(id) == nil {
		return errors.New("openvpn: unable to initiate rekey")
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		current, rekeying := s.channel, s.rekeying
		s.mu.Unlock()
		if current != previous {
			return nil
		}
		if !rekeying {
			return errors.New("openvpn: rekey failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.Err()
		case <-tick.C:
		}
	}
}
