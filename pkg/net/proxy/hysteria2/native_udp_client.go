package hysteria2

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/wire"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/apernet/quic-go"
)

type hyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

type nativeUDPManager struct {
	conn     *quic.Conn
	mu       sync.RWMutex
	sessions map[uint32]*nativeUDPSession
	next     uint32
	closed   bool
}
type nativeUDPSession struct {
	manager      *nativeUDPManager
	id           uint32
	receive      chan wire.UDPMessage
	fragment     wire.Defragger
	sendMu       sync.Mutex
	nextPacketID uint16
}

func newNativeUDPManager(conn *quic.Conn) *nativeUDPManager {
	m := &nativeUDPManager{conn: conn, sessions: make(map[uint32]*nativeUDPSession), next: 1}
	go m.run()
	return m
}

func (m *nativeUDPManager) run() {
	defer m.closeAll()
	for {
		b, err := m.conn.ReceiveDatagram(m.conn.Context())
		if err != nil {
			return
		}
		msg, err := wire.ParseUDPMessage(b)
		if err != nil {
			continue
		}
		m.mu.RLock()
		s := m.sessions[msg.SessionID]
		if s != nil {
			select {
			case s.receive <- msg:
			default:
			}
		}
		m.mu.RUnlock()
	}
}

func (m *nativeUDPManager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for id, s := range m.sessions {
		close(s.receive)
		delete(m.sessions, id)
	}
}

func (m *nativeUDPManager) newSession() (hyUDPConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.conn.Context().Err() != nil {
		return nil, io.ErrClosedPipe
	}
	for {
		id := m.next
		m.next++
		if id == 0 || m.sessions[id] != nil {
			continue
		}
		s := &nativeUDPSession{manager: m, id: id, receive: make(chan wire.UDPMessage, 128)}
		m.sessions[id] = s
		return s, nil
	}
}

func (s *nativeUDPSession) Receive() ([]byte, string, error) {
	for {
		msg, ok := <-s.receive
		if !ok {
			return nil, "", io.EOF
		}
		complete, done, err := s.fragment.Feed(msg, time.Now())
		if err != nil || !done {
			continue
		}
		return complete.Data, complete.Address, nil
	}
}

func (s *nativeUDPSession) Send(data []byte, address string) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.manager.mu.RLock()
	active := !s.manager.closed && s.manager.sessions[s.id] == s
	s.manager.mu.RUnlock()
	if !active {
		return io.ErrClosedPipe
	}
	msg := wire.UDPMessage{SessionID: s.id, PacketID: s.nextPacketID, FragmentCount: 1, Address: address, Data: data}
	s.nextPacketID++
	return sendNativeDatagram(s.manager.conn, msg)
}

type nativeDatagramSender interface {
	SendDatagram([]byte) error
}

func sendNativeDatagram(conn nativeDatagramSender, msg wire.UDPMessage) error {
	if len(msg.Address) > wire.MaxAddress || len(msg.Data) > wire.MaxPacket {
		return fmt.Errorf("%w: oversized UDP message", wire.ErrMalformed)
	}
	// SendDatagram copies accepted payloads. Reuse one bounded encoding buffer
	// for the original packet and all fragments, returning it after the copies.
	buffer := pool.GetBytes(msg.Size())
	defer pool.PutBytes(buffer)
	b, err := wire.AppendUDPMessage(buffer[:0], msg)
	if err != nil {
		return err
	}
	err = conn.SendDatagram(b)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	fragments, err := wire.FragmentUDPMessage(msg, int(tooLarge.MaxDatagramPayloadSize))
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		b, err := wire.AppendUDPMessage(buffer[:0], fragment)
		if err != nil {
			return err
		}
		if err := conn.SendDatagram(b); err != nil {
			return err
		}
	}
	return nil
}

func (s *nativeUDPSession) Close() error {
	m := s.manager
	m.mu.Lock()
	if m.sessions[s.id] == s {
		delete(m.sessions, s.id)
		close(s.receive)
	}
	m.mu.Unlock()
	return nil
}

var _ hyUDPConn = (*nativeUDPSession)(nil)
