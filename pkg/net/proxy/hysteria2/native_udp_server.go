package hysteria2

import (
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/wire"
)

// Every QUIC connection owns its own UDP session-ID namespace.
type nativeServerUDP struct {
	conn *quic.Conn
	handler netapi.Handler
	mu sync.Mutex
	sessions map[uint32]*nativeServerUDPSession
	closed bool
	wg sync.WaitGroup
}

type nativeServerUDPSession struct {
	id uint32
	conn *serverPacketConn
	fragment wire.Defragger
	last time.Time
}

const nativeUDPIdle = 60*time.Second
const maxUDPSessionsPerQUIC = 4096

func newNativeServerUDP(conn *quic.Conn, handler netapi.Handler) *nativeServerUDP {
	return &nativeServerUDP{conn:conn,handler:handler,sessions:make(map[uint32]*nativeServerUDPSession)}
}

func (m *nativeServerUDP) run() {
	tickerStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tickerStop: return
			case <-ticker.C: m.expire()
			}
		}
	}()
	defer close(tickerStop)
	defer m.closeAll()
	for {
		b, err := m.conn.ReceiveDatagram(m.conn.Context())
		if err != nil { return }
		msg, err := wire.ParseUDPMessage(b)
		if err != nil { continue }
		m.mu.Lock()
		entry := m.sessions[msg.SessionID]
		if entry == nil {
			if m.closed || len(m.sessions) >= maxUDPSessionsPerQUIC { m.mu.Unlock(); continue }
			entry = &nativeServerUDPSession{id:msg.SessionID,
				conn:newServerPacketConn(m.conn.Context(),m.conn.RemoteAddr(),m.handler)}
			m.sessions[msg.SessionID] = entry
			m.wg.Add(1)
			go m.sendReplies(entry)
		}
		entry.last = time.Now()
		result, ready, err := entry.fragment.Feed(msg,entry.last)
		m.mu.Unlock()
		if ready && err == nil { _,_ = entry.conn.WriteTo(result.Data,result.Address) }
	}
}

func (m *nativeServerUDP) sendReplies(entry *nativeServerUDPSession) {
	defer m.wg.Done()
	buf := make([]byte,65535)
	for {
		n, addr, err := entry.conn.ReadFrom(buf)
		if err != nil { return }
		msg := wire.UDPMessage{SessionID:entry.id,FragmentCount:1,Address:addr,Data:buf[:n]}
		if err := sendNativeDatagram(m.conn,msg); err != nil { return }
	}
}

func (m *nativeServerUDP) expire() {
	m.mu.Lock()
	now := time.Now()
	var old []*serverPacketConn
	for id, entry := range m.sessions {
		if now.Sub(entry.last) > nativeUDPIdle {
			delete(m.sessions,id)
			old = append(old,entry.conn)
		}
	}
	m.mu.Unlock()
	for _, conn := range old { _ = conn.Close() }
}

func (m *nativeServerUDP) closeAll() {
	m.mu.Lock()
	if m.closed { m.mu.Unlock(); return }
	m.closed = true
	var conns []*serverPacketConn
	for id, s := range m.sessions { delete(m.sessions,id); conns=append(conns,s.conn) }
	m.mu.Unlock()
	for _, conn := range conns { _ = conn.Close() }
	m.wg.Wait()
}
