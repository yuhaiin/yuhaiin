package softether

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
	"golang.org/x/crypto/chacha20poly1305"
)

// UDP acceleration v2 is a separately authenticated Ethernet data channel.
// We intentionally do not implement legacy RC4 v1. A server that does not
// negotiate encrypted v2 remains on the always-available TLS data channel.
type udpAcceleration struct {
	sock                       net.PacketConn
	peer                       *net.UDPAddr
	encrypt, decrypt           cipher.AEAD
	serverCookie, clientCookie uint32
	writeMu                    sync.Mutex
	start                      time.Time
	lastSendTick               uint64
	lastReceiveTick            uint64
	lastEcho                   atomic.Uint64
	lastSeen                   atomic.Int64
	stableSince                atomic.Int64
	disabled                   atomic.Bool
}

func newUDPAcceleration(sock net.PacketConn, peerIP net.IP, client *native.UDPClientOptions, server *native.UDPServerOptions) (*udpAcceleration, error) {
	if sock == nil || client == nil || server == nil || server.Version != 2 {
		return nil, errors.New("softether: UDP acceleration parameters missing")
	}
	if peerIP == nil {
		return nil, errors.New("softether: invalid UDP acceleration peer")
	}
	encrypt, err := chacha20poly1305.New(client.KeyV2[:32])
	if err != nil {
		return nil, err
	}
	decrypt, err := chacha20poly1305.New(server.KeyV2[:32])
	if err != nil {
		return nil, err
	}
	return &udpAcceleration{sock: sock, peer: &net.UDPAddr{IP: peerIP, Port: int(server.Port)},
		encrypt: encrypt, decrypt: decrypt, serverCookie: server.ServerCookie, clientCookie: server.ClientCookie,
		start: time.Now()}, nil
}

func (u *udpAcceleration) tick() uint64 {
	// The wire protocol uses milliseconds and reserves 0.
	return uint64(time.Since(u.start)/time.Millisecond) + 1
}

func (u *udpAcceleration) seal(frame []byte) ([]byte, error) {
	if len(frame) > 1350 {
		return nil, errors.New("softether: frame too large for UDP acceleration")
	}
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	inner := make([]byte, 23+len(frame))
	binary.BigEndian.PutUint32(inner[0:4], u.serverCookie)
	now := u.tick()
	binary.BigEndian.PutUint64(inner[4:12], now)
	binary.BigEndian.PutUint64(inner[12:20], u.lastReceiveTick)
	binary.BigEndian.PutUint16(inner[20:22], uint16(len(frame)))
	// Uncompressed Ethernet frame: inner[22] = 0.
	copy(inner[23:], frame)
	cipherText := u.encrypt.Seal(nil, nonce[:], inner, nil)
	packet := make([]byte, 0, len(nonce)+len(cipherText))
	packet = append(packet, nonce[:]...)
	packet = append(packet, cipherText...)
	u.lastSendTick = now
	return packet, nil
}

func (u *udpAcceleration) open(packet []byte) ([]byte, error) {
	if len(packet) < 12+23+16 || len(packet) > 2000 {
		return nil, errors.New("softether: invalid UDP packet length")
	}
	plain, err := u.decrypt.Open(nil, packet[:12], packet[12:], nil)
	if err != nil {
		return nil, err
	}
	if len(plain) < 23 || binary.BigEndian.Uint32(plain[:4]) != u.clientCookie {
		return nil, errors.New("softether: invalid UDP acceleration cookie")
	}
	theirTick := binary.BigEndian.Uint64(plain[4:12])
	echoTick := binary.BigEndian.Uint64(plain[12:20])
	if theirTick == 0 {
		return nil, errors.New("softether: invalid UDP timestamp")
	}
	size := int(binary.BigEndian.Uint16(plain[20:22]))
	if size > 1600 || 23+size > len(plain) || plain[22] != 0 {
		return nil, errors.New("softether: unsupported UDP compression or payload")
	}
	u.writeMu.Lock()
	if theirTick+30000 < u.lastReceiveTick {
		u.writeMu.Unlock()
		return nil, errors.New("softether: stale UDP frame")
	}
	if theirTick > u.lastReceiveTick {
		u.lastReceiveTick = theirTick
	}
	u.writeMu.Unlock()
	if echoTick != 0 && echoTick <= u.tick() {
		u.lastEcho.Store(echoTick)
		u.observeAcknowledgement(time.Now())
	}
	if size == 0 {
		return nil, nil
	}
	return append([]byte(nil), plain[23:23+size]...), nil
}

func (u *udpAcceleration) observeAcknowledgement(now time.Time) {
	nowNS := now.UnixNano()
	last := u.lastSeen.Swap(nowNS)
	if last == 0 || now.Sub(time.Unix(0, last)) >= 3*time.Second {
		u.stableSince.Store(nowNS)
	}
}

// ready is deliberately conservative: server ACK, 10 seconds of stable
// keepalive traffic, and recent acknowledgement. Otherwise TLS remains active.
func (u *udpAcceleration) ready() bool {
	if u == nil || u.disabled.Load() || u.lastEcho.Load() == 0 {
		return false
	}
	last, stable := u.lastSeen.Load(), u.stableSince.Load()
	return last != 0 && stable != 0 &&
		time.Since(time.Unix(0, last)) < 3*time.Second &&
		time.Since(time.Unix(0, stable)) >= 10*time.Second
}

func (u *udpAcceleration) send(frame []byte) error {
	if u.disabled.Load() {
		return net.ErrClosed
	}
	packet, err := u.seal(frame)
	if err != nil {
		return err
	}
	n, err := u.sock.WriteTo(packet, u.peer)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return errors.New("softether: partial UDP write")
	}
	return nil
}

func (u *udpAcceleration) run(ctxDone <-chan struct{}, deliver func([]byte)) {
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctxDone:
				return
			case <-t.C:
				if err := u.send(nil); err != nil {
					u.disabled.Store(true)
					return
				}
			}
		}
	}()
	buf := make([]byte, 2100)
	for {
		// A timeout checks shutdown without requiring socket ownership outside.
		_ = u.sock.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := u.sock.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctxDone:
					return
				default:
					continue
				}
			}
			u.disabled.Store(true)
			return
		}
		udpFrom, ok := from.(*net.UDPAddr)
		if !ok || !udpFrom.IP.Equal(u.peer.IP) {
			continue
		}
		frame, err := u.open(buf[:n])
		if err != nil || len(frame) == 0 {
			continue
		}
		deliver(frame)
	}
}
