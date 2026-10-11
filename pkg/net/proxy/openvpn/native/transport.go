package native

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// Transport preserves packet boundaries on both UDP and OpenVPN TCP framing.
// A caller supplies the socket, including a socket reached through a proxy.
type Transport struct {
	Conn net.Conn
	TCP  bool
	mu   sync.Mutex
}

func (t *Transport) ReadPacket(buf []byte) ([]byte, error) {
	if !t.TCP {
		n, err := t.Conn.Read(buf)
		return buf[:n], err
	}
	var header [2]byte
	if _, err := io.ReadFull(t.Conn, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n == 0 || n > len(buf) {
		return nil, errors.New("openvpn: invalid TCP packet size")
	}
	_, err := io.ReadFull(t.Conn, buf[:n])
	return buf[:n], err
}

func (t *Transport) WritePacket(packet []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(packet) == 0 || len(packet) > 65535 {
		return errors.New("openvpn: invalid outgoing packet size")
	}
	if !t.TCP {
		n, err := t.Conn.Write(packet)
		if err == nil && n != len(packet) {
			return io.ErrShortWrite
		}
		return err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	out = append(out, packet...)
	for len(out) > 0 {
		n, err := t.Conn.Write(out)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		out = out[n:]
	}
	return nil
}
