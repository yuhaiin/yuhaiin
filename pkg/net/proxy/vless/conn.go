package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Conn struct {
	net.Conn
	dst      netapi.Address
	id       id.UUID
	received bool
	udp      bool

	remain int
}

func (vc *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	if vc.remain > 0 {
		length := min(len(b), vc.remain)
		n, err := vc.Read(b[:length])
		vc.remain -= n
		return n, vc.dst, err
	}

	var total uint16
	if err := binary.Read(vc.Conn, binary.BigEndian, &total); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	length := min(len(b), int(total))

	if n, err := io.ReadFull(vc.Conn, b[:total]); err != nil {
		return n, vc.dst, fmt.Errorf("read packet error: %w", err)
	}

	vc.remain = int(total) - length
	return length, vc.dst, nil
}

func (vc *Conn) WriteTo(b []byte, target net.Addr) (int, error) {
	buf := pool.NewBufferSize(2 + len(b))
	defer buf.Reset()

	_ = pool.BinaryWriteUint16(buf, binary.BigEndian, uint16(len(b)))
	_, _ = buf.Write(b)

	_, err := vc.Write(buf.Bytes())
	return len(b), err
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.Conn.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.Conn.Read(b)
}

func (vc *Conn) sendRequest() error {
	buf := pool.NewBufferSize(2048)
	defer buf.Reset()

	_ = buf.WriteByte(Version) // protocol version
	_, _ = buf.Write(vc.id[:]) // 16 bytes of uuid
	_ = buf.WriteByte(0)       // addon data length. 0 means no addon data

	// Command
	if vc.udp {
		_ = buf.WriteByte(CommandUDP)
	} else {
		_ = buf.WriteByte(CommandTCP)
	}

	// Port AddrType Addr
	_ = pool.BinaryWriteUint16(buf, binary.BigEndian, vc.dst.Port())

	if vc.dst.IsFqdn() {
		_ = buf.WriteByte(AtypDomainName)
		_ = buf.WriteByte(byte(len(vc.dst.Hostname())))
		_, _ = buf.WriteString(vc.dst.Hostname())
	} else {
		addrPort := vc.dst.(netapi.IPAddress).AddrPort()

		if addrPort.Addr().Is6() {
			_ = buf.WriteByte(AtypIPv6)
		} else {
			_ = buf.WriteByte(AtypIPv4)
		}

		_, _ = buf.Write(addrPort.Addr().AsSlice())
	}

	_, err := vc.Write(buf.Bytes())
	return err
}

func (vc *Conn) recvResponse() error {
	var buf [2]byte
	if _, err := io.ReadFull(vc.Conn, buf[:]); err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buf[1])
	if length > 0 { // addon data length > 0
		_, _ = io.CopyN(io.Discard, vc.Conn, length) // just discard
	}

	return nil
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, udp bool, dst netapi.Address) (*Conn, error) {
	c := &Conn{
		Conn: conn,
		id:   client.uuid,
		dst:  dst,
		udp:  udp,
	}

	if err := c.sendRequest(); err != nil {
		return nil, err
	}
	return c, nil
}
