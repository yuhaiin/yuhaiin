package yuubinsya2

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

/*
plain for over tls/quic/grpc/.... that is already encrypted
all unit is byte

+---------+----------+~~~~~~+--------------+~~~~~~~~~~+----------+
|    1    |    1     |  var |       1      |    var   |     1    |
+---------+----------+~~~~~~+--------------+~~~~~~~~~~+----------+
| version | user len | user | password len | password | protocol |
+---------+----------+~~~~~~+--------------+~~~~~~~~~~+----------+

version: 2
userLen: 0 - 255
user: max length 255
passwordLen: 0 - 255
password: max length 255
protocol: 0 - 255
	1: tcp
	2: udp


TCP

+-----------+~~~~~~+------+~~~~~~+
|     1     |  var |   2  | var  |
+-----------+~~~~~~+------+~~~~~~+
| addr type | addr | port | data |
+-----------+~~~~~~+------+~~~~~~+


UDP


UDP over Stream

+------------+-----------+~~~~~~+------+----------+~~~~~~+
|     8      |     1     |  var |   2  |    2     | var  |
+------------+-----------+~~~~~~+------+----------+~~~~~~+
| migrate id | addr type | addr | port | data len | data |
+------------+-----------+~~~~~~+------+----------+~~~~~~+

migrate id: uint64 hash, for reconnect when stream down, it's generate by server

addr type:
	1: ipv4
	4: ipv6
	3: domain

addr:
	ipv4: 4
	ipv6: 16
	domain: | domain len | domain |
	  domainLen: 0 - 255
	  domain: max length 255

port: 0 - 65535
data len: 0 - 65535
data: max length 65535
*/

type UserAuth interface {
	Verify(user string, password string) bool
}

type Protocol byte

const (
	TCP Protocol = iota
	UDP
)

func EncodeHeader(username, password string, protocol Protocol) []byte {
	buf := pool.GetBytes(1 + 1 + len(username) + 1 + len(password) + 1)

	buf[0] = 2
	buf[1] = byte(len(username))
	copy(buf[2:2+len(username)], username)
	buf[2+len(username)] = byte(len(password))
	copy(buf[3+len(username):3+len(username)+len(password)], password)
	buf[3+len(username)+len(password)] = byte(protocol)

	return buf
}

func DecodeHeader(b *bufio.Reader, auth UserAuth) (Protocol, error) {
	version, err := b.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read version failed: %w", err)
	}

	if version != 2 {
		return 0, fmt.Errorf("invalid version: %d", version)
	}

	userLen, err := b.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read user len failed: %w", err)
	}

	user := make([]byte, userLen)
	if _, err := io.ReadFull(b, user); err != nil {
		return 0, fmt.Errorf("read user failed: %w", err)
	}

	passwordLen, err := b.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read password len failed: %w", err)
	}

	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(b, password); err != nil {
		return 0, fmt.Errorf("read password failed: %w", err)
	}

	if !auth.Verify(
		unsafe.String(unsafe.SliceData(user), userLen),
		unsafe.String(unsafe.SliceData(password), passwordLen),
	) {
		return 0, fmt.Errorf("auth failed")
	}

	protocol, err := b.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read protocol failed: %w", err)
	}

	if protocol != byte(TCP) && protocol != byte(UDP) {
		return 0, fmt.Errorf("invalid protocol: %d", protocol)
	}

	return Protocol(protocol), nil
}

func DecodeTCPHeader(b *bufio.Reader) (netapi.Address, error) {
	_, addr, err := tools.ReadAddr("tcp", b)
	return addr, err
}

func EncodeTCPHeader(addr netapi.Address, data []byte) []byte {
	buf := pool.GetBytes(tools.MaxAddrLength + len(data))
	offset := tools.EncodeAddr(addr, buf)
	offset += copy(buf[offset:], data)
	return buf[:offset]
}

func DecodeUDPHeader(b *bufio.Reader) (uint64, netapi.Address, []byte, error) {
	mirgateBytes, err := b.Peek(8)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read migrate id failed: %w", err)
	}

	_, _ = b.Discard(8)

	migrateID := binary.BigEndian.Uint64(mirgateBytes)

	_, addr, err := tools.ReadAddr("udp", b)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read addr failed: %w", err)
	}

	dataLenBytes, err := b.Peek(2)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read data len failed: %w", err)
	}

	_, _ = b.Discard(2)

	dataLen := binary.BigEndian.Uint16(dataLenBytes)
	buf := pool.GetBytes(dataLen)

	if _, err := io.ReadFull(b, buf); err != nil {
		return 0, nil, nil, fmt.Errorf("read data failed: %w", err)
	}

	return migrateID, addr, buf, nil
}

func EncodeUDPHeader(migrateID uint64, addr netapi.Address, data []byte) []byte {
	buf := pool.GetBytes(tools.MaxAddrLength + len(data) + 8 + 2)
	binary.BigEndian.PutUint64(buf, migrateID)
	offset := 8
	offset += tools.EncodeAddr(addr, buf[offset:])
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(data)))
	offset += 2
	offset += copy(buf[offset:], data)
	return buf[:offset]
}
