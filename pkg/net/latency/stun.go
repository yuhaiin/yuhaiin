package latency

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/stun"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type NatType int32

const (
	Unknown NatType = iota
	NoResult
	EndpointIndependentNoNAT
	EndpointIndependent
	AddressDependent
	AddressAndPortDependent
	ServerNotSupportChangePort
)

func (n NatType) String() string {
	switch n {
	case NoResult:
		return "NoResult"
	case EndpointIndependentNoNAT:
		return "EndpointIndependentNoNAT"
	case EndpointIndependent:
		return "EndpointIndependent"
	case AddressDependent:
		return "AddressDependent"
	case AddressAndPortDependent:
		return "AddressAndPortDependent"
	case ServerNotSupportChangePort:
		return "ServerNotSupportChangePort"
	default:
		return "Unknown"
	}
}

func Mapping(conn net.PacketConn, udpAddr netapi.Address, timeout time.Duration) (Response, NatType, error) {
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Test I: Regular binding request
	resp, err := sendRequest(req, conn, udpAddr, timeout)
	if err != nil {
		return Response{}, NoResult, err
	}

	if resp.xorMappedAddr.String() == conn.LocalAddr().String() {
		return resp, EndpointIndependentNoNAT, nil
	}

	if resp.otherAddr.IP == nil {
		if resp.changedAddr.IP == nil {
			return resp, ServerNotSupportChangePort, nil
		}

		resp.otherAddr = &stun.OtherAddress{
			IP:   resp.changedAddr.IP,
			Port: resp.changedAddr.Port,
		}
	}

	// Test II: Send binding request to the other address but primary port
	oaddr := &net.UDPAddr{
		IP:   resp.otherAddr.IP,
		Port: int(udpAddr.Port()),
	}
	resp2, err := sendRequest(req, conn, oaddr, timeout)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return resp, NoResult, err
		}
	} else {
		if resp2.xorMappedAddr.String() == resp.xorMappedAddr.String() {
			return resp, EndpointIndependent, nil
		}
	}

	// Test III: Send binding request to the other address and port
	resp3, err := sendRequest(req, conn, &net.UDPAddr{IP: resp.otherAddr.IP, Port: resp.otherAddr.Port}, timeout)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return resp, NoResult, err
		}
	} else {
		if resp3.xorMappedAddr.String() == resp2.xorMappedAddr.String() {
			return resp, AddressDependent, nil
		}
	}

	return resp, AddressAndPortDependent, nil
}

func Filtering(conn net.PacketConn, udpAddr netapi.Address, timeout time.Duration) (NatType, error) {
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Test I: Regular binding request
	_, err := sendRequest(req, conn, udpAddr, timeout)
	if err != nil {
		return NoResult, err
	}

	// Test II: Request to change both IP and port
	//
	// changeIP: 0x04, changePort: 0x02
	req = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	req.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x04 | 0x02})

	_, err = sendRequest(req, conn, udpAddr, timeout)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return NoResult, err
		}
	} else {
		return EndpointIndependent, nil
	}

	// Test III: Request to change port only
	req = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	req.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	_, err = sendRequest(req, conn, udpAddr, timeout)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return NoResult, err
		}
	} else {
		return AddressDependent, nil
	}

	return AddressAndPortDependent, nil
}

type Response struct {
	xorMappedAddr *stun.XORMappedAddress
	otherAddr     *stun.OtherAddress
	changedAddr   *stun.ChangedAddress
	origin        *stun.ResponseOrigin
	mappedAddr    *stun.MappedAddress
	software      *stun.Software
	FromAddr      net.Addr
}

func ParseResponse(msg *stun.Message) (Response, error) {
	resp := Response{
		xorMappedAddr: &stun.XORMappedAddress{},
		otherAddr:     &stun.OtherAddress{},
		changedAddr:   &stun.ChangedAddress{},
		origin:        &stun.ResponseOrigin{},
		mappedAddr:    &stun.MappedAddress{},
		software:      &stun.Software{},
	}

	err := resp.xorMappedAddr.GetFrom(msg)
	if err != nil {
		return Response{}, fmt.Errorf("get xor mapped address failed: %w", err)
	}
	_ = resp.otherAddr.GetFrom(msg)
	_ = resp.changedAddr.GetFrom(msg)
	_ = resp.origin.GetFrom(msg)
	_ = resp.mappedAddr.GetFrom(msg)
	_ = resp.software.GetFrom(msg)

	return resp, nil
}

var parseError = errors.New("parse error")

func sendRequest(req *stun.Message, conn net.PacketConn, addr net.Addr, timeout time.Duration) (Response, error) {
	if err := req.NewTransactionID(); err != nil {
		return Response{}, err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.WriteTo(req.Raw, addr)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return Response{}, err
	}

	b := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(b)

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, addr, err := conn.ReadFrom(b)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return Response{}, err
	}

	resp := &stun.Message{
		Raw: b[:n],
	}

	if err := resp.Decode(); err != nil {
		return Response{}, err
	}

	stunResp, err := ParseResponse(resp)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %w", parseError, err)
	}

	stunResp.FromAddr = addr

	return stunResp, nil
}

type StunResponse struct {
	MappedAddr    string
	MappingType   NatType
	FilteringType NatType
}

// Stun
// Stun nat behavior test
// modified from https://github.com/pion/stun/blob/master/cmd/stun-nat-behaviour/main.go
func Stun(ctx context.Context, p netapi.Proxy, host string) (StunResponse, error) {
	addr, err := netapi.ParseAddress("udp", host)
	if err != nil {
		return StunResponse{}, err
	}
	if addr.Port() == 0 {
		addr = netapi.ParseAddressPort("udp", addr.Hostname(), 3478)
	}

	pconn, err := p.PacketConn(ctx, addr)
	if err != nil {
		return StunResponse{}, err
	}
	defer pconn.Close()

	mr, mt, err := Mapping(pconn, addr, time.Second*5)
	if err != nil {
		return StunResponse{}, err
	}

	var ft NatType = ServerNotSupportChangePort

	if mt != ServerNotSupportChangePort {
		ft, err = Filtering(pconn, addr, time.Second*5)
		if err != nil {
			return StunResponse{}, err
		}
	}

	return StunResponse{
		MappingType:   mt,
		FilteringType: ft,
		MappedAddr:    mr.xorMappedAddr.String(),
	}, nil
}

func StunTCP(ctx context.Context, p netapi.Proxy, host string) (string, error) {
	addr, err := netapi.ParseAddress("udp", host)
	if err != nil {
		return "", err
	}
	if addr.Port() == 0 {
		addr = netapi.ParseAddressPort("udp", addr.Hostname(), 3478)
	}
	c, err := p.Conn(ctx, addr)
	if err != nil {
		return "", err
	}
	defer c.Close()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	_ = c.SetWriteDeadline(time.Now().Add(time.Second * 10))
	_, err = msg.WriteTo(c)
	if err != nil {
		return "", err
	}
	_ = c.SetWriteDeadline(time.Time{})

	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	_ = c.SetReadDeadline(time.Now().Add(time.Second * 10))
	_, err = io.ReadFull(c, buf[:20])
	if err != nil {
		return "", err
	}
	_ = c.SetReadDeadline(time.Time{})

	length := binary.BigEndian.Uint16(buf[2:4])

	if int(length) > nat.MaxSegmentSize-20 {
		return "", fmt.Errorf("invalid length")
	}

	_ = c.SetReadDeadline(time.Now().Add(time.Second * 10))
	_, err = io.ReadFull(c, buf[20:length+20])
	if err != nil {
		return "", err
	}
	_ = c.SetReadDeadline(time.Time{})

	msg.Raw = buf[:length+20]

	err = msg.Decode()
	if err != nil {
		return "", err
	}

	var xor stun.XORMappedAddress
	err = xor.GetFrom(msg)
	if err != nil {
		return "", err
	}

	return xor.String(), nil
}
