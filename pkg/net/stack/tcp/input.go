package tcp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Transport struct {
	sockets map[Socket]struct{}
}

type Socket struct {
	SrcAddr tcpip.Address
	DstAddr tcpip.Address
	SrcPort uint16
	DstPort uint16
}

type TCPState int

const (
	LISTEN TCPState = iota
	SYN_RECEIVED
	ESTABLISHED
	CLOSE_WAIT
	LAST_ACK
	CLOSED
)

type Connection struct {
	socket Socket
	seqNum uint32

	status   TCPState
	mySeqNum uint32
}

func (c *Connection) Input(socket Socket, hdr header.TCP) {
	switch c.status {
	case LISTEN:
		if hdr.Flags()&header.TCPFlagSyn != 0 {
			c.seqNum = hdr.SequenceNumber()
			c.status = SYN_RECEIVED
			c.SendAck(c.seqNum+1, header.TCPFlagSyn|header.TCPFlagAck)
		}

	case SYN_RECEIVED:
		if hdr.Flags()&header.TCPFlagAck != 0 && hdr.AckNumber() == c.seqNum+1 {
			c.status = ESTABLISHED
		}

	case ESTABLISHED:
		if hdr.Flags()&header.TCPFlagFin != 0 {
			c.status = CLOSE_WAIT
			c.SendAck(hdr.SequenceNumber()+1, header.TCPFlagAck)
			return
		}

		if len(hdr.Payload()) > 0 {
			// TODO

			c.SendAck(hdr.SequenceNumber()+uint32(len(hdr.Payload())), header.TCPFlagAck)
		}

	case CLOSE_WAIT:
		if hdr.Flags()&header.TCPFlagFin != 0 {
			c.status = LAST_ACK
			c.SendAck(hdr.SequenceNumber()+1, header.TCPFlagAck)
		}

	case LAST_ACK:
		if hdr.Flags()&header.TCPFlagAck != 0 && hdr.AckNumber() == c.seqNum+1 {
			c.status = CLOSED
		}
	}
}

func (c *Connection) SendAck(seqNum uint32, flag header.TCPFlags) {
	hdr := make([]byte, header.MaxIPPacketSize+header.TCPHeaderMaximumSize)
	tcpHdr := header.TCP(hdr)
	tcpHdr.SetSequenceNumber(c.mySeqNum)
	tcpHdr.SetAckNumber(seqNum)
	tcpHdr.SetFlags(uint8(flag))
	tcpHdr.SetDestinationPort(c.socket.SrcPort)
	tcpHdr.SetSourcePort(c.socket.DstPort)
}

func (t *Transport) Inputv4(hdr header.IPv4) {
	if hdr.TransportProtocol() != header.TCPProtocolNumber {
		return
	}

	tcpHdr := header.TCP(hdr.Payload())

	socket := Socket{
		SrcAddr: hdr.SourceAddress(),
		DstAddr: hdr.DestinationAddress(),
		SrcPort: tcpHdr.SourcePort(),
		DstPort: tcpHdr.DestinationPort(),
	}

	if tcpHdr.Flags()&header.TCPFlagSyn != 0 {
		if _, ok := t.sockets[socket]; ok {
			return
		}

		t.sockets[socket] = struct{}{}
	}
}

func (t *Transport) Inputv6(hdr header.IPv6) {
	if hdr.TransportProtocol() != header.TCPProtocolNumber {
		return
	}

}
