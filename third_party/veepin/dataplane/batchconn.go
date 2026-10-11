package dataplane

import (
	"net"

	xipv4 "golang.org/x/net/ipv4"
)

// BatchConn amortises a UDP socket's per-datagram syscall cost by moving a batch
// of datagrams per syscall — sendmmsg/recvmmsg on platforms that have them (via
// golang.org/x/net/ipv4), degrading to one syscall per datagram where they do
// not.
//
// It is the building block for the first lever in
// [doc/scaling-the-data-path.md]: the data path is syscall-bound long before it
// is CPU-bound (a single Write costs microseconds while the AES-GCM that protects
// the same packet costs hundreds of nanoseconds), so cutting the number of
// syscalls per packet is the cheapest throughput available — and, unlike adding
// goroutines, it carries no packet-reordering risk.
//
// The scratch message slices are reused across calls, so a steady-state caller
// allocates nothing per batch.
type BatchConn struct {
	conn  *net.UDPConn
	pc    *xipv4.PacketConn
	wmsgs []xipv4.Message
	rmsgs []xipv4.Message
}

// NewBatchConn wraps a UDP socket for batched I/O.
func NewBatchConn(conn *net.UDPConn) *BatchConn {
	return &BatchConn{conn: conn, pc: xipv4.NewPacketConn(conn)}
}

// WriteBatch sends every packet in pkts using as few syscalls as the platform
// allows. On a connected socket pass to == nil; otherwise every datagram is sent
// to to. It returns the number of datagrams the kernel accepted.
func (b *BatchConn) WriteBatch(pkts [][]byte, to net.Addr) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}
	if cap(b.wmsgs) < len(pkts) {
		b.wmsgs = make([]xipv4.Message, len(pkts))
	}
	msgs := b.wmsgs[:len(pkts)]
	for i, p := range pkts {
		// Reuse each Message's Buffers slice rather than allocating a new
		// [][]byte per datagram.
		msgs[i].Buffers = append(msgs[i].Buffers[:0], p)
		msgs[i].Addr = to
	}
	return b.pc.WriteBatch(msgs, 0)
}

// ReadBatch receives up to len(bufs) datagrams, one per entry of bufs, with as
// few syscalls as the platform allows. It returns the number of datagrams read
// and writes their lengths into the first n entries of sizes (which must be at
// least len(bufs) long).
func (b *BatchConn) ReadBatch(bufs [][]byte, sizes []int) (n int, err error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if cap(b.rmsgs) < len(bufs) {
		b.rmsgs = make([]xipv4.Message, len(bufs))
	}
	msgs := b.rmsgs[:len(bufs)]
	for i := range bufs {
		msgs[i].Buffers = append(msgs[i].Buffers[:0], bufs[i])
	}
	n, err = b.pc.ReadBatch(msgs, 0)
	for i := 0; i < n; i++ {
		sizes[i] = msgs[i].N
	}
	return n, err
}
