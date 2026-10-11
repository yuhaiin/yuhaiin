//go:build !linux

package dataplane

import "net"

// groTable and the GRO batch path exist only on Linux, where a vnet TUN can
// accept super-frames; these stubs keep Pump portable. handleInboundBatchGRO
// can never be reached (p.vnet is never set off Linux) and reports false so
// HandleInboundBatch falls through to per-packet delivery.
type groTable struct{}

func (p *Pump) handleInboundBatchGRO(*view, [][]byte, []*net.UDPAddr, int64) bool {
	return false
}
