// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package channel provides the implemention of channel-based data-link layer
// endpoints. Such endpoints allow injection of inbound packets and store
// outbound packets in a channel.

package gvisor

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

var (
	_ stack.LinkEndpoint = (*Endpoint)(nil)
	_ stack.GSOEndpoint  = (*Endpoint)(nil)
)

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	dev netlink.Tun

	linkAddr tcpip.LinkAddress
	wg       sync.WaitGroup

	closed   atomic.Bool
	attached bool

	gso bool
}

// New creates a new channel endpoint.
func NewEndpoint(w netlink.Tun) *Endpoint {
	e := &Endpoint{
		dev: w,
	}

	if w.GSOEnabled() {
		e.gso = e.SupportedGSO() == stack.HostGSOSupported
	}

	return e
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	if e.closed.Load() {
		return
	}
	e.closed.Store(true)
	e.dev.Close()
	e.wg.Wait()
}

func (e *Endpoint) Writer() netlink.Tun {
	return e.dev
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil && e.IsAttached() {
		e.Close()
		e.attached = false
	}

	if dispatcher != nil && !e.IsAttached() {
		e.attached = true
		gro := &gro.GRO{
			Dispatcher: dispatcher,
		}
		gro.Init(e.dev.GSOEnabled())
		e.wg.Go(func() {
			defer gro.Flush()
			e.Forward(gro)
		})
	}
}

func (e *Endpoint) Forward(dispatcher *gro.GRO) {
	bufs := make([][]byte, e.dev.BatchSize())
	size := make([]int, e.dev.BatchSize())

	offset := e.dev.Offset()

	for i := range bufs {
		bufs[i] = make([]byte, e.dev.MTU()+offset)
	}

	for {
		n, err := e.dev.Read(bufs, size)

		for i := range n {
			buf := bufs[i][offset : size[i]+offset]

			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(buf) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				continue
			}

			pkt := stack.NewPacketBuffer(
				stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(buf),
				})
			pkt.NetworkProtocolNumber = p
			pkt.RXChecksumValidated = true
			dispatcher.Enqueue(pkt)
			// dispatcher.DeliverNetworkPacket(p, pkt)
			pkt.DecRef()
		}

		if err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				log.Warn("dev read failed", "err", err)
				continue
			}

			log.Error("dev read failed", "err", err)
			return
		}
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool { return e.attached }

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 { return uint32(e.dev.MTU()) }

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress { return e.linkAddr }

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.closed.Load() {
		return 0, &tcpip.ErrClosedForSend{}
	}

	offset := e.dev.Offset()

	bufs := make([][]byte, 0, pkts.Len())

	for _, pkt := range pkts.AsSlice() {
		buf := pool.GetBytes(pkt.Size() + offset)
		index := offset

		views, voffset := pkt.AsViewList()
		length := pkt.Size()

		for v := views.Front(); length > 0 && v != nil; v = v.Next() {
			size := v.Size()
			if voffset >= size {
				voffset -= size
				continue
			}

			vb := v.AsSlice()

			if voffset > 0 {
				vb = vb[voffset:]
				voffset = 0
			}

			n := copy(buf[index:], vb)
			index += n
			length -= n
		}

		if e.gso {
			// TODO: should we split gso[tun.GSOSplit] by ourself? instead of reset checksum?
			// it seems no problem now that we just reset checksum
			// see https://github.com/tailscale/tailscale/blob/ff1d0aa027f9e8de36d8f4a4aba67f575534cd06/net/tstun/wrap.go#L1364
			//
			// reset checksum when tcp
			// see: https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/transport/tcp/connect.go#L915
			// and https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/transport/tcp/connect.go#L840
			// resetGSOChecksum(buf[offset:], pkt)
		}

		bufs = append(bufs, buf)
	}

	n, er := e.dev.Write(bufs)
	for _, b := range bufs {
		pool.PutBytes(b)
	}

	if er != nil {
		if !errors.Is(er, os.ErrClosed) {
			log.Error("write packet failed", "err", er)
		}
		if n == 0 {
			return 0, &tcpip.ErrClosedForSend{}
		}
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (e *Endpoint) Wait() { e.wg.Wait() }

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*Endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) { e.linkAddr = addr }

func (e *Endpoint) SetMTU(mtu uint32)       {}
func (e *Endpoint) SetOnCloseAction(func()) {}

func (e *Endpoint) GSOMaxSize() uint32 {
	// This an increase from 32k returned by channel.Endpoint.GSOMaxSize() to
	// 64k, which improves throughput.
	if e.gso {
		return (1 << 16) - 1
	}

	return 0
}

// SupportedGSO returns the supported segmentation offloading.
func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	if e.gso {
		return stack.HostGSOSupported
	}
	return stack.GSONotSupported
}

func resetGSOChecksum(data []byte, pkt *stack.PacketBuffer) {
	// see: https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/transport/tcp/connect.go#L915
	// and https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/transport/tcp/connect.go#L840
	if pkt.GSOOptions.Type == stack.GSONone || !pkt.GSOOptions.NeedsCsum {
		return
	}

	if pkt.TransportProtocolNumber == header.TCPProtocolNumber {
		var network header.Network
		switch pkt.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			network = header.IPv4(data)
		case header.IPv6ProtocolNumber:
			network = header.IPv6(data)
		default:
			return
		}
		tcp := header.TCP(network.Payload())
		device.ResetTransportChecksum(network, tcp, tcp.Checksum())
	}
}
