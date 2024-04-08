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

package tun

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	wg  sync.WaitGroup
	mtu uint32

	dev netlink.Writer

	attached bool
}

// New creates a new channel endpoint.
func NewEndpoint(w netlink.Writer, mtu uint32) *Endpoint {
	return &Endpoint{
		mtu: mtu,
		dev: w,
	}
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	e.dev.Close()
	e.wg.Wait()
}

func (e *Endpoint) Writer() netlink.Writer {
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
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.dispatchLoop(dispatcher)
		}()
	}
}

func (e *Endpoint) dispatchLoop(dispatcher stack.NetworkDispatcher) {
	bufs := make([][]byte, e.dev.BatchSize())
	size := make([]int, e.dev.BatchSize())

	for i := range bufs {
		bufs[i] = make([]byte, e.mtu)
	}

	for {
		n, err := e.dev.Read(bufs, size)
		if err != nil {
			return
		}

		for i := range n {
			buf := bufs[i][:size[i]]

			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(buf) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				_, _ = e.dev.Write([][]byte{buf})
				continue
			}

			pkt := stack.NewPacketBuffer(
				stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(buf),
				})
			dispatcher.DeliverNetworkPacket(p, pkt)
			pkt.DecRef()
		}
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool { return e.attached }

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 { return e.mtu }

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress { return "" }

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	bufs := [][]byte{}
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		defer view.Release()
		bufs = append(bufs, view.AsSlice())
	}

	n, er := e.dev.Write(bufs)
	if er != nil {
		log.Error("write packet failed", "err", er)
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
