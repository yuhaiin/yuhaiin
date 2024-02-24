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
	"io"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type writer interface {
	Write([]byte) tcpip.Error
	WritePacket(pkt stack.PacketBufferPtr) tcpip.Error
	dispatch(e stack.NetworkDispatcher, mtu uint32) (bool, tcpip.Error)
	io.Closer
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	wg  sync.WaitGroup
	mtu uint32

	writer writer

	attached bool
}

// New creates a new channel endpoint.
func NewEndpoint(w writer, mtu uint32) *Endpoint {
	return &Endpoint{
		mtu:    mtu,
		writer: w,
	}
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	e.writer.Close()
	e.wg.Wait()
}

func (e *Endpoint) Writer() writer {
	return e.writer
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
			for {
				cont, err := e.writer.dispatch(dispatcher, e.MTU())
				if err != nil || !cont {
					log.Debug("dispatch exit", "err", err)
					break
				}
			}
		}()
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool { return e.attached }

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress { return "" }

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if err := e.writer.WritePacket(pkt); err != nil {
			if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok && n == 0 {
				return 0, err
			}
			break
		}
		n++
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (e *Endpoint) Wait() { e.wg.Wait() }

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*Endpoint) AddHeader(stack.PacketBufferPtr) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*Endpoint) ParseHeader(stack.PacketBufferPtr) bool { return true }
