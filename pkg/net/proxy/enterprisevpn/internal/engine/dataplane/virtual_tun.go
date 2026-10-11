package dataplane

import (
	"errors"
	"sync"
)

// VirtualPacketIO represents a packet-oriented, non-host TUN.
type VirtualPacketIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

var virtualDevices sync.Map // name -> VirtualPacketIO, consumed once

func RegisterVirtualTUN(name string, io VirtualPacketIO) (func(), error) {
	if name == "" || io == nil {
		return nil, errors.New("virtual TUN requires a unique name and device")
	}
	if _, loaded := virtualDevices.LoadOrStore(name, io); loaded {
		return nil, errors.New("virtual TUN already registered")
	}
	return func() { virtualDevices.Delete(name) }, nil
}
func consumeVirtualTUN(name string) (VirtualPacketIO, bool) {
	v, ok := virtualDevices.LoadAndDelete(name)
	if !ok {
		return nil, false
	}
	return v.(VirtualPacketIO), true
}
