package netapi

import (
	"net"
	"reflect"
)

// IsNilConn reports whether a net.Conn is nil, including a typed nil pointer
// stored in an interface. Such values compare unequal to nil but panic when
// their methods are called. They can escape when a (*net.TCPConn, error)
// return value is implicitly converted to (net.Conn, error).
func IsNilConn(conn net.Conn) bool {
	return isNilNetworkInterface(conn)
}

// IsNilPacketConn is the datagram equivalent of IsNilConn.
func IsNilPacketConn(conn net.PacketConn) bool {
	return isNilNetworkInterface(conn)
}

func isNilNetworkInterface(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}
