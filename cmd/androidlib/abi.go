// Command androidlib is the C ABI of the Android core.
//
// Built with -buildmode=c-shared it becomes libyuhaiin.so, the only native
// entry point of yuhaiin-android. The exported C functions live in cabi.go
// (Android builds only); everything else here is plain Go so the operation
// table can be unit tested on any host.
//
// The ABI is deliberately tiny: yh_call carries low-frequency control
// operations as name + JSON/bytes, yh_host carries the platform callbacks.
// New core features add operations, not C functions.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sync/atomic"
)

// ABIVersion must match YH_ABI_VERSION in yuhaiin_abi.h.
const ABIVersion = 1

// Status codes shared with yuhaiin_abi.h.
const (
	statusOK         int32 = 0
	statusErr        int32 = -1
	statusUnknownOp  int32 = -2
	statusBadRequest int32 = -3
	statusPanic      int32 = -4
	statusNoHost     int32 = -5
)

// errBadRequest marks malformed request payloads.
type badRequestError struct{ err error }

func (e badRequestError) Error() string { return "bad request: " + e.err.Error() }
func (e badRequestError) Unwrap() error { return e.err }

var errNoHost = errors.New("platform host is not installed")

// host is the platform side (Kotlin through JNI on Android). Implementations
// must be safe for concurrent use: the core calls them from many goroutines.
type host interface {
	// Protect exempts fd from the VPN. It reports success.
	Protect(fd int32) bool
	// Bind binds an outbound socket to a platform Network: the handle, 0 when
	// unknown or -1 on failure.
	Bind(fd int32, iface string) int64
	// DumpUID returns the owner uid of a connection.
	DumpUID(protocol int32, srcIP string, srcPort int32, dstIP string, dstPort int32) (int32, error)
	// Establish builds the VPN interface and returns its descriptor.
	Establish(generation int64, config string) (int32, error)
	// Call is the generic callback. It returns the raw response.
	Call(op string, req []byte) ([]byte, error)
}

type hostBox struct{ host }

var currentHost atomic.Pointer[hostBox]

// installHost replaces the platform host; nil uninstalls it.
func installHost(h host) {
	if h == nil {
		currentHost.Store(nil)
		return
	}
	currentHost.Store(&hostBox{h})
}

func getHost() host {
	if b := currentHost.Load(); b != nil {
		return b.host
	}
	return nil
}

// hostCall invokes the generic host callback.
func hostCall(op string, req []byte) ([]byte, error) {
	h := getHost()
	if h == nil {
		return nil, errNoHost
	}
	return h.Call(op, req)
}

// operation handles one yh_call. It returns the raw response bytes.
type operation func(req []byte) ([]byte, error)

var operations = map[string]operation{}

func register(name string, op operation) {
	if _, dup := operations[name]; dup {
		panic("duplicate operation " + name)
	}
	operations[name] = op
}

// call dispatches an operation and converts failures into status codes. A
// panic inside an operation is recovered here and never unwinds into C.
func call(name string, req []byte) (resp []byte, status int32) {
	defer func() {
		if r := recover(); r != nil {
			resp = fmt.Appendf(nil, "panic in %s: %v\n%s", name, r, debug.Stack())
			status = statusPanic
		}
	}()
	op, ok := operations[name]
	if !ok {
		return []byte("unknown operation: " + name), statusUnknownOp
	}
	out, err := op(req)
	if err != nil {
		var bad badRequestError
		switch {
		case errors.As(err, &bad):
			return []byte(err.Error()), statusBadRequest
		case errors.Is(err, errNoHost):
			return []byte(err.Error()), statusNoHost
		}
		return []byte(err.Error()), statusErr
	}
	return out, statusOK
}

// decode parses a JSON request; an empty request decodes to the zero value.
func decode[T any](req []byte) (T, error) {
	var v T
	if len(req) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(req, &v); err != nil {
		return v, badRequestError{err}
	}
	return v, nil
}

func encode(v any) ([]byte, error) { return json.Marshal(v) }

// jsonOp adapts a typed JSON handler.
func jsonOp[Req, Resp any](fn func(Req) (Resp, error)) operation {
	return func(raw []byte) ([]byte, error) {
		req, err := decode[Req](raw)
		if err != nil {
			return nil, err
		}
		resp, err := fn(req)
		if err != nil {
			return nil, err
		}
		return encode(resp)
	}
}

type empty struct{}

// main is required by -buildmode=c-shared and is never called.
func main() {}
