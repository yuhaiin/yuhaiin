//go:build cgo

package main

/*
#cgo CFLAGS: -I${SRCDIR} -DYH_NO_EXPORT_DECLS
#include <stdlib.h>
#include "yuhaiin_abi.h"

int32_t yh_host_protect(const yh_host *h, int32_t fd);
int64_t yh_host_bind(const yh_host *h, int32_t fd, const char *iface);
int32_t yh_host_dump_uid(const yh_host *h, int32_t proto, const char *src, int32_t sport,
                         const char *dst, int32_t dport);
int32_t yh_host_establish(const yh_host *h, int64_t generation, const char *config, char **error);
int32_t yh_host_call(const yh_host *h, const char *op, const uint8_t *req, size_t req_len,
                     uint8_t **resp, size_t *resp_len);
*/
import "C"

import (
	"errors"
	"unsafe"
)

//export yh_abi_version
func yh_abi_version() C.uint32_t { return ABIVersion }

//export yh_free
func yh_free(ptr unsafe.Pointer) { C.free(ptr) }

//export yh_call
func yh_call(operation *C.char, request *C.uint8_t, requestLen C.size_t, response **C.uint8_t, responseLen *C.size_t) C.int32_t {
	if response != nil {
		*response = nil
	}
	if responseLen != nil {
		*responseLen = 0
	}
	if operation == nil {
		return C.int32_t(statusBadRequest)
	}
	var req []byte
	if requestLen > 0 && request != nil {
		req = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out, status := call(C.GoString(operation), req)
	if len(out) > 0 && response != nil && responseLen != nil {
		p := C.malloc(C.size_t(len(out)))
		if p == nil {
			return C.int32_t(statusErr)
		}
		copy(unsafe.Slice((*byte)(p), len(out)), out)
		*response = (*C.uint8_t)(p)
		*responseLen = C.size_t(len(out))
	}
	return C.int32_t(status)
}

//export yh_set_host
func yh_set_host(h *C.yh_host) C.int32_t {
	if h == nil {
		installHost(nil)
		return C.int32_t(statusOK)
	}
	if uintptr(h.size) < unsafe.Sizeof(C.yh_host{}) {
		return C.int32_t(statusBadRequest) // the host predates this core
	}
	cp := new(C.yh_host) // immutable copy; in-flight callbacks keep it alive
	*cp = *h
	installHost(cHost{cp})
	installPlatform()
	return C.int32_t(statusOK)
}

// cHost implements host over the C callback table.
type cHost struct{ h *C.yh_host }

func (c cHost) Protect(fd int32) bool { return C.yh_host_protect(c.h, C.int32_t(fd)) != 0 }

func (c cHost) Bind(fd int32, iface string) int64 {
	s := C.CString(iface)
	defer C.free(unsafe.Pointer(s))
	return int64(C.yh_host_bind(c.h, C.int32_t(fd), s))
}

func (c cHost) DumpUID(proto int32, srcIP string, srcPort int32, dstIP string, dstPort int32) (int32, error) {
	src, dst := C.CString(srcIP), C.CString(dstIP)
	defer C.free(unsafe.Pointer(src))
	defer C.free(unsafe.Pointer(dst))
	uid := int32(C.yh_host_dump_uid(c.h, C.int32_t(proto), src, C.int32_t(srcPort), dst, C.int32_t(dstPort)))
	if uid < 0 {
		return 0, errors.New("uid lookup failed")
	}
	return uid, nil
}

func (c cHost) Establish(generation int64, config string) (int32, error) {
	cfg := C.CString(config)
	defer C.free(unsafe.Pointer(cfg))
	var cerr *C.char
	fd := int32(C.yh_host_establish(c.h, C.int64_t(generation), cfg, &cerr))
	if fd >= 0 {
		if cerr != nil {
			C.free(unsafe.Pointer(cerr))
		}
		return fd, nil
	}
	msg := "provider_unavailable: VPN establish failed"
	if cerr != nil {
		msg = C.GoString(cerr)
		C.free(unsafe.Pointer(cerr))
	}
	return -1, errors.New(msg)
}

func (c cHost) Call(op string, req []byte) ([]byte, error) {
	name := C.CString(op)
	defer C.free(unsafe.Pointer(name))
	var reqPtr *C.uint8_t
	if len(req) > 0 {
		p := C.malloc(C.size_t(len(req)))
		if p == nil {
			return nil, errors.New("out of memory")
		}
		defer C.free(p)
		copy(unsafe.Slice((*byte)(p), len(req)), req)
		reqPtr = (*C.uint8_t)(p)
	}
	var resp *C.uint8_t
	var respLen C.size_t
	status := int32(C.yh_host_call(c.h, name, reqPtr, C.size_t(len(req)), &resp, &respLen))
	var out []byte
	if resp != nil {
		out = C.GoBytes(unsafe.Pointer(resp), C.int(respLen))
		C.free(unsafe.Pointer(resp))
	}
	if status != 0 {
		if len(out) == 0 {
			return nil, errors.New("host call " + op + " failed")
		}
		return nil, errors.New(string(out))
	}
	return out, nil
}
