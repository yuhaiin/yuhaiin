package ssr

import (
	"crypto"
	"hash"
)

type customHmac interface {
	Reset(key []byte)
	Write(p []byte) (n int, err error)
	Size() int
	BlockSize() int
	Sum(in []byte) []byte
	Hash() crypto.Hash
}

type chmac struct {
	opad, ipad   []byte
	outer, inner hash.Hash

	h crypto.Hash
}

func (h *chmac) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)

	h.outer.Reset()
	h.outer.Write(h.opad)
	h.outer.Write(in[origLen:])
	return h.outer.Sum(in[:origLen])
}

func (h *chmac) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *chmac) Size() int      { return h.outer.Size() }
func (h *chmac) BlockSize() int { return h.inner.BlockSize() }

func memsetRepeat(a []byte, v byte) {
	if len(a) == 0 {
		return
	}
	a[0] = v
	for bp := 1; bp < len(a); bp *= 2 {
		copy(a[bp:], a[:bp])
	}
}

func (h *chmac) Reset(key []byte) {
	blockSize := h.inner.BlockSize()
	if len(key) > blockSize {
		h.outer.Reset()
		// If key is too big, hash it.
		h.outer.Write(key)
		key = h.outer.Sum(nil)
	}
	memsetRepeat(h.ipad, 0x0)
	memsetRepeat(h.opad, 0x0)
	copy(h.ipad, key)
	copy(h.opad, key)
	for i := range h.ipad {
		h.ipad[i] ^= 0x36
	}
	for i := range h.opad {
		h.opad[i] ^= 0x5c
	}
	h.inner.Reset()
	h.inner.Write(h.ipad)
}

// NewHmac returns a new HMAC hash using the given hash.Hash type and key.
// NewHmac functions like sha256.NewHmac from crypto/sha256 can be used as h.
// h must return a new Hash every time it is called.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewHmac(h crypto.Hash) customHmac {
	hm := new(chmac)
	hm.h = h
	hm.outer = h.New()
	hm.inner = h.New()
	unique := true
	func() {
		defer func() {
			// The comparison might panic if the underlying types are not comparable.
			_ = recover()
		}()
		if hm.outer == hm.inner {
			unique = false
		}
	}()
	if !unique {
		panic("crypto/hmac: hash generation function does not produce unique values")
	}
	blocksize := hm.inner.BlockSize()
	hm.ipad = make([]byte, blocksize)
	hm.opad = make([]byte, blocksize)
	return hm
}

func (h *chmac) Hash() crypto.Hash {
	return h.h
}
