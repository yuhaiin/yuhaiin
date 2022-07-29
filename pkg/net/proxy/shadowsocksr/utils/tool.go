package ssr

import (
	"crypto"
	"hash"
	"sync"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	_ "github.com/shadowsocks/go-shadowsocks2/core"
)

var hmacPool syncmap.SyncMap[crypto.Hash, *sync.Pool]

func getHmac(hash crypto.Hash, key []byte) CHmac {
	z, ok := hmacPool.Load(hash)
	if !ok {
		z = &sync.Pool{New: func() interface{} { return NewHmac(hash) }}
		hmacPool.Store(hash, z)
	}

	h := z.Get().(CHmac)
	h.ResetKey(key)
	return h
}

func putHmac(h CHmac) {
	z, ok := hmacPool.Load(h.Hash())
	if !ok {

		z = &sync.Pool{New: func() interface{} { return NewHmac(h.Hash()) }}
		hmacPool.Store(h.Hash(), z)
	}
	z.Put(h)
}

func Hmac(c crypto.Hash, key, data, buf []byte) []byte {
	h := getHmac(c, key)
	defer putHmac(h)

	h.Write(data)

	if buf == nil {
		buf = make([]byte, h.Size())
	}

	copy(buf, h.Sum(nil))
	return buf
}

var hashPool syncmap.SyncMap[crypto.Hash, *sync.Pool]

type chash struct {
	hash.Hash
	h crypto.Hash
}

func (c chash) CryptoHash() crypto.Hash { return c.h }

func newCHash(c crypto.Hash) *chash { return &chash{h: c, Hash: c.New()} }

func getHash(ha crypto.Hash) *chash {
	h, ok := hashPool.Load(ha)
	if !ok {
		h = &sync.Pool{New: func() interface{} { return newCHash(ha) }}
		hashPool.Store(ha, h)
	}
	z := h.Get().(*chash)
	z.Reset()
	return z
}

func putHash(hh *chash) {
	h, ok := hashPool.Load(hh.CryptoHash())
	if !ok {
		h = &sync.Pool{New: func() interface{} { return newCHash(hh.CryptoHash()) }}
		hashPool.Store(hh.CryptoHash(), h)
	}
	hh.Reset()
	h.Put(hh)
}

func HashSum(h crypto.Hash, d []byte) []byte {
	hh := getHash(h)
	defer putHash(hh)
	hh.Reset()
	hh.Write(d)
	return hh.Sum(nil)
}

//go:linkname KDF github.com/shadowsocks/go-shadowsocks2/core.kdf
func KDF(string, int) []byte
