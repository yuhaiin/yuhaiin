package crypto

import (
	"crypto/sha256"
	"hash"
)

type Hash interface {
	New() hash.Hash
	Size() int
}

var Sha256 = sha256Hash{}

type sha256Hash struct{}

func (sha256Hash) New() hash.Hash { return sha256.New() }
func (sha256Hash) Size() int      { return sha256.Size }
