package rc2

import (
	"crypto/cipher"
	_ "unsafe"

	_ "golang.org/x/crypto/pkcs12"
)

//go:linkname New golang.org/x/crypto/pkcs12/internal/rc2.New
func New(key []byte, t1 int) (cipher.Block, error)
