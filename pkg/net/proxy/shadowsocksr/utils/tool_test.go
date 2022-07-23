package ssr

import (
	"crypto"
	"testing"
)

func TestKDF(t *testing.T) {
	t.Log(KDF("12345678", 16))
}

func TestMd5Hmac(t *testing.T) {
	t.Log(Hmac(crypto.MD5, []byte("12345678"), []byte("12345678"), nil))
	// t.Log(HmacMD52([]byte("12345678"), []byte("12345678")))
	t.Log(Hmac(crypto.MD5, []byte("xxxx"), []byte("xxxx"), nil))
	// t.Log(HmacMD52([]byte("xxxx"), []byte("xxxx")))
	t.Log(Hmac(crypto.MD5, []byte("12345678"), []byte("12345678xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), nil))
	// t.Log(HmacMD52([]byte("12345678"), []byte("12345678xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")))
	t.Log(Hmac(crypto.MD5, []byte("xxxx"), []byte("xxxx"), nil))
	// t.Log(HmacMD52([]byte("xxxx"), []byte("xxxx")))
}
