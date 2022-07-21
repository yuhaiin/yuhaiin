package ssr

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	_ "unsafe"

	_ "github.com/shadowsocks/go-shadowsocks2/core"
)

func HmacMD5(key []byte, data []byte) []byte {
	hmacMD5 := hmac.New(md5.New, key)
	hmacMD5.Write(data)
	return hmacMD5.Sum(nil)[:16]
}

func HmacSHA1(key []byte, data []byte) []byte {
	hmacSHA1 := hmac.New(sha1.New, key)
	hmacSHA1.Write(data)
	return hmacSHA1.Sum(nil)[:20]
}

func MD5Sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func SHA1Sum(d []byte) []byte {
	h := sha1.New()
	h.Write(d)
	return h.Sum(nil)
}

//go:linkname KDF github.com/shadowsocks/go-shadowsocks2/core.kdf
func KDF(string, int) []byte
