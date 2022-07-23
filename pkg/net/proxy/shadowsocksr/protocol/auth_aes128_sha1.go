package protocol

import "crypto"

func init() {
	register("auth_aes128_sha1", NewAuthAES128SHA1)
}

func NewAuthAES128SHA1(info ProtocolInfo) IProtocol { return newAuthAES128(info, crypto.SHA1) }
