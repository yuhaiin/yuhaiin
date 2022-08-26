package protocol

import "crypto"

func NewAuthAES128SHA1(info Info) Protocol { return newAuthAES128(info, crypto.SHA1) }
