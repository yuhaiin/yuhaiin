package protocol

import "crypto"

func NewAuthAES128SHA1(info Protocol) protocol { return newAuthAES128(info, crypto.SHA1) }
