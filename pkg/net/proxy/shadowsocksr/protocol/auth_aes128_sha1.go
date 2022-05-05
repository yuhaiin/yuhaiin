package protocol

import (
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func init() {
	register("auth_aes128_sha1", NewAuthAES128SHA1)
}

func NewAuthAES128SHA1(info ProtocolInfo) IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_sha1",
		hmac:       ssr.HmacSHA1,
		hashDigest: ssr.SHA1Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
			wbuf:   utils.GetBuffer(),
			rbuf:   utils.GetBuffer(),
		},

		key:    info.Key,
		keyLen: info.KeySize,
		iv:     info.IV,
		ivLen:  info.IVSize,
		param:  info.Param,
		auth:   info.Auth,
	}
	a.initUserKey()
	return a
}
