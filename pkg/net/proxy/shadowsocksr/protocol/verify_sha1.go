//nolint:unused // OTA verification is retained for legacy ShadowsocksR compatibility.
package protocol

import (
	"bytes"
	"crypto"
	"encoding/binary"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type verifySHA1 struct {
	Protocol
	hasSentHeader bool
	chunkId       uint32
	hmac          ssr.HMAC
}

const (
	oneTimeAuthMask byte = 0x10
)

func NewVerifySHA1(info Protocol) protocol {
	a := &verifySHA1{
		Protocol: info,
		hmac:     ssr.HMAC(crypto.SHA1),
	}
	return a
}

func (v *verifySHA1) otaConnectAuth(data []byte) []byte {
	key := make([]byte, len(v.IV)+len(v.Key()))
	copy(key, v.IV)
	copy(key[len(v.IV):], v.Key())
	out := make([]byte, 0, len(data)+20)
	out = append(out, data...)
	return append(out, v.hmac.HMAC(key, data, nil)...)
}

func (v *verifySHA1) otaReqChunkAuth(buffer *pool.Buffer, chunkId uint32, data []byte) {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)

	_, _ = buffer.Write(nb)
	key := make([]byte, len(v.IV)+len(chunkIdBytes))
	copy(key, v.IV)
	copy(key[len(v.IV):], chunkIdBytes)
	_, _ = buffer.Write(v.hmac.HMAC(key, data, nil))
	_, _ = buffer.Write(data)
}

func (v *verifySHA1) otaVerifyAuth(iv []byte, chunkId uint32, data []byte, expectedHmacSha1 []byte) bool {
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
	key := make([]byte, len(iv)+len(chunkIdBytes))
	copy(key, iv)
	copy(key[len(iv):], chunkIdBytes)
	actualHmacSha1 := v.hmac.HMAC(key, data, nil)
	return bytes.Equal(expectedHmacSha1, actualHmacSha1)
}

func (v *verifySHA1) getAndIncreaseChunkId() (chunkId uint32) {
	chunkId = v.chunkId
	v.chunkId += 1
	return
}

func (v *verifySHA1) EncryptStream(buffer *pool.Buffer, data []byte) (err error) {
	dataLength := len(data)
	offset := 0
	if dataLength == 0 {
		return nil
	}
	if !v.hasSentHeader {
		headSize := v.HeadSize
		if headSize <= 0 {
			headSize = GetHeadSize(data, 30)
		}
		headSize = min(headSize, dataLength)
		header := append([]byte(nil), data[:headSize]...)
		header[0] |= oneTimeAuthMask
		_, _ = buffer.Write(v.otaConnectAuth(header))
		v.hasSentHeader = true
		dataLength -= headSize
		offset += headSize
	}
	const blockSize = 4096
	for dataLength > blockSize {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(buffer, chunkId, data[offset:offset+blockSize])
		dataLength -= blockSize
		offset += blockSize
	}
	if dataLength > 0 {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(buffer, chunkId, data[offset:])
	}
	return nil
}

func (v *verifySHA1) DecryptStream(dst *pool.Buffer, data []byte) (int, error) {
	return dst.Write(data)
}

func (v *verifySHA1) GetOverhead() int {
	return 0
}

func (a *verifySHA1) EncryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
func (a *verifySHA1) DecryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
