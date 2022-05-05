package protocol

import (
	"bytes"
	"encoding/binary"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func init() {
	register("verify_sha1", NewVerifySHA1)
	register("ota", NewVerifySHA1)
}

type verifySHA1 struct {
	ProtocolInfo
	hasSentHeader bool
	buffer        *bytes.Buffer
	chunkId       uint32
}

const (
	oneTimeAuthMask byte = 0x10
)

func NewVerifySHA1(info ProtocolInfo) IProtocol {
	a := &verifySHA1{
		ProtocolInfo: info,
		buffer:       utils.GetBuffer(),
	}
	return a
}

func (v *verifySHA1) otaConnectAuth(data []byte) []byte {
	return append(data, ssr.HmacSHA1(append(v.IV, v.Key...), data)...)
}

func (v *verifySHA1) otaReqChunkAuth(chunkId uint32, data []byte) {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)

	v.buffer.Write(nb)
	v.buffer.Write(ssr.HmacSHA1(append(v.IV, chunkIdBytes...), data))
	v.buffer.Write(data)
}

func (v *verifySHA1) otaVerifyAuth(iv []byte, chunkId uint32, data []byte, expectedHmacSha1 []byte) bool {
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
	actualHmacSha1 := ssr.HmacSHA1(append(iv, chunkIdBytes...), data)
	return bytes.Equal(expectedHmacSha1, actualHmacSha1)
}

func (v *verifySHA1) getAndIncreaseChunkId() (chunkId uint32) {
	chunkId = v.chunkId
	v.chunkId += 1
	return
}

func (v *verifySHA1) EncryptStream(data []byte) (encryptedData []byte, err error) {
	v.buffer.Reset()
	dataLength := len(data)
	offset := 0
	if !v.hasSentHeader {
		data[0] |= oneTimeAuthMask
		v.buffer.Write(v.otaConnectAuth(data[:v.HeadSize]))
		v.hasSentHeader = true
		dataLength -= v.HeadSize
		offset += v.HeadSize
	}
	const blockSize = 4096
	for dataLength > blockSize {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(chunkId, data[offset:offset+blockSize])
		dataLength -= blockSize
		offset += blockSize
	}
	if dataLength > 0 {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(chunkId, data[offset:])
	}
	return v.buffer.Bytes(), nil
}

func (v *verifySHA1) DecryptStream(data []byte) ([]byte, int, error) {
	return data, len(data), nil
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

func (a *verifySHA1) Close() error {
	return nil
}
