package protocol

import (
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

func init() {
	register("origin", NewOrigin)
}

type origin struct {
	ssr.ServerInfo
}

func NewOrigin(ssr.ServerInfo) IProtocol {
	a := &origin{}
	return a
}

func (o *origin) PreEncrypt(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *origin) PostDecrypt(data []byte) ([]byte, int, error) {
	return data, len(data), nil
}

func (o *origin) GetOverhead() int {
	return 0
}

func (o *origin) AddOverhead(int) {}

func (o *origin) GetData() interface{}     { return &AuthData{} }
func (o *origin) SetData(data interface{}) {}

func (a *origin) PreEncryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
func (a *origin) PostDecryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
