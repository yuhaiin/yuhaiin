package protocol

import "bytes"

type origin struct{}

var _origin = &origin{}

func NewOrigin(Protocol) protocol { return _origin }
func (o *origin) EncryptStream(dst *bytes.Buffer, data []byte) (err error) {
	dst.Write(data)
	return nil
}
func (o *origin) DecryptStream(dst *bytes.Buffer, data []byte) (int, error) { return dst.Write(data) }
func (o *origin) GetOverhead() int                                          { return 0 }
func (a *origin) EncryptPacket(b []byte) ([]byte, error)                    { return b, nil }
func (a *origin) DecryptPacket(b []byte) ([]byte, error)                    { return b, nil }
