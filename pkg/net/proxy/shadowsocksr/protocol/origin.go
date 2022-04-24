package protocol

func init() {
	register("origin", NewOrigin)
}

type origin struct{}

func NewOrigin(ProtocolInfo) IProtocol {
	a := &origin{}
	return a
}

func (o *origin) EncryptStream(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *origin) DecryptStream(data []byte) ([]byte, int, error) {
	return data, len(data), nil
}

func (o *origin) GetOverhead() int {
	return 0
}

func (a *origin) EncryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
func (a *origin) DecryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
