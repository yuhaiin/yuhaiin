package manager

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func encodeChain(chain [][]byte) []byte {
	var result []byte
	for _, der := range chain {
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return result
}

func encodeSigner(key any) (certificates.Secret, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return certificates.Secret{}, err
	}
	return certificates.NewSecret(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
