package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestECDSALeafWithEd25519CA(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ca := &Ca{PrivateKey: key, Cert: &x509.Certificate{
		SerialNumber: big.NewInt(1), PublicKeyAlgorithm: x509.Ed25519,
		SignatureAlgorithm: x509.PureEd25519, PublicKey: key.Public(),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}}
	rootPEM, err := ca.CertBytes()
	assert.NoError(t, err)
	leaf, err := ca.GenerateServerCertWithAlgorithm(x509.ECDSA, "test.example")
	assert.NoError(t, err)
	certificate, err := leaf.TlsCert()
	assert.NoError(t, err)
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	assert.NoError(t, err)
	assert.Equal(t, x509.ECDSA, parsed.PublicKeyAlgorithm)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid root certificate")
	}
	_, err = parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "test.example"})
	assert.NoError(t, err)
}

func TestGenerate(t *testing.T) {
	ca, err := GenerateCa()
	assert.NoError(t, err)

	t.Log(ca.Cert.SignatureAlgorithm, ca.Cert.PublicKeyAlgorithm)

	sc, err := ca.GenerateServerCert("www.xx.com")
	assert.NoError(t, err)
	t.Log(sc.Cert.SignatureAlgorithm, sc.Cert.PublicKeyAlgorithm)
	tc, err := sc.TlsCert()
	assert.NoError(t, err)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer tcp.Close()
	go func() {
		tlss := tls.NewListener(tcp, &tls.Config{
			Certificates: []tls.Certificate{tc},
		})
		err := http.Serve(tlss, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello"))
		}))
		if errors.Is(err, net.ErrClosed) {
			return
		}
		assert.NoError(t, err)
	}()

	rootCa, err := x509.SystemCertPool()
	assert.NoError(t, err)
	rootCa.AddCert(ca.Cert)

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCa,
				ServerName: "www.xx.com",
			},
		},
	}

	res, err := hc.Get("https://" + tcp.Addr().String())
	assert.NoError(t, err)
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, "hello", string(data))
	t.Log(string(data))
}
