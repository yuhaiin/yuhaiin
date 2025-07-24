package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

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
			w.Write([]byte("hello"))
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
