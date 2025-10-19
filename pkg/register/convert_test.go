package register

import (
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestConvert(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		t.Run("tls auto", func(t *testing.T) {
			ca, err := cert.GenerateCa()
			assert.NoError(t, err)

			b, err := ca.CertBytes()
			assert.NoError(t, err)

			k, err := ca.PrivateKeyBytes()
			assert.NoError(t, err)

			pp, err := ConvertTransport(config.Transport_builder{
				TlsAuto: config.TlsAuto_builder{
					NextProtos: []string{"123"},
					Servernames: []string{
						"*.google.com",
						"www.x.com",
					},
					CaCert: b,
					CaKey:  k,
					// TODO ECH
				}.Build(),
			}.Build())
			assert.NoError(t, err)

			assert.MustEqual(t, pp.GetTls().GetNextProtos(), []string{"123"})
			assert.MustEqual(t, pp.GetTls().GetCaCert()[0], b)

			for _, servername := range pp.GetTls().GetServerNames() {
				if strings.HasSuffix(servername, "google.com") {
					continue
				}

				if servername == "www.x.com" {
					continue
				}

				t.Error("unexpected servername", servername)
			}
		})
	})
}
