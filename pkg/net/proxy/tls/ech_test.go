package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

func TestEch(t *testing.T) {
	ca, err := cert.GenerateCa()
	assert.NoError(t, err)

	sc, err := ca.GenerateServerCert("www.realdomain.com")
	assert.NoError(t, err)

	cert, err := sc.TlsCert()
	assert.NoError(t, err)

	private, config, err := NewECHConfig(0, []byte("www.example.com"))
	assert.NoError(t, err)

	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	tlsc := tls.NewListener(lis, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{
				Config:      config,
				PrivateKey:  private.Bytes(),
				SendAsRetry: true,
			},
		},
	})

	go func() {
		for {
			conn, err := tlsc.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()

				buf := make([]byte, 1024)

				n, err := conn.Read(buf)
				if err != nil {
					t.Error(err)
				}

				_, err = conn.Write(buf[:n])
				if err != nil {
					t.Error(err)
				}
			}()
		}
	}()

	configList, err := ECHConfigList([]ECHConfig{config})
	assert.NoError(t, err)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Cert)

	conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		RootCAs:                        rootPool,
		EncryptedClientHelloConfigList: configList,
		ServerName:                     "www.realdomain.com",
	})
	assert.NoError(t, err)

	_, err = conn.Write([]byte("www.realdomain.com"))
	assert.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	assert.NoError(t, err)

	assert.Equal(t, true, assert.ObjectsAreEqual(buf[:n], []byte("www.realdomain.com")))
}

func TestParse(t *testing.T) {
	t.Run("parse client", func(t *testing.T) {
		_, config, err := NewECHConfig(0, []byte("www.example.com"))
		assert.NoError(t, err)

		configList, err := ECHConfigList([]ECHConfig{config})
		assert.NoError(t, err)

		resp, err := parseEchConfigListOrConfig(config)
		assert.NoError(t, err)

		assert.Equal(t, true, assert.ObjectsAreEqual(resp, configList))

		resp, err = parseEchConfigListOrConfig(configList)
		assert.NoError(t, err)

		assert.Equal(t, true, assert.ObjectsAreEqual(resp, configList))

		t.Run("error", func(t *testing.T) {
			_, err = parseEchConfigListOrConfig([]byte{0, 23, 123, 34, 23, 65, 231, 45})
			assert.Error(t, err)
		})
	})
}

func TestXxx(t *testing.T) {
	x := "<bilibili_mcdn>.a.c.v.d"

	i := strings.IndexByte(x, '.')

	t.Log(x[:i], x[i+1:])

	prefix := fmt.Sprintf("xy%dx%dx%dx%dxy", rand.IntN(255), rand.IntN(255), rand.IntN(255), rand.IntN(255))

	if rand.IntN(2) == 0 {
		ipv6 := net.IP{
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			byte(rand.IntN(255)), byte(rand.IntN(255)),
			0, 0,
			0, 0,
			0, 0,
			byte(rand.IntN(255)), byte(rand.IntN(255)),
		}.String()

		ipv6 = strings.ReplaceAll(ipv6, ":", "y")

		prefix += ipv6 + "xy"
	}

	t.Log(prefix)
}
