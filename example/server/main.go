package main

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func main() {
	bootstrap1, _ := resolver.NewDoU(resolver.Config{Host: "1.1.1.1", Dialer: direct.Default})
	Internet := resolver.NewClient(resolver.Config{Name: "internet"}, bootstrap1)
	netapi.SetBootstrap(Internet)
	lis, err := net.Listen("tcp", "0.0.0.0:3333")
	must(err)
	defer func() { must(lis.Close()) }()

	cab := []byte(`-----BEGIN CERTIFICATE-----
MIIDUTCCAjmgAwIBAgIQV5lZYOBwZXQkaYrqzGG2XTANBgkqhkiG9w0BAQsFADAy
MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMC
RTYwIBcNMjYwMTA3MDcxNzE5WhgPMjEyNTEyMTQwNzE3MTlaMDIxCzAJBgNVBAYT
AlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJFNjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANv3WTvfE5du+oIR/Jjtj/XpG9fuNIZz
SmpVXjvjWT/bKgD+L0iNxFRZKKI5BzbpE7RX2OKrYpsPHWxmvtfo9tu0o3TJKIgs
8h5zlKq6VdvXPqn26GAB4dO3/a+G0AFykfmZpR53OS/Fz3r0DNk9xAPWolAeQQMl
PT+UAecbDT54g7BirFhbVcXE8ggDbkcmWz5vqwSrD95V3P50cYCBAiebeXU9+ukf
Ad5mj8Ichf9/quLYQd5BAmbviNnlOcuItJLeZJ4ijfcXIZTDu9dav95JEAUJlSOf
dQS/YXvm/OpnOA95HEA9+9vQKiWMqtzSUVeB77+oQi7ipVZrVFMROWMCAwEAAaNh
MF8wDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTCIDlSfH9YjPDB5cLnGXGmEWSX
sjANBgkqhkiG9w0BAQsFAAOCAQEACxi0joTig0JXC2B9KBs3oj+WzOT0ve7zCPvp
PuQYZ6C+FQgeyqkrF6NT5UGi+HOZv2qiAWmIxbmEBQ7hNp6m/qbvQbnpPUH9Yzuu
3dkNa5/uKVNbw/NoRkAFGcnWzNmnWSLPwEmbsdl4lQrWTJDgaZIELN60gh51B/s0
M7OS6TNQd8UWDf5nXYhMx8bhdD4BzrwgBIOaj5RGwlGUX3btT6uLeqjNLtYJcHFe
zcZvySFcWsHy3yM9ZwuaUFo4HAsQKsjJF11BgC25vVCYrV0X4vORAx2sOuw8OpFv
ZLOIPND1zt747zOwU2olyTOnZklWh/wFjYixeshBIYqFLjqoSg==
-----END CERTIFICATE-----
`)
	fmt.Println(string(cab))

	pkb := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb91k73xOXbvqC
EfyY7Y/16RvX7jSGc0pqVV4741k/2yoA/i9IjcRUWSiiOQc26RO0V9jiq2KbDx1s
Zr7X6PbbtKN0ySiILPIec5SqulXb1z6p9uhgAeHTt/2vhtABcpH5maUedzkvxc96
9AzZPcQD1qJQHkEDJT0/lAHnGw0+eIOwYqxYW1XFxPIIA25HJls+b6sEqw/eVdz+
dHGAgQInm3l1PfrpHwHeZo/CHIX/f6ri2EHeQQJm74jZ5TnLiLSS3mSeIo33FyGU
w7vXWr/eSRAFCZUjn3UEv2F75vzqZzgPeRxAPfvb0ColjKrc0lFXge+/qEIu4qVW
a1RTETljAgMBAAECggEAUWugxacghtzG8E99GxRQRdun+UkMezoAsRRxYaSZXCgh
R6XO1cHYCsrH3ihS0dH7f7VGrDx5LuEs6Hutp5jti0y1dlyhWqqcYoYw4PNBJbNq
WBpzUFpR/37q8cZqhyaj/uqO8pR6AANt9dqRSPZycGNJyHMyaFon7jk4bRWX1Oex
3quxXZFjxqaOQ/6gZaRmzsru33imKdKpRYAsZhpmDZl63Yig1dKkgslCWx89YHxQ
xReqeL6pxX+wmPlVVXSpYqEEzF3aT8muMHYqGYZSvPtbpMhVACphp30M/RcCiMNd
VbFXxL7JZVYFCRrIFkyNGYjv2pcnDyWk6P0iQO6SRQKBgQD/PKcMQPuMDq0BeB7T
KSfqZi6zPlSN/ycNZaHCnZpMXaZMgY7eYwFemibNoxioHETkWp//f6oePottxdQx
jgi3f2htwTCfe9rej1N4Kgggg0Vg4IzpmWnfi3zj9FkOfxFGU28Mba+hahsOcQEF
Iu32pua3Ykz55lNpjpA6rYB37QKBgQDcn7OKl5Mag4s7bK8dKLJgEu+9WraAU3qR
5wQammou27Uf4Gdc6d5GJc0A4ZBf7LLp2UR6nNcUZ4ZYDqNDCzWtD2IRQIbf8Bga
KJTh9EmHPnT6188jiGaVV9dreiQ94A7qkCspZZHBUZ3d2PdBGjfl7jg6mgPhfR8y
bI5ciUesjwKBgEee52ki2vNEMvvUjyHFzLOTlMsrVGK8FGNH/4oy21dOeBnDySlS
MtIvA3B0sbiKpjJF09vIIR53gnx9JLv7FSsYj18s9M3r3VDSeyOe98TX0SIMIL50
FCdsZtE4gbz1nw1S4Dhmlv/+XDVDNHwSfx/VWaxf4yXEoede3833XbNJAoGARJ/E
N+q3zfp2t3Ax8+7xtOKPAaYSuE2/BV0HMMMxHgwnBZhGbmcsRUOCxbBjuQKmEAkN
vNnGKMmexwseiz8UXhU32sfobAWBabmPvcy/hjrOJiw0eQf3aKKfFgYy+bAU068u
Tb0THj+lzBitp+lg07tKcCfx5xSFPKj5ix0EV08CgYEAmm8B009tSS/0SZxn8gzG
J+KLzcaNTCqJW3iGZYU4bChG5mX95yDEuNltpATRR521X2qEl4wWpqAZ+UWvkdue
c9OCqqGQpVnJ7uhOZ6ygnVbs8P0+7NFjF9/4rumfC4oijM7LmddvWO4HCbHIu+hc
TGV6S/Av/lWZyEMrO6yxhoM=
-----END PRIVATE KEY-----
`)
	fmt.Println(string(pkb))

	nlis, err := tls.NewTlsAutoServer(config.TlsAuto_builder{
		CaCert:      cab,
		CaKey:       pkb,
		Servernames: []string{"www.example.t.com"},
	}.Build(), netapi.NewListener(lis, nil))
	must(err)
	defer func() { must(nlis.Close()) }()

	s, err := yuubinsya.NewServer(config.Yuubinsya_builder{
		Password: proto.String("123"),
	}.Build(), netapi.NewListener(nlis, nil), &handler{})
	must(err)
	defer s.Close()

ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT)
	defer cancel()

	<-ctx.Done()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type handler struct{}

func (h *handler) HandleStream(req *netapi.StreamMeta) {
	ips, err := net.LookupIP(req.Address.Hostname())
	if err != nil {
		log.Error("lookup failed", "err", err)
		return
	}

	if len(ips) == 0 {
		log.Error("lookup failed empty", "err", err)
		return
	}

	log.Info("connect", "ip", ips[0].String(), "port", req.Address.Port())

dconn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ips[0].String(), strconv.Itoa(int(req.Address.Port()))))
	if err != nil {
		log.Error("dial failed", "err", err)
		return
	}
	defer dconn.Close()

	relay.Relay(dconn, req.Src)
}

func (h *handler) HandlePacket(*netapi.Packet) {}
func (h *handler) HandlePing(*netapi.PingMeta) {}
