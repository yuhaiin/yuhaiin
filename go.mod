module github.com/Asutorufa/yuhaiin

go 1.21.5

require (
	github.com/libp2p/go-yamux/v4 v4.0.1
	github.com/quic-go/quic-go v0.40.1
	github.com/refraction-networking/utls v1.5.4
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/xtls/reality v0.0.0-20231112171332-de1173cf2b19
	go.etcd.io/bbolt v1.3.8
	golang.org/x/crypto v0.16.0
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa
	golang.org/x/mobile v0.0.0-20231108233038-35478a0c49da
	golang.org/x/net v0.19.0
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard v0.0.0-20231018191413-24ea13351eb7
	google.golang.org/grpc v1.60.0
	google.golang.org/protobuf v1.31.0
	gvisor.dev/gvisor v0.0.0-20231116050414-019eb8be3703
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.5 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20230926050212-f7f687d19a98 // indirect
	github.com/klauspost/compress v1.17.1 // indirect
	github.com/libp2p/go-buffer-pool v0.0.2 // indirect
	github.com/onsi/ginkgo/v2 v2.13.0 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.3.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231016165738-49dd2c1f3d0b // indirect
)

replace github.com/vishvananda/netlink => github.com/yuhaiin/netlink v0.0.0-20230919144802-e22cd926ecf5
