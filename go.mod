module github.com/Asutorufa/yuhaiin

go 1.22.0

require (
	github.com/google/pprof v0.0.0-20240625030939-27f56978b8b0
	github.com/libp2p/go-yamux/v4 v4.0.2-0.20240206065824-7222fbc3459d
	github.com/quic-go/quic-go v0.45.1
	github.com/refraction-networking/utls v1.6.7
	github.com/tailscale/wireguard-go v0.0.0-20240705152531-2f5d148bcfe1
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20240524165444-4d4ba1473f21
	github.com/xtls/reality v0.0.0-20240712055506-48f0b2d5ed6d
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20240721101322-5be00099c3cd
	go.etcd.io/bbolt v1.3.10
	golang.org/x/crypto v0.25.0
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8
	golang.org/x/mobile v0.0.0-20240604190613-2782386b8afd
	golang.org/x/net v0.27.0
	golang.org/x/sys v0.22.0
	golang.org/x/time v0.5.0
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
	gvisor.dev/gvisor v0.0.0-20240718221906-48cc2545899e
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.13.2 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
)

replace golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
