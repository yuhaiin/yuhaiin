module github.com/Asutorufa/yuhaiin

go 1.23.0

require (
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8
	github.com/libp2p/go-yamux/v4 v4.0.2-0.20240206065824-7222fbc3459d
	github.com/prometheus/client_golang v1.20.3
	github.com/quic-go/quic-go v0.46.0
	github.com/refraction-networking/utls v1.6.7
	github.com/tailscale/wireguard-go v0.0.0-20240724015428-60eeedfd624b
	github.com/vishvananda/netlink v1.3.0
	github.com/xtls/reality v0.0.0-20240712055506-48f0b2d5ed6d
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20240826143240-1abd5a1a38b9
	go.etcd.io/bbolt v1.3.11
	golang.org/x/crypto v0.26.0
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa
	golang.org/x/mobile v0.0.0-20240806205939-81131f6468ab
	golang.org/x/net v0.28.0
	golang.org/x/sys v0.24.0
	golang.org/x/time v0.6.0
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
	gvisor.dev/gvisor v0.0.0-20240819215755-2a492e6970fd
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.13.2 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.20.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
)

replace golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
