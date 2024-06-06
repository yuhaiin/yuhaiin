module github.com/Asutorufa/yuhaiin

go 1.22.0

require (
	github.com/go-json-experiment/json v0.0.0-20240524174822-2d9f40f7385b
	github.com/libp2p/go-yamux/v4 v4.0.2-0.20240206065824-7222fbc3459d
	github.com/quic-go/quic-go v0.45.0
	github.com/refraction-networking/utls v1.6.6
	github.com/tailscale/wireguard-go v0.0.0-20240429185444-03c5a0ccf754
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20240524165444-4d4ba1473f21
	github.com/xtls/reality v0.0.0-20240429224917-ecc4401070cc
	github.com/yuhaiin/kitte v0.0.0-20240515014533-69bd6d4301f5
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20240603132443-404c784d941d
	go.etcd.io/bbolt v1.3.10
	golang.org/x/crypto v0.24.0
	golang.org/x/exp v0.0.0-20240531132922-fd00a4e0eefc
	golang.org/x/mobile v0.0.0-20240520174638-fa72addaaa1b
	golang.org/x/net v0.26.0
	golang.org/x/sys v0.21.0
	golang.org/x/time v0.5.0
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.1
	gvisor.dev/gvisor v0.0.0-20240601000839-2607065bd125
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20231212022811-ec68065c825e // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.13.2 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
)

replace golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
