module github.com/Asutorufa/yuhaiin

go 1.21.1

toolchain go1.21.6

require (
	github.com/libp2p/go-yamux/v4 v4.0.2-0.20231213140704-4c5812896512
	github.com/quic-go/quic-go v0.40.1-0.20240105102142-0a922b4e7d13
	github.com/refraction-networking/utls v1.6.1
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/xtls/reality v0.0.0-20231112171332-de1173cf2b19
	go.etcd.io/bbolt v1.3.8
	golang.org/x/crypto v0.18.0
	golang.org/x/exp v0.0.0-20240110193028-0dcbfd608b1e
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	golang.org/x/net v0.20.0
	golang.org/x/sys v0.16.0
	golang.org/x/time v0.5.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.32.0
	gvisor.dev/gvisor v0.0.0-20231216175137-0e649a1ce9ad
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20231212022811-ec68065c825e // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.13.2 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.3.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.16.1 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231212172506-995d672761c0 // indirect
)

replace github.com/vishvananda/netlink => github.com/yuhaiin/netlink v0.0.0-20230919144802-e22cd926ecf5
