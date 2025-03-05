module github.com/Asutorufa/yuhaiin

go 1.24.0

require (
	github.com/godbus/dbus/v5 v5.1.1-0.20241109141217-c266b19b28e9
	github.com/google/nftables v0.3.0
	github.com/google/uuid v1.6.0
	github.com/libp2p/go-yamux/v5 v5.0.0
	github.com/prometheus/client_golang v1.21.1
	github.com/quic-go/quic-go v0.50.0
	github.com/refraction-networking/utls v1.6.7
	github.com/tailscale/wireguard-go v0.0.0-20250304000100-91a0587fb251
	github.com/vishvananda/netlink v1.3.0
	github.com/xtls/reality v0.0.0-20240909153216-e26ae2305463
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20250308101321-1303041d2d73
	// for fix https://github.com/etcd-io/bbolt/issues/840
	go.etcd.io/bbolt v1.4.0
	golang.org/x/crypto v0.36.0
	golang.org/x/mobile v0.0.0-20250305212854-3a7bc9f8a4de
	golang.org/x/net v0.37.0
	golang.org/x/sys v0.31.0
	golang.org/x/time v0.11.0
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/grpc v1.71.0
	google.golang.org/protobuf v1.36.5
	gvisor.dev/gvisor v0.0.0-20250212202256-d8010a143980
	tailscale.com v1.80.3
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.29.5 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.58 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssm v1.44.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.13 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/coreos/go-iptables v0.7.1-0.20240112124308-65c67c9f46e6 // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gaissmai/bart v0.18.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20250223041408-d3c622f1b874 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20250208200701-d0013a598941 // indirect
	github.com/gorilla/csrf v1.7.3-0.20250123201450-9dd6af1f6d30 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/illarion/gonotify/v3 v3.0.2 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20231206064809-8c70d406f6d2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/kortschak/wol v0.0.0-20200729010619-da482cc4850a // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/sdnotify v1.0.0 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/miekg/dns v1.1.58 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.13.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pires/go-proxyproto v0.7.0 // indirect
	github.com/prometheus-community/pro-bing v0.4.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/tailscale/certstore v0.1.1-0.20231202035212-d3fa0460f47e // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.5.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20250228200357-dead58393ab7 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/term v0.30.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)

replace golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e

replace tailscale.com => github.com/Asutorufa/tailscale v0.0.0-20250305052811-8b7a8d94ca60
