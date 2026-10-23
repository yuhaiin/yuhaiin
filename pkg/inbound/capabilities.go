package inbound

import (
	"runtime"
	"slices"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
)

// Capabilities reports protocol support in this server, independent of the
// operating system used by the browser. It does not claim device permissions.
func Capabilities() contract.Capabilities {
	return capabilitiesFor(runtime.GOOS, runtime.GOARCH)
}

func capabilitiesFor(platform, arch string) contract.Capabilities {
	protocols := []string{contract.ProtocolHysteria2, contract.ProtocolMasque, contract.ProtocolHTTP, contract.ProtocolSocks5,
		contract.ProtocolYuubinsya, contract.ProtocolMixed, contract.ProtocolSocks4A, contract.ProtocolWireguard,
		contract.ProtocolKrunlet, contract.ProtocolReverseTCP, contract.ProtocolNone}
	if platform == "linux" || platform == "android" {
		protocols = append(protocols, contract.ProtocolTProxy)
	}
	if platform == "linux" || platform == "android" || platform == "darwin" {
		protocols = append(protocols, contract.ProtocolRedir)
	}
	// Named devices are implemented by the Linux, Windows and Unix adapters;
	// the Unix adapter excludes ppc64 and supports wireguard-go's BSD drivers.
	if slices.Contains([]string{"linux", "android", "windows"}, platform) || arch != "ppc64" && slices.Contains([]string{"darwin", "freebsd", "openbsd"}, platform) {
		protocols = append(protocols, contract.ProtocolTun)
	}
	return contract.Capabilities{Platform: platform, Protocols: protocols}
}
