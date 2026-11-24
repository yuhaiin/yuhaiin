package inbound

import (
	"context"
	"os"
	"runtime"
	"slices"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/sshserver"
	"github.com/yuhaiin/sessionnet"
)

// Capabilities reports protocol support in this server, independent of the
// operating system used by the browser. It does not claim device permissions.
func Capabilities() contract.Capabilities {
	c := capabilitiesFor(runtime.GOOS, runtime.GOARCH)
	if slices.Contains(c.Protocols, contract.ProtocolSSH) {
		c.SSH = sshCapabilities()
	}
	return c
}

// CapabilitiesWithEnvironment adds the detected SSH session environment,
// which creates a short-lived probe session (cached briefly).
func CapabilitiesWithEnvironment(ctx context.Context) contract.Capabilities {
	c := Capabilities()
	if c.SSH != nil {
		c.SSH.Environment = new(sshserver.DetectEnvironment(ctx))
	}
	return c
}

// sshCapabilities names the Yuhaiin account by host IDs, the ID space of the
// SSH inbound uid/gid settings.
func sshCapabilities() *contract.SSHCapabilities {
	ssh := &contract.SSHCapabilities{ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid())}
	if own, err := sessionnet.DefaultCredential(); err == nil {
		ssh.ServiceUID, ssh.ServiceGID = own.UID, own.GID
	}
	if ns, err := sessionnet.CurrentUserNamespace(); err == nil {
		ssh.Root = ns.Initial && os.Geteuid() == 0
	}
	return ssh
}

func capabilitiesFor(platform, arch string) contract.Capabilities {
	protocols := []string{contract.ProtocolHysteria2, contract.ProtocolMasque, contract.ProtocolHTTP, contract.ProtocolSocks5,
		contract.ProtocolYuubinsya, contract.ProtocolMixed, contract.ProtocolSocks4A, contract.ProtocolWireguard, contract.ProtocolSSTP,
		contract.ProtocolKrunlet, contract.ProtocolReverseTCP, contract.ProtocolLANLink, contract.ProtocolNone}
	if platform == "linux" {
		protocols = append(protocols, contract.ProtocolSSH)
	}
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
