package yuhaiin

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
)

type CIDR struct {
	IP   string
	Mask int32
}

// ProxyGet fetches a URL through the configured Go proxy chain. It is exposed
// to the Android Compose updater through the generated AAR bindings.
func ProxyGet(rawURL string) ([]byte, error) {
	resp, err := updatepkg.NewProxyHTTPClient().Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("proxy request failed: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// ProxyDownload downloads a file through the configured Go proxy chain into
// destination. Callers should provide a temporary destination and atomically
// move it into place after this function returns successfully.
func ProxyDownload(rawURL, destination string) error {
	resp, err := updatepkg.NewProxyHTTPClient().Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("proxy download failed: %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	tmp, err := os.Create(destination)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(destination)
	}
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 512<<20)); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func ParseCIDR(s string) (*CIDR, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	mask, _ := ipNet.Mask.Size()
	ip := ipNet.IP.String()
	return &CIDR{IP: ip, Mask: int32(mask)}, nil
}

type AddRoute interface {
	Add(*CIDR)
}

func FakeDnsCidr(f func(string)) {
	db, err := newResolverDB().SQLDB(context.Background())
	if err != nil {
		log.Error("view resolver db failed", "err", err)
		return
	}
	config, err := plainstore.NewResolverConfigStore(db).FakeDNS(context.Background())
	if err != nil {
		log.Error("get fakedns config failed", "err", err)
		return
	}
	f(config.IPv4Range)
	f(config.IPv6Range)
}

func IsIPv6() bool {
	db, err := newChoreDB().SQLDB(context.Background())
	if err != nil {
		log.Error("open settings db failed", "err", err)
		return false
	}
	settings, err := plainstore.NewSettingsStore(db).Load(context.Background())
	if err != nil {
		log.Error("view chore db failed", "err", err)
		return false
	}

	return settings.IPv6
}

func AddFakeDnsCidr(process AddRoute) {
	FakeDnsCidr(func(s string) {
		cidr, err := ParseCIDR(s)
		if err != nil {
			log.Error("parse cidr failed", "cidr", s, "err", err)
			return
		}

		process.Add(cidr)
	})
}
