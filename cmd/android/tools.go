package yuhaiin

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type CIDR struct {
	IP   string
	Mask int32
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
