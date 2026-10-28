package manager

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"golang.org/x/crypto/acme"
)

type Presenters struct {
	HTTP HTTPPresenter
	DNS  *dnschallenge.Service
}

func (p Presenters) Present(ctx context.Context, c contract.Config, client *acme.Client, auth *acme.Authorization, ch *acme.Challenge) (func(), error) {
	switch ch.Type {
	case "http-01":
		return p.HTTP.Present(ctx, c, client, auth, ch)
	case "dns-01":
		if p.DNS == nil {
			return nil, errors.New("DNS-01 provider is unavailable")
		}
		value, err := client.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, err
		}
		return p.DNS.Present(ctx, c.Challenge.DNSProviderID, auth.Identifier.Value, value)
	default:
		return nil, errors.New("unsupported ACME challenge")
	}
}
