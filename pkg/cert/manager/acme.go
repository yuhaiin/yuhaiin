package manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
	"golang.org/x/crypto/acme"
)

// ChallengePresenter supplies bounded presentation and cleanup for a selected
// challenge. DNS implementations own exact-record receipts and propagation checks.
type ChallengePresenter interface {
	Present(context.Context, contract.Config, *acme.Client, *acme.Authorization, *acme.Challenge) (func(), error)
}

type HTTPPresenter struct{ Challenges *HTTPChallenges }

func (h HTTPPresenter) Present(ctx context.Context, c contract.Config, client *acme.Client, auth *acme.Authorization, ch *acme.Challenge) (func(), error) {
	if h.Challenges == nil || ch.Type != "http-01" || auth.Wildcard {
		return nil, errors.New("unsupported HTTP-01 presentation")
	}
	response, err := client.HTTP01ChallengeResponse(ch.Token)
	if err != nil {
		return nil, err
	}
	return h.Challenges.Present(ctx, c.Challenge.HTTPGatewayID, auth.Identifier.Value, ch.Token, response)
}

// Issuer delegates RFC 8555 signatures and protocol state to x/crypto/acme.
// Client must use the application's governed network path and verified TLS.
// The issuer narrows that client to the explicitly configured CA origin.
type Issuer struct {
	Store     *certificates.Store
	Client    *http.Client
	Presenter ChallengePresenter
}

type originTransport struct {
	base   http.RoundTripper
	origin *url.URL
}

func (t originTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || !strings.EqualFold(r.URL.Host, t.origin.Host) || r.URL.User != nil || r.URL.Fragment != "" {
		return nil, errors.New("ACME response attempted a different network origin")
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > 1<<20 {
		_ = response.Body.Close()
		return nil, errors.New("ACME response exceeds 1 MiB")
	}
	response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	return response, nil
}

func (i *Issuer) Issue(ctx context.Context, c contract.Config) (certificates.Material, error) {
	var empty certificates.Material
	if err := c.Validate(); err != nil {
		return empty, err
	}
	if i.Store == nil || i.Client == nil || i.Client.Transport == nil || i.Presenter == nil {
		return empty, errors.New("ACME requires storage, governed HTTPS transport and a challenge presenter")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Minute {
		return empty, errors.New("ACME issuance requires a deadline of at most ten minutes")
	}
	u, err := url.Parse(c.DirectoryURL)
	if err != nil {
		return empty, err
	}
	httpClient := *i.Client
	httpClient.Transport = originTransport{i.Client.Transport, u}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("ACME redirects are disabled") }
	account, err := i.Store.AccountKey(ctx, c.DirectoryURL, c.Email, certificates.Secret{})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return empty, err
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return empty, err
		}
		encoded, err := encodeSigner(key)
		if err != nil {
			return empty, err
		}
		account, err = i.Store.AccountKey(ctx, c.DirectoryURL, c.Email, encoded)
		if err != nil {
			return empty, err
		}
	}
	keyBytes := account.Key.Bytes()
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return empty, errors.New("invalid persisted ACME account key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(keyBytes)
	if err != nil {
		return empty, errors.New("invalid persisted ACME account key")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return empty, errors.New("invalid persisted ACME account signer")
	}
	client := &acme.Client{Key: signer, DirectoryURL: c.DirectoryURL, HTTPClient: &httpClient, UserAgent: "yuhaiin-certificate-manager", KID: acme.KeyID(account.URI)}
	if account.URI == "" {
		registration, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + c.Email}}, func(string) bool { return c.TermsAccepted })
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			registration, err = client.GetReg(ctx, "")
		}
		if err != nil {
			return empty, err
		}
		if err = i.Store.BindAccount(ctx, c.DirectoryURL, c.Email, account.Key, registration.URI); err != nil {
			return empty, err
		}
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(c.Domains...))
	if err != nil {
		return empty, err
	}
	if len(order.AuthzURLs) > len(c.Domains) {
		return empty, errors.New("ACME returned too many authorizations")
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return empty, err
		}
		name := auth.Identifier.Value
		if auth.Wildcard {
			name = "*." + name
		}
		found := slices.Contains(c.Domains, name)
		if auth.Identifier.Type != "dns" || !found {
			return empty, errors.New("ACME authorization does not match requested DNS names")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var selected *acme.Challenge
		for _, challenge := range auth.Challenges {
			if challenge.Type == c.Challenge.Type {
				selected = challenge
				break
			}
		}
		if selected == nil {
			return empty, errors.New("ACME did not offer configured challenge")
		}
		cleanup, err := i.Presenter.Present(ctx, c, client, auth, selected)
		if err != nil {
			return empty, err
		}
		err = func() error {
			defer cleanup()
			if _, err := client.Accept(ctx, selected); err != nil {
				return err
			}
			_, err := client.WaitAuthorization(ctx, auth.URI)
			return err
		}()
		if err != nil {
			return empty, err
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return empty, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: c.Domains}, leafKey)
	if err != nil {
		return empty, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return empty, err
	}
	privateKey, err := encodeSigner(leafKey)
	if err != nil {
		return empty, err
	}
	material := certificates.Material{CertificatePEM: encodeChain(chain), PrivateKey: privateKey}
	if _, err = ValidateMaterial(c, material, time.Now()); err != nil {
		return empty, err
	}
	return material, nil
}
