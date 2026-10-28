// Package cloudflare implements owned DNS-01 TXT records through Cloudflare's
// DNS API. The API origin is fixed; users cannot redirect a credential elsewhere.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type Provider struct {
	client *http.Client
	base   string
}

func New(client *http.Client) (*Provider, error) {
	return newWithBase(client, "https://api.cloudflare.com/client/v4")
}

func newWithBase(client *http.Client, base string) (*Provider, error) {
	if client == nil || client.Transport == nil {
		return nil, errors.New("cloudflare DNS requires a governed HTTPS transport")
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("DNS provider HTTPS verification is required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid DNS provider origin")
	}
	owned := *client
	owned.Jar = nil
	owned.CheckRedirect = func(*http.Request, []*http.Request) error { return &dnschallenge.Error{Code: "dns_redirect_rejected"} }
	owned.Timeout = 30 * time.Second
	return &Provider{client: &owned, base: strings.TrimSuffix(base, "/")}, nil
}

type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
	TTL     int    `json:"ttl,omitzero"`
}

var errNotFound = errors.New("DNS record is absent")

func (p *Provider) request(ctx context.Context, method, path string, query url.Values, token certificates.Secret, body, output any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	u := p.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return &dnschallenge.Error{Code: "dns_invalid_request"}
	}
	request.Header.Set("Authorization", "Bearer "+string(token.Bytes()))
	if method == http.MethodPost {
		request.GetBody = nil
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return &dnschallenge.Error{Code: "dns_network_error"}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if response.StatusCode == http.StatusTooManyRequests {
		delay := time.Hour
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 {
			delay = time.Duration(min(seconds, 7*24*3600)) * time.Second
		}
		return &dnschallenge.Error{Code: "dns_rate_limited", RetryAfter: delay}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &dnschallenge.Error{Code: "dns_api_rejected"}
	}
	limited := http.MaxBytesReader(nil, response.Body, 1<<20)
	data, err = io.ReadAll(limited)
	if err != nil {
		return &dnschallenge.Error{Code: "dns_invalid_response"}
	}
	var envelope struct {
		Success bool           `json:"success"`
		Result  jsontext.Value `json:"result"`
	}
	if err = json.Unmarshal(data, &envelope); err != nil || !envelope.Success {
		return &dnschallenge.Error{Code: "dns_invalid_response"}
	}
	if output != nil {
		if err = json.Unmarshal(envelope.Result, output); err != nil {
			return &dnschallenge.Error{Code: "dns_invalid_response"}
		}
	}
	return nil
}

func validID(id string) bool {
	data, err := hex.DecodeString(id)
	return err == nil && len(data) == 16 && strings.ToLower(id) == id
}
func tag(r certificates.DNSCleanup) string { return "yuhaiin-acme:" + r.ID }
func matches(record record, r certificates.DNSCleanup) bool {
	return validID(record.ID) && record.Type == "TXT" && strings.TrimSuffix(strings.ToLower(record.Name), ".") == r.Name && record.Comment == tag(r) && (record.Content == r.Value || record.Content == "\""+r.Value+"\"")
}
func validate(p contract.DNSProvider, r certificates.DNSCleanup) bool {
	return certificates.ValidProvider(p) && p.ID == r.ProviderID && contract.ValidID(r.ID) && strings.HasPrefix(r.Name, "_acme-challenge.") && (strings.TrimPrefix(r.Name, "_acme-challenge.") == p.ZoneName || strings.HasSuffix(r.Name, "."+p.ZoneName)) && len(r.Value) == 43
}

func (p *Provider) Create(ctx context.Context, provider contract.DNSProvider, token certificates.Secret, r certificates.DNSCleanup) (string, error) {
	if !validate(provider, r) || token.Empty() {
		return "", &dnschallenge.Error{Code: "dns_invalid_challenge"}
	}
	request := record{Type: "TXT", Name: r.Name, Content: "\"" + r.Value + "\"", Comment: tag(r), TTL: 60}
	var response record
	if err := p.request(ctx, http.MethodPost, "/zones/"+provider.ZoneID+"/dns_records", nil, token, request, &response); err != nil {
		return "", err
	}
	if !matches(response, r) {
		return "", &dnschallenge.Error{Code: "dns_ownership_mismatch"}
	}
	return response.ID, nil
}

func (p *Provider) Cleanup(ctx context.Context, provider contract.DNSProvider, token certificates.Secret, r certificates.DNSCleanup) error {
	if !validate(provider, r) || token.Empty() {
		return &dnschallenge.Error{Code: "dns_invalid_cleanup"}
	}
	path := "/zones/" + provider.ZoneID + "/dns_records"
	var records []record
	if r.RecordID != "" {
		if !validID(r.RecordID) {
			return &dnschallenge.Error{Code: "dns_invalid_cleanup"}
		}
		var response record
		err := p.request(ctx, http.MethodGet, path+"/"+r.RecordID, nil, token, nil, &response)
		if errors.Is(err, errNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if response.ID != r.RecordID || !matches(response, r) {
			return &dnschallenge.Error{Code: "dns_ownership_changed"}
		}
		records = []record{response}
	} else {
		// Unique per-attempt comments keep this query small. Pagination is hard
		// bounded; unexpected excess retains the receipt instead of guessing.
		query := url.Values{"type": {"TXT"}, "name.exact": {r.Name}, "comment.exact": {tag(r)}, "per_page": {"100"}, "page": {"1"}}
		if err := p.request(ctx, http.MethodGet, path, query, token, nil, &records); err != nil {
			return err
		}
		if len(records) >= 100 {
			return &dnschallenge.Error{Code: "dns_cleanup_result_limit"}
		}
	}
	for _, record := range records {
		if !matches(record, r) {
			continue
		}
		err := p.request(ctx, http.MethodDelete, path+"/"+record.ID, nil, token, nil, nil)
		if err != nil && !errors.Is(err, errNotFound) {
			return err
		}
	}
	return nil
}
