package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

// RenewalInformation is public RFC 9773 advice, independent of account keys and
// order authentication. Issuance itself stays with the existing mature client.
type RenewalInformation struct {
	Window         RenewalWindow
	NextCheck      time.Time
	ExplanationURL string
	Supported      bool
}

type renewalInfoError struct {
	temporary  bool
	retryAfter time.Duration
}

func (*renewalInfoError) Error() string { return "ACME renewal information unavailable" }

// renewalCertificateID preserves DER INTEGER's positive leading zero byte.
// SerialNumber.Bytes alone would produce the wrong identifier for a high bit.
func renewalCertificateID(leaf *x509.Certificate) (string, error) {
	if leaf == nil || len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return "", errors.New("certificate has no ARI identifier")
	}
	der, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil {
		return "", err
	}
	var integer asn1.RawValue
	if _, err = asn1.Unmarshal(der, &integer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(integer.Bytes), nil
}

func renewalRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		return time.Duration(min(max(seconds, 60), 86400)) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		return min(max(at.Sub(now), time.Minute), 24*time.Hour), true
	}
	return 0, false
}

// FetchRenewalInfo uses the same governed verified CA transport as issuance.
// Advice is unsigned GET, with no account authorization or cross-origin fetch.
// No explanation URL is fetched. Refresh lifetime/leases are owned by Manager.
func FetchRenewalInfo(ctx context.Context, client *http.Client, config contract.Config, pair *tls.Certificate, now time.Time) (RenewalInformation, error) {
	var result RenewalInformation
	if err := config.Validate(); err != nil {
		return result, err
	}
	if client == nil || client.Transport == nil || pair == nil || pair.Leaf == nil {
		return result, errors.New("ARI requires governed HTTPS and a validated certificate")
	}
	if !now.Before(pair.Leaf.NotAfter) {
		return result, errors.New("expired certificate cannot request ARI")
	}
	id, err := renewalCertificateID(pair.Leaf)
	if err != nil {
		return RenewalInformation{NextCheck: now.Add(24 * time.Hour)}, nil
	}
	origin, err := url.Parse(config.DirectoryURL)
	if err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	narrowed := *client
	narrowed.Transport = originTransport{client.Transport, origin}
	narrowed.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("ARI redirects are disabled") }
	get := func(address string, destination any) (http.Header, error) {
		request, err := http.NewRequestWithContext(bounded, http.MethodGet, address, nil)
		if err != nil {
			return nil, &renewalInfoError{}
		}
		request.Header.Set("Accept", "application/json")
		response, err := narrowed.Do(request)
		if err != nil {
			temporary := false
			if e, ok := errors.AsType[net.Error](err); ok {
				temporary = e.Timeout()
			}
			return nil, &renewalInfoError{temporary: temporary}
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			delay, _ := renewalRetryAfter(response.Header.Get("Retry-After"), now)
			return nil, &renewalInfoError{temporary: response.StatusCode >= 500, retryAfter: delay}
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		if err != nil || len(data) > 64<<10 {
			return nil, &renewalInfoError{}
		}
		if err = json.Unmarshal(data, destination); err != nil {
			return nil, &renewalInfoError{}
		}
		return response.Header, nil
	}
	var directory struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if _, err = get(config.DirectoryURL, &directory); err != nil {
		return result, err
	}
	if directory.RenewalInfo == "" {
		return RenewalInformation{NextCheck: now.Add(24 * time.Hour)}, nil
	}
	endpoint, err := url.Parse(directory.RenewalInfo)
	if err != nil || endpoint.Scheme != "https" || !strings.EqualFold(endpoint.Host, origin.Host) || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" || endpoint.Opaque != "" || len(directory.RenewalInfo) > 2048 {
		return result, &renewalInfoError{}
	}
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/" + id
	endpoint.RawPath = ""
	var response struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	header, err := get(endpoint.String(), &response)
	if err != nil {
		return result, err
	}
	delay, valid := renewalRetryAfter(header.Get("Retry-After"), now)
	if !valid || response.SuggestedWindow.Start.IsZero() || !response.SuggestedWindow.End.After(response.SuggestedWindow.Start) || !response.SuggestedWindow.Start.Before(pair.Leaf.NotAfter) {
		return result, &renewalInfoError{}
	}

	return RenewalInformation{Supported: true, Window: RenewalWindow{response.SuggestedWindow.Start, minTime(response.SuggestedWindow.End, pair.Leaf.NotAfter)}, NextCheck: now.Add(delay), ExplanationURL: renewalExplanationURL(response.ExplanationURL)}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func renewalExplanationURL(value string) string {
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(value) > 2048 || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}
