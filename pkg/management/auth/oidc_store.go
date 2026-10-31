package auth

import (
	"net/url"
	"strings"
)

func validOIDCConfiguration(p OAuthProvider) bool {
	if !p.isOIDC() {
		return p.Issuer == ""
	}
	if len(p.Issuer) > 2048 || len(p.Name) > 128 || strings.TrimSpace(p.Name) == "" {
		return false
	}
	issuer, err := url.Parse(p.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return false
	}
	callback, err := url.Parse(p.RedirectURL)
	return err == nil && callback.Scheme == "https"
}

func validOAuthProviderConfiguration(p OAuthProvider) bool {
	return validProvider(p.Provider) && validOIDCConfiguration(p) && len(p.Name) <= 128 && len(p.ClientID) <= 512 && strings.TrimSpace(p.ClientID) != "" && len(p.ClientSecret) <= 2048 && len(p.RedirectURL) <= 2048 && validOAuthCallback(p.Provider, p.RedirectURL)
}
