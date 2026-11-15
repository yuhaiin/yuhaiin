package configbackup

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"net/url"
	"uuid"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
)

// ShareFeed removes the feed token so a shared export cannot serve nodes. The
// restored feed keeps its selection and gets a new link when it is reissued.
func ShareFeed(data string) (string, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, errors.New("invalid share feed configuration in export")
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal(value, &document); err != nil || document == nil {
		return "", false, errors.New("invalid share feed configuration in export")
	}
	changed := false
	for key := range document {
		if normalizeField(key) == "token" {
			document[key] = jsontext.Value(`""`)
			changed = true
		}
	}
	result, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return "", false, errors.New("cannot encode redacted share feed configuration")
	}
	return string(result), changed, nil
}

// legacyPublish is the document stored by the publish feature that share
// feeds replaced.
type legacyPublish struct {
	Name     string   `json:"name"`
	Points   []string `json:"points"`
	Address  string   `json:"address"`
	Insecure bool     `json:"insecure"`
}

// LegacyPublishShareFeed converts a stored publish into a share feed document.
// The old path and password are dropped: the feed gets a new token.
func LegacyPublishShareFeed(name, data string, updatedAt int64) (id string, document string, err error) {
	var publish legacyPublish
	if err := json.Unmarshal([]byte(data), &publish); err != nil {
		return "", "", errors.New("invalid publish configuration")
	}
	if publish.Name == "" {
		publish.Name = name
	}
	if publish.Name == "" {
		return "", "", errors.New("publish configuration has no name")
	}
	feed := contractsubscription.ShareFeed{
		ID:        uuid.New().String(),
		Name:      publish.Name,
		Enabled:   true,
		Token:     newShareFeedToken(),
		BaseURL:   legacyPublishBaseURL(publish.Address, publish.Insecure),
		Entries:   []contractsubscription.ShareFeedEntry{},
		CreatedAt: updatedAt,
		UpdatedAt: updatedAt,
	}
	seen := map[string]bool{}
	for _, point := range publish.Points {
		if point == "" || seen[point] {
			continue
		}
		seen[point] = true
		feed.Entries = append(feed.Entries, contractsubscription.ShareFeedEntry{Kind: contractsubscription.ShareFeedEntryNode, Value: point})
	}
	encoded, err := json.Marshal(feed)
	if err != nil {
		return "", "", err
	}
	return feed.ID, string(encoded), nil
}

func legacyPublishBaseURL(address string, insecure bool) string {
	if address == "" {
		return ""
	}
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		// A bare host keeps the scheme's default port.
		if net.ParseIP(address) != nil && net.ParseIP(address).To4() == nil {
			address = "[" + address + "]"
		}
	}
	u, err := url.Parse(scheme + "://" + address)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return u.String()
}

func newShareFeedToken() string {
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	return base64.RawURLEncoding.EncodeToString(token)
}
