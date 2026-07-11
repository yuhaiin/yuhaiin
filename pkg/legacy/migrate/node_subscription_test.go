package migrate

import (
	"encoding/base64"
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func TestParseLegacyYuhaiinURLRemote(t *testing.T) {
	payload, err := json.Marshal(node.YuhaiinUrl_builder{
		Name: new("share"),
		Remote: node.YuhaiinUrl_Remote_builder{
			Publish: node.Publish_builder{
				Name:     new("share"),
				Address:  new("yuubinsya.com:8000"),
				Path:     new("/aws/share"),
				Password: new("vVfY0CwE1Dp2DHmRlZO!3nqT6"),
			}.Build(),
		}.Build(),
	}.Build())
	if err != nil {
		t.Fatal(err)
	}
	url := "yuhaiin://" + base64.RawURLEncoding.EncodeToString(payload)
	parsed, err := ParseLegacyYuhaiinURL(strings.TrimSpace(url))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Remote == nil || parsed.Remote.Address != "yuubinsya.com:8000" {
		t.Fatalf("unexpected parsed remote: %+v", parsed.Remote)
	}
}
