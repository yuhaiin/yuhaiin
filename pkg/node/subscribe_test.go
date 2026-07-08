package node

import (
	"encoding/base64"
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
)

func TestXxx(t *testing.T) {
	payload, err := json.Marshal(node.YuhaiinUrl_builder{
		Name: ptr("share"),
		Remote: node.YuhaiinUrl_Remote_builder{
			Publish: node.Publish_builder{
				Name:     ptr("share"),
				Address:  ptr("yuubinsya.com:8000"),
				Path:     ptr("/aws/share"),
				Password: ptr("vVfY0CwE1Dp2DHmRlZO!3nqT6"),
			}.Build(),
		}.Build(),
	}.Build())
	if err != nil {
		t.Fatal(err)
	}
	uu := "yuhaiin://" + base64.RawURLEncoding.EncodeToString(payload)
	u := strings.TrimPrefix(uu, "yuhaiin://")

	data, err := base64.RawURLEncoding.DecodeString(u)
	if err != nil {
		t.Fatal(err)
	}

	yu := &node.YuhaiinUrl{}
	if err = json.Unmarshal(data, yu); err != nil {
		t.Fatal(err)
	}

	t.Log(yu)
}

func ptr[T any](v T) *T { return &v }
