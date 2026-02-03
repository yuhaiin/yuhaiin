package node

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
)

func TestXxx(t *testing.T) {
	uu := "yuhaiin://CkQKQhIKL2F3cy9zaGFyZRoFc2hhcmUiGXZWZlkwQ3dFMURwMkRIbVJsWk8hM25xVDYqEHl1dWJpbnN5YS5jb206ODAwARoFc2hhcmU"
	u := strings.TrimPrefix(uu, "yuhaiin://")

	data, err := base64.RawURLEncoding.DecodeString(u)
	if err != nil {
		t.Fatal(err)
	}

	yu := &node.YuhaiinUrl{}
	if err = proto.Unmarshal(data, yu); err != nil {
		t.Fatal(err)
	}

	t.Log(yu)
}
