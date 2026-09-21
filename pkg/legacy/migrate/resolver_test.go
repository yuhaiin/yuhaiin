package migrate

import (
	"testing"

	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

func TestConvertLegacyResolverRejectsUnknownType(t *testing.T) {
	typ := legacy.Type(99)
	if _, err := ConvertLegacyResolver("broken", legacy.Dns_builder{Type: typ.Enum(), Host: new("resolver")}.Build()); err == nil {
		t.Fatal("unknown resolver type was silently converted to UDP")
	}
}
