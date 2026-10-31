package resolver

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestGetURL(t *testing.T) {
	dnsQStr := "https://8.8.8.8/dns-query"

	u, err := parseDohUrl("https://8.8.8.8")
	assert.NoError(t, err)
	assert.Equal(t, dnsQStr, u.String())

	u, err = parseDohUrl("8.8.8.8")
	assert.NoError(t, err)
	assert.Equal(t, u.String(), dnsQStr)

	u, err = parseDohUrl("8.8.8.8/test-path")
	assert.NoError(t, err)
	assert.Equal(t, "https://8.8.8.8/test-path", u.String())

}
