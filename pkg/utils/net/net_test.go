package net

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestGetScheme(t *testing.T) {
	scheme, _, err := GetScheme("http://www.baidu.com/dns-query")
	assert.NoError(t, err)
	assert.Equal(t, "http", scheme)
	scheme, _, err = GetScheme("file:///www.baidu.com/dns-query")
	assert.NoError(t, err)
	assert.Equal(t, "file", scheme)
}
