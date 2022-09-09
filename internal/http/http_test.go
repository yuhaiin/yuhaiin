package simplehttp

import (
	"bytes"
	"html/template"
	"testing"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestXxx(t *testing.T) {
	tp, err := template.ParseFS(tps.Pages, "http.html", "sub.html")
	assert.NoError(t, err)

	z := bytes.NewBuffer(nil)
	err = tp.Execute(z, map[string]any{
		"LS": []string{"testlink", "test2"},
		"Links": map[string]node.NodeLink{
			"testlink": {
				Name: "testlink",
				Url:  "http://url",
			},
			"test2": {
				Name: "test2",
				Url:  "https://test2",
			},
		},
	})
	assert.NoError(t, err)

	t.Log(z.String())

	z.Reset()

	TPS.BodyExecute(z, nil, "statistic.html")
	t.Log(z.String())
}
