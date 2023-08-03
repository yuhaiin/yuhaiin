package log

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestExt(t *testing.T) {
	dir := "/home/dev/yuhaiin.log"

	t.Log(NewPath(dir).FullPath("xxx"))

	f, err := os.ReadDir("/home/asutorufa/.config/yuhaiin/log")
	assert.NoError(t, err)

	sort.Slice(f, func(i, j int) bool { return f[i].Name() > f[j].Name() })

	count := 0
	for _, v := range f {
		if !(strings.HasPrefix(v.Name(), "yuhaiin_") && strings.HasSuffix(v.Name(), "log")) {
			continue
		}
		count++

		if count <= 5 {
			continue
		}

		t.Log(v.Name(), count)
	}
}
