package bbolt

/*
import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/internal/statistics"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	bolt "go.etcd.io/bbolt"
)

func TestBBlotDomainMatcherSearch(t *testing.T) {
	os.MkdirAll("/tmp/bbolt", os.ModePerm)
	b, err := bolt.Open("/tmp/bbolt/test.db", os.ModePerm, &bolt.Options{})
	assert.NoError(t, err)
	defer b.Close()

	root := NewBBoltDomainMapper(b)
	insert := func(d, str string) {
		root.Insert(d, []byte(str))
	}

	insert("*.baidu.com", "sub_baidu_test")
	insert("www.baidu.com", "test_baidu")
	insert("last.baidu.*", "test_last_baidu")
	insert("*.baidu.*", "last_sub_baidu_test")
	insert("spo.baidu.com", "test_no_sub_baidu")
	insert("www.google.com", "test_google")
	insert("music.111.com", "1111")
	insert("163.com", "163")
	insert("*.google.com", "google")
	insert("*.dl.google.com", "google_dl")
	insert("api.sec.miui.*", "ad_miui")
	insert("*.miui.com", "miui")

	search := func(s string) string {
		res, _ := root.Search(proxy.ParseAddressSplit("", s, 0))
		return string(res)
	}
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_no_sub_baidu", search("spo.baidu.com"))
	assert.Equal(t, "test_last_baidu", search("last.baidu.com.cn"))
	assert.Equal(t, "sub_baidu_test", search("test.baidu.com"))
	assert.Equal(t, "sub_baidu_test", search("test.test2.baidu.com"))
	assert.Equal(t, "last_sub_baidu_test", search("www.baidu.cn"))
	assert.Equal(t, "test_google", search("www.google.com"))
	assert.Equal(t, "", search("www.google.cn"))
	assert.Equal(t, "", search("music.163.com"))
	assert.Equal(t, "163", search("163.com"))
	assert.Equal(t, "google", search("www.x.google.com"))
	assert.Equal(t, "google_dl", search("dl.google.com"))
	assert.Equal(t, "ad_miui", search("api.sec.miui.com"))
}

func TestInsertBBolt(t *testing.T) {
	rule := &rule{}
	os.MkdirAll("/tmp/bbolt", os.ModePerm)
	b, err := bolt.Open("/tmp/bbolt/test.db", os.ModePerm, &bolt.Options{})
	assert.NoError(t, err)
	defer b.Close()

	root := NewBBoltDomainMapper(b)
	insert := func(d string, str []byte) {
		root.Insert(d, str)
	}

	f, err := os.Open("/mnt/share/Work/code/shell/ACL/yuhaiin/yuhaiin_my.conf")
	assert.NoError(t, err)
	defer f.Close()

	br := bufio.NewScanner(f)
	for {
		if !br.Scan() {
			break
		}

		a := br.Bytes()

		i := bytes.IndexByte(a, '#')
		if i != -1 {
			a = a[:i]
		}

		i = bytes.IndexByte(a, ' ')
		if i == -1 {
			continue
		}

		c, b := a[:i], a[i+1:]

		if len(c) != 0 && len(b) != 0 {
			insert(string(c), []byte{byte(rule.GetID(string(b)))})
		}
	}
}

type rule struct {
	id        statistics.IDGenerator
	mapping   syncmap.SyncMap[string, uint16]
	idMapping syncmap.SyncMap[uint16, string]
}

func (r *rule) GetID(s string) uint16 {
	s = strings.ToUpper(s)
	if v, ok := r.mapping.Load(s); ok {
		return v
	}
	id := uint16(r.id.Generate())
	r.mapping.Store(s, id)
	r.idMapping.Store(id, s)
	return id
}

func (r *rule) GetMode(id uint16) string {
	if v, ok := r.idMapping.Load(id); ok {
		return v
	}
	return ""
}
*/
