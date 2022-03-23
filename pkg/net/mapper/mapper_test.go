package mapper

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	mock_dns "github.com/Asutorufa/yuhaiin/pkg/net/dns/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewMatcher(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dns := mock_dns.NewMockDNS(ctrl)
	dns.EXPECT().LookupIP("www.twitter.com").Return([]net.IP{net.ParseIP("10.2.2.1")}, nil)
	dns.EXPECT().LookupIP("www.facebook.com").Return([]net.IP{net.ParseIP("10.2.2.1")}, nil)
	dns.EXPECT().LookupIP("www.google.com").Return([]net.IP{net.ParseIP("127.0.0.1")}, nil)

	matcher := NewMapper[string](dns.LookupIP)
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	matcher.Insert("*.163.com", "163")
	matcher.Insert("music.126.com", "126")
	matcher.Insert("*.advertising.com", "advertising")

	search := func(s string) interface{} {
		res, _ := matcher.Search(s)
		return res
	}
	assert.Equal(t, "test_cidr", search("10.2.2.1"))
	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_baidu", search("passport.baidu.com"))
	assert.Equal(t, "test_baidu", search("tieba.baidu.com"))
	assert.Equal(t, nil, search("www.google.com"))
	assert.Equal(t, "163", search("test.music.163.com"))
	assert.Equal(t, "advertising", search("guce.advertising.com"))
	assert.Equal(t, "test_cidr", search("www.twitter.com"))
	assert.Equal(t, "test_cidr", search("www.facebook.com"))
	assert.Equal(t, nil, search("127.0.0.1"))
	assert.Equal(t, nil, search("ff::"))
}

func BenchmarkMapper(b *testing.B) {
	b.StopTimer()
	matcher := NewMapper[string](dns.NewDoH("223.5.5.5", nil, nil).LookupIP)
	matcher.Insert("*.baidu.com", "test_baidu")
	matcher.Insert("10.2.2.1/18", "test_cidr")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 1 {
			matcher.Search("www.example.baidu.com")
		} else {
			matcher.Search("10.2.2.1")
		}
	}
}
