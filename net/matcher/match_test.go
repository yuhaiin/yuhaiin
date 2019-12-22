package matcher

import (
	"testing"
)

func TestNewMatcher(t *testing.T) {
	matcher := NewMatcher("119.29.29.29:53")
	if err := matcher.InsertOne("www.baidu.com", "test_baidu"); err != nil {
		t.Error(err)
	}
	if err := matcher.InsertOne("10.2.2.1/18", "test_cidr"); err != nil {
		t.Error(err)
	}
	t.Log(matcher.MatchStr("10.2.2.1"))
	t.Log(matcher.MatchStr("www.baidu.com"))
	t.Log(matcher.MatchStr("www.google.com"))
}

func TestNewMatcherWithFile(t *testing.T) {
	matcher, err := NewMatcherWithFile("119.29.29.29:53", "../../rule/rule.config")
	if err != nil {
		t.Error(err)
	}
	t.Log(matcher.MatchStr("10.2.2.1"))
	t.Log(matcher.MatchStr("www.baidu.com"))
	t.Log(matcher.MatchStr("www.google.com"))
}
