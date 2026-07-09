package route

import (
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func newTestMatchers(t *testing.T) *Matchers {
	t.Helper()

	lists := &Lists{
		hostTrie:    newHostTrie(t.TempDir()),
		processTrie: newProcessTrie(),
	}

	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})

	return NewMatchers(lists)
}

func TestChangePriority(t *testing.T) {
	t.Run("insertBefore", func(t *testing.T) {
		src := []string{"a", "b", "c", "d", "e"}
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertBefore(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"d", "a", "b", "c", "e"}, InsertBefore(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "d", "e"}, InsertBefore(src, 3, 4)))
	})

	t.Run("insertAfter", func(t *testing.T) {
		src := []string{"a", "b", "c", "d", "e"}
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "d", "c", "e"}, InsertAfter(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertAfter(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "e", "d"}, InsertAfter(src, 3, 4)))
	})
}

func TestDisabledRuleSkippedBeforeParsing(t *testing.T) {
	matchers := newTestMatchers(t)

	matchers.Update(contractroute.RouteRule{
		Name:     "disabled-host-list",
		Disabled: true,
		Rules: []contractroute.RuleExpr{
			{Type: "host", Host: &contractroute.ListRef{List: "disabled-list"}},
		},
	})

	if len(matchers.matchers) != 0 {
		t.Fatalf("disabled rule should not be added to runtime matchers, got %d", len(matchers.matchers))
	}
}

func TestMatcherRebuildSkipsDisabledRules(t *testing.T) {
	matchers := newTestMatchers(t)

	matchers.Update(
		contractroute.RouteRule{Name: "enabled-a"},
		contractroute.RouteRule{
			Name:     "disabled-b",
			Disabled: true,
			Rules: []contractroute.RuleExpr{
				{Type: "host", Host: &contractroute.ListRef{List: "disabled-list"}},
			},
		},
		contractroute.RouteRule{Name: "enabled-c"},
	)

	if len(matchers.matchers) != 2 {
		t.Fatalf("disabled rule should be skipped during rebuild, got %d matchers", len(matchers.matchers))
	}
	if matchers.matchers[0].name != "enabled-a" || matchers.matchers[1].name != "enabled-c" {
		t.Fatalf("unexpected runtime matcher order: %#v", matchers.matchers)
	}
}
