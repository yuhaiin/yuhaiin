package route

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

type memoryRuleDB struct {
	setting *config.Setting
}

func newMemoryRuleDB(rules ...*config.Rulev2) *memoryRuleDB {
	return &memoryRuleDB{
		setting: config.Setting_builder{
			Bypass: config.BypassConfig_builder{
				RulesV2: rules,
			}.Build(),
		}.Build(),
	}
}

func (d *memoryRuleDB) Batch(f ...func(*config.Setting) error) error {
	for _, fn := range f {
		if err := fn(d.setting); err != nil {
			return err
		}
	}

	return nil
}

func (d *memoryRuleDB) View(f ...func(*config.Setting) error) error {
	for _, fn := range f {
		if err := fn(d.setting); err != nil {
			return err
		}
	}

	return nil
}

func (d *memoryRuleDB) Dir() string { return tTempDir }

const tTempDir = "/tmp"

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
		src := []string{
			"a",
			"b",
			"c",
			"d",
			"e",
		}

		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertBefore(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"d", "a", "b", "c", "e"}, InsertBefore(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "d", "e"}, InsertBefore(src, 3, 4)))
	})

	t.Run("insertAfter", func(t *testing.T) {
		src := []string{
			"a",
			"b",
			"c",
			"d",
			"e",
		}

		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "d", "c", "e"},
			InsertAfter(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"},
			InsertAfter(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "e", "d"},
			InsertAfter(src, 3, 4)))
	})
}

func TestDisabledRuleSkippedBeforeParsing(t *testing.T) {
	matchers := newTestMatchers(t)

	matchers.Update(config.Rulev2_builder{
		Name:     new("disabled-host-list"),
		Disabled: new(true),
		Rules: []*config.Or{
			config.Or_builder{
				Rules: []*config.Rule{
					config.Rule_builder{
						Host: config.Host_builder{
							List: new("disabled-list"),
						}.Build(),
					}.Build(),
				},
			}.Build(),
		},
	}.Build())

	if len(matchers.matchers) != 0 {
		t.Fatalf("disabled rule should not be added to runtime matchers, got %d", len(matchers.matchers))
	}
}

func TestRuleListIncludesDisabledState(t *testing.T) {
	db := newMemoryRuleDB(
		config.Rulev2_builder{
			Name: new("enabled"),
		}.Build(),
		config.Rulev2_builder{
			Name:     new("disabled"),
			Disabled: new(true),
		}.Build(),
	)

	rs := &Rules{db: db, route: &Route{ms: newTestMatchers(t)}}
	resp, err := rs.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.GetNames()) != 2 || len(resp.GetItems()) != 2 {
		t.Fatalf("expected 2 names and 2 items, got names=%d items=%d", len(resp.GetNames()), len(resp.GetItems()))
	}

	if resp.GetItems()[0].GetName() != "enabled" || resp.GetItems()[0].GetDisabled() {
		t.Fatalf("unexpected first rule item: %v", resp.GetItems()[0])
	}

	if resp.GetItems()[1].GetName() != "disabled" || !resp.GetItems()[1].GetDisabled() {
		t.Fatalf("unexpected second rule item: %v", resp.GetItems()[1])
	}
}

func TestChangePriorityRebuildsMatchersWithDisabledRules(t *testing.T) {
	db := newMemoryRuleDB(
		config.Rulev2_builder{
			Name: new("enabled-a"),
		}.Build(),
		config.Rulev2_builder{
			Name:     new("disabled-b"),
			Disabled: new(true),
			Rules: []*config.Or{
				config.Or_builder{
					Rules: []*config.Rule{
						config.Rule_builder{
							Host: config.Host_builder{
								List: new("disabled-list"),
							}.Build(),
						}.Build(),
					},
				}.Build(),
			},
		}.Build(),
		config.Rulev2_builder{
			Name: new("enabled-c"),
		}.Build(),
	)

	rs := &Rules{db: db, route: &Route{ms: newTestMatchers(t)}}
	rs.route.ms.Update(db.setting.GetBypass().GetRulesV2()...)

	_, err := rs.ChangePriority(context.Background(), api.ChangePriorityRequest_builder{
		Operate: api.ChangePriorityRequest_Exchange.Enum(),
		Source: api.RuleIndex_builder{
			Index: proto.Uint32(0),
			Name:  new("enabled-a"),
		}.Build(),
		Target: api.RuleIndex_builder{
			Index: proto.Uint32(1),
			Name:  new("disabled-b"),
		}.Build(),
	}.Build())
	if err != nil {
		t.Fatal(err)
	}

	rules := db.setting.GetBypass().GetRulesV2()
	if rules[0].GetName() != "disabled-b" || rules[1].GetName() != "enabled-a" {
		t.Fatalf("rules were not exchanged: got %q, %q", rules[0].GetName(), rules[1].GetName())
	}

	if len(rs.route.ms.matchers) != 2 {
		t.Fatalf("disabled rule should be skipped during rebuild, got %d matchers", len(rs.route.ms.matchers))
	}

	if rs.route.ms.matchers[0].name != "enabled-a" || rs.route.ms.matchers[1].name != "enabled-c" {
		t.Fatalf("unexpected runtime matcher order: %#v", rs.route.ms.matchers)
	}
}
