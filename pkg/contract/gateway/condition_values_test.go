package gateway

import (
	json "encoding/json/v2"
	"reflect"
	"testing"
)

func TestNormalizeConditionMigratesLegacyValuesRecursively(t *testing.T) {
	var old Condition
	if err := json.Unmarshal([]byte(`{"all":[{"field":"path","operator":"prefix","value":"/api/"},{"not":{"field":"host","value":"blocked.example"}}]}`), &old); err != nil {
		t.Fatal(err)
	}
	migrated := NormalizeCondition(old)
	if !reflect.DeepEqual(migrated.All[0].Values, []string{"/api/"}) ||
		!reflect.DeepEqual(migrated.All[1].Not.Values, []string{"blocked.example"}) {
		t.Fatalf("legacy values lost: %+v", migrated)
	}
	if migrated.All[0].Value != "" || migrated.All[1].Not.Value != "" {
		t.Fatalf("legacy value survived normalization: %+v", migrated)
	}
	data, err := json.Marshal(migrated)
	if err != nil { t.Fatal(err) }
	if string(data) == "" { t.Fatal("empty JSON") }
	var again Condition
	if err := json.Unmarshal(data, &again); err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(again, migrated) { t.Fatalf("round trip changed values: %+v", again) }
	// The legacy draft remains unchanged.
	if old.All[0].Value != "/api/" { t.Fatal("normalization mutated input") }
}

func TestWorkspaceMigratesLegacyValuesOnReadAndWrite(t *testing.T) {
	cfg := Config{
		Gateways: []Gateway{{ID: "g", RuleIDs: []string{"r"}, Default: Action{Type: "block"}}},
		Rules: []Rule{{ID: "r", Match: Condition{Field: "path", Value: "/legacy"}}},
	}
	doc, err := WorkspaceFromConfig(cfg)
	if err != nil { t.Fatal(err) }
	if got := doc.Gateways[0].Policies[0].Match; len(got.Values) != 1 || got.Values[0] != "/legacy" || got.Value != "" {
		t.Fatalf("workspace did not normalize legacy value: %+v", got)
	}
	doc.Gateways[0].Policies[0].Match = Condition{Any: []Condition{{Field: "host", Value: "example.com"}, {Field: "path", Values: []string{"/a", "/b"}}}}
	loaded, err := ConfigFromWorkspace(doc)
	if err != nil { t.Fatal(err) }
	if got := loaded.Rules[0].Match.Any[0]; !reflect.DeepEqual(got.Values, []string{"example.com"}) || got.Value != "" {
		t.Fatalf("workspace load failed to migrate legacy value: %+v", got)
	}
}
