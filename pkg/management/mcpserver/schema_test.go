package mcpserver

import (
	"encoding/json/v2"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/google/jsonschema-go/jsonschema"
)

type schemaLeaf struct {
	Value string `json:"value"`
}

type schemaSample struct {
	Type     string         `json:"type"`
	Left     *schemaLeaf    `json:"left,omitzero"`
	Right    *schemaLeaf    `json:"right,omitzero"`
	Nullable *schemaLeaf    `json:"nullable"`
	Children []schemaSample `json:"children"`
	Secret   string         `json:"secret" secret:"true"`
	Hidden   string         `json:"-"`
	embedded
}

type embedded struct {
	Inline int `json:"inline"`
}

func validate(t *testing.T, schema map[string]any, instance string) error {
	t.Helper()
	encoded, _ := json.Marshal(schema)
	var s jsonschema.Schema
	if err := json.Unmarshal(encoded, &s); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal([]byte(instance), &value); err != nil {
		t.Fatal(err)
	}
	return resolved.Validate(value)
}

func TestSchemaForHandlesRecursionUnionsAndInlining(t *testing.T) {
	schema := schemaFor[schemaSample]()
	encoded, _ := json.Marshal(schema)
	for _, want := range []string{`"$ref":"#/$defs/mcpserver.schemaSample"`, `"enum":["left","right"]`, `"inline"`, `Secret;`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("schema lacks %s: %s", want, encoded)
		}
	}
	if strings.Contains(string(encoded), "Hidden") {
		t.Error("json:\"-\" field exposed")
	}
	for instance, ok := range map[string]bool{
		`{"type":"left","left":{"value":"x"},"nullable":null,"children":[{"type":"right","right":{"value":"y"}}],"inline":1}`: true,
		`{"type":"middle"}`:             false,
		`{"type":"left","unknown":1}`:   false,
		`{"children":[{"bogus":true}]}`: false,
		`{"left":null}`:                 false,
	} {
		if err := validate(t, schema, instance); (err == nil) != ok {
			t.Errorf("%s: %v, want valid=%v", instance, err, ok)
		}
	}
}

func TestContractSchemasAreUsable(t *testing.T) {
	for name, schema := range map[string]map[string]any{"node": schemaFor[contractnode.Node](), "rule": schemaFor[contractroute.RuleDraft]()} {
		if _, ok := schema["$defs"]; !ok {
			t.Errorf("%s schema has no definitions", name)
		}
	}
	node := `{"id":"n","name":"n","group":"g","origin":"manual","enabled":true,"chain":[{"type":"simple","simple":{"host":"192.0.2.1","port":443}},{"type":"tls","tls":{"enable":true}}]}`
	if err := validate(t, schemaFor[contractnode.Node](), node); err != nil {
		t.Fatal(err)
	}
	// Compound rule expressions are slice variants of the union.
	rule := `{"rule":{"id":"r","name":"r","mode":"block","revision":0,"rules":[{"type":"all","all":[{"type":"host","host":{"list":"ads"}},{"type":"not","not":{"type":"port","port":{"ports":"443"}}}]}]}}`
	if err := validate(t, schemaFor[contractroute.RuleDraft](), rule); err != nil {
		t.Fatal("compound rule rejected:", err)
	}
	strict := strictDTO[contractnode.Node](nil)
	if _, err := strict([]byte(`{"name":"x","bogus":1}`)); err == nil {
		t.Fatal("unknown member accepted")
	}
}

func TestEveryToolHasAClosedObjectSchema(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range builtinTools() {
		if seen[tool.Name] {
			t.Errorf("duplicate tool %s", tool.Name)
		}
		seen[tool.Name] = true
		if tool.Schema["type"] != "object" || tool.Schema["additionalProperties"] != false || tool.Arguments == nil || tool.Operation == "" {
			t.Errorf("tool %s has an incomplete definition", tool.Name)
		}
		if _, err := json.Marshal(tool.Schema); err != nil {
			t.Errorf("tool %s schema: %v", tool.Name, err)
		}
	}
}
