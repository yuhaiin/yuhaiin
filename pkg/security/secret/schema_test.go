package secret

import (
	"reflect"
	"testing"
)

type schemaCounter struct {
	Upload, Download uint64
	Name             string
}

type schemaFlow struct {
	Download string
	Counters map[string]schemaCounter
	History  []*schemaCounter
	hidden   any
}

type schemaPolicy struct{ Header string }

func (schemaPolicy) SecretField(string) bool { return false }

type schemaTree struct {
	Children []schemaTree
	Next     *schemaTree
	Key      *testKey
}

type schemaAny struct{ Value any }

func TestMayHoldSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		want bool
	}{
		{"counters", reflect.TypeFor[*schemaFlow](), false},
		{"tagged", reflect.TypeFor[testConfig](), true},
		{"nested tagged", reflect.TypeFor[map[string][]*testKey](), true},
		{"policy", reflect.TypeFor[[]schemaPolicy](), true},
		{"interface", reflect.TypeFor[schemaAny](), true},
		{"recursive", reflect.TypeFor[schemaTree](), true},
		{"scalar", reflect.TypeFor[string](), false},
	} {
		if got := mayHoldSecret(tc.typ); got != tc.want {
			t.Errorf("%s: mayHoldSecret = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRedactSkipsSecretFreeTypes(t *testing.T) {
	in := &schemaFlow{Download: "1", Counters: map[string]schemaCounter{"a": {Upload: 1}}, History: []*schemaCounter{{Name: "x"}}}
	out, err := Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatal("secret-free response was deep-copied")
	}
	walked, err := walk(reflect.ValueOf(in), reflect.Value{}, true, Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(walked.Interface(), out) {
		t.Fatal("skipping redaction changed the result")
	}
}

func BenchmarkRedactSecretFree(b *testing.B) {
	in := &schemaFlow{Counters: map[string]schemaCounter{}}
	for i := range 256 {
		in.Counters[string(rune('a'+i%26))+string(rune(i))] = schemaCounter{Upload: uint64(i)}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Redact(in); err != nil {
			b.Fatal(err)
		}
	}
}
