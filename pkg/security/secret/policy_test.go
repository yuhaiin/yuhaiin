package secret

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

type testKey struct {
	ID       string
	Password string `secret:"true"`
	Key      []byte `secret:"true"`
}
type testConfig struct {
	Name    string
	Keys    []testKey
	Users   map[string]string   `secret:"values"`
	Headers map[string][]string `secret:"values"`
	URL     string              `secret:"url"`
	Hooks   []string            `secret:"true" privilege:"system:execute"`
}

func testValue() testConfig {
	return testConfig{Name: "Gateway", Keys: []testKey{{ID: "alice", Password: "alice-proof", Key: []byte("alice-private")}, {ID: "bob", Password: "bob-proof"}}, Users: map[string]string{"carol": "carol-proof"}, Headers: map[string][]string{"Authorization": {"Bearer upstream-proof"}}, URL: "https://user:proof@example.com/path", Hooks: []string{"echo configured"}}
}

func TestRedactionClonesAndPreservesResourcesByID(t *testing.T) {
	original := testValue()
	before := testValue()
	masked, err := Redact(original)
	if err != nil {
		t.Fatal(err)
	}
	if !isMarker(reflect.ValueOf(masked.Keys[0].Password)) || !isMarker(reflect.ValueOf(masked.Keys[0].Key)) || !isMarker(reflect.ValueOf(masked.Users["carol"])) || !isMarker(reflect.ValueOf(masked.Headers["Authorization"])) || !isMarker(reflect.ValueOf(masked.URL)) {
		t.Fatal("annotated proof escaped redaction", masked)
	}
	masked.Name = "Renamed"
	masked.Keys[0], masked.Keys[1] = masked.Keys[1], masked.Keys[0]
	ctx := WithCapabilities(t.Context(), Capabilities{})
	saved, err := Merge(ctx, masked, original)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Name != "Renamed" || saved.Keys[0].ID != "bob" || saved.Keys[0].Password != "bob-proof" || saved.Keys[1].Password != "alice-proof" || !bytes.Equal(saved.Keys[1].Key, []byte("alice-private")) {
		t.Fatal("reordered metadata attached another owner's secret", saved)
	}
	if !reflect.DeepEqual(original, before) {
		t.Fatal("read or merge mutated published configuration")
	}
	saved.Keys[1].Key[0] = 'X'
	if !reflect.DeepEqual(original, before) {
		t.Fatal("merged private key aliases published configuration")
	}
}

func TestSecretChangesAndClearsNeedSeparateCapabilities(t *testing.T) {
	for _, edit := range []func(*testConfig){
		func(v *testConfig) { v.Keys[0].Password = "replacement" },
		func(v *testConfig) { v.Keys[0].Password = "" },
		func(v *testConfig) { v.Keys = v.Keys[1:] },
		func(v *testConfig) { delete(v.Users, "carol") },
		func(v *testConfig) { v.Headers["Authorization"] = []string{"Bearer replacement"} },
	} {
		old := testValue()
		next, _ := Redact(old)
		edit(&next)
		if _, err := Merge(WithCapabilities(t.Context(), Capabilities{}), next, old); !errors.Is(err, ErrManage) {
			t.Fatal("secret mutation accepted", err)
		}
		if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), next, old); err != nil {
			t.Fatal("authorized secret mutation rejected", err)
		}
	}
	old := testValue()
	next, _ := Redact(old)
	next.Hooks = []string{"different command"}
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), next, old); !errors.Is(err, ErrExecute) {
		t.Fatal("secret management permits executable hook changes", err)
	}
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true, Execute: true}), next, old); err != nil {
		t.Fatal(err)
	}
}

func TestMarkersCannotCreateOrBorrowAnotherResourceSecret(t *testing.T) {
	old := testValue()
	next, _ := Redact(old)
	next.Keys[0].ID = "unknown"
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), next, old); !errors.Is(err, ErrPreserved) {
		t.Fatal("marker borrowed another object's credential", err)
	}
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), testKey{ID: "new", Password: Preserved}, testKey{}); !errors.Is(err, ErrPreserved) {
		t.Fatal("new resource persisted a marker", err)
	}
}

func TestOptionalPolicyPreservesNativeConfigurationSemantics(t *testing.T) {
	old := testValue()
	next := testValue()
	next.Keys[0].Password = "new"
	saved, err := Merge(t.Context(), next, old)
	if err != nil || saved.Keys[0].Password != "new" {
		t.Fatal(saved, err)
	}
}

func TestPrivateURLsIncludeRelativeAndMalformedCapabilityURLs(t *testing.T) {
	for _, value := range []string{"/callback?token=private-proof", "https://example.test/#private-proof", "https://user:private-proof@[invalid"} {
		original := struct {
			URL string `secret:"url"`
		}{URL: value}
		masked, err := Redact(original)
		if err != nil || masked.URL == value {
			t.Fatal("private URL was not masked", err)
		}
		preserved, err := Merge(WithCapabilities(t.Context(), Capabilities{}), masked, original)
		if err != nil || preserved.URL != value {
			t.Fatal("private URL was not preserved", err)
		}
	}
}

func TestPlaintextEqualityDoesNotExposeAGuessingOracle(t *testing.T) {
	original := testKey{ID: "node", Password: "stored-private-proof"}
	ctx := WithCapabilities(t.Context(), Capabilities{})
	for _, candidate := range []string{"stored-private-proof", "incorrect-guess"} {
		if _, err := Merge(ctx, testKey{ID: "node", Password: candidate}, original); !errors.Is(err, ErrManage) {
			t.Fatal("plaintext guess distinguished the stored value", err)
		}
	}
	masked, err := Redact(original)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Merge(ctx, masked, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(WithResolvedConfiguration(ctx), resolved, original); err != nil {
		t.Fatal("internal persistence rejected the validated preserved value", err)
	}
	resolved.Password = "replacement"
	if _, err := Merge(WithResolvedConfiguration(ctx), resolved, original); !errors.Is(err, ErrManage) {
		t.Fatal("internal persistence changed a secret", err)
	}
}
