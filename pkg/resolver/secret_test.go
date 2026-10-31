package resolver

import (
	"errors"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaskedResolverSavePublishesActualPersistedConfiguration(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewResolverStore(db.DB())
	original := contractresolver.Resolver{ID: "private", Name: "Private DNS", Type: "doh", Host: "https://example.test/dns-query?key=private-proof"}
	if err := store.Save(t.Context(), original, 0); err != nil {
		t.Fatal(err)
	}
	runtime := NewResolver(nil)
	defer runtime.Close()
	controller := &ResolverCtr{resolvers: store, r: runtime}
	masked, err := secret.Redact(original)
	if err != nil {
		t.Fatal(err)
	}
	masked.Name = "Renamed DNS"
	ctx := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	saved, err := controller.SaveContract(ctx, masked)
	if err != nil || saved.Host != original.Host {
		t.Fatal("masked resolver save lost proof", err)
	}
	active, ok := runtime.resolvers.Load(original.ID)
	if !ok || active.Host != original.Host || active.Name != masked.Name {
		t.Fatal("runtime activated an opaque placeholder")
	}
	masked.Host = "https://example.test/dns-query?key=replacement"
	if _, err := controller.SaveContract(ctx, masked); !errors.Is(err, secret.ErrManage) {
		t.Fatal("resolver writer changed private URL", err)
	}
	active, _ = runtime.resolvers.Load(original.ID)
	if active.Host != original.Host {
		t.Fatal("denied write changed resolver runtime")
	}
}

func TestPrivateResolverURLIsNotCopiedIntoDefaultPublicName(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	controller := &ResolverCtr{resolvers: plainstore.NewResolverStore(db.DB()), r: NewResolver(nil)}
	defer controller.r.Close()
	saved, err := controller.SaveContract(t.Context(), contractresolver.Resolver{ID: "private", Type: "doh", Host: "https://user:private-proof@example.test/path?key=private-query"})
	if err != nil {
		t.Fatal(err)
	}
	masked, err := secret.Redact(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(masked.Name, "private-proof") || strings.Contains(masked.Name, "private-query") {
		t.Fatal("default resolver name exposed URL credentials")
	}
}
