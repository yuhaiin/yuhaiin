package tls

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadOrCreatePersistsCertificate(t *testing.T) {
	dir := t.TempDir()
	certificate, fingerprint, created, err := LoadOrCreate(dir, []string{"management.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first call did not create a certificate")
	}
	if fingerprint == "" {
		t.Fatal("certificate fingerprint is empty")
	}
	if err := certificate.Leaf.VerifyHostname("management.example"); err != nil {
		t.Fatalf("generated certificate does not cover requested hostname: %v", err)
	}
	if err := certificate.Leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("generated certificate does not cover localhost: %v", err)
	}

	path := filepath.Join(dir, certificateFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("certificate bundle permissions = %04o, want 0600", info.Mode().Perm())
	}

	loaded, loadedFingerprint, created, err := LoadOrCreate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second call replaced the persisted certificate")
	}
	if loadedFingerprint != fingerprint {
		t.Fatalf("loaded fingerprint = %q, want %q", loadedFingerprint, fingerprint)
	}
	if err := loaded.Leaf.VerifyHostname("management.example"); err != nil {
		t.Fatalf("persisted certificate lost requested hostname: %v", err)
	}
}

func TestLoadPair(t *testing.T) {
	dir := t.TempDir()
	_, fingerprint, _, err := LoadOrCreate(dir, []string{"management.example"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, certificateFileName))
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, rest := pem.Decode(data)
	if certificateBlock == nil {
		t.Fatal("missing certificate PEM block")
	}
	privateKeyBlock, _ := pem.Decode(rest)
	if privateKeyBlock == nil {
		t.Fatal("missing private key PEM block")
	}
	certificatePath := filepath.Join(dir, "certificate.pem")
	privateKeyPath := filepath.Join(dir, "private-key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(certificateBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(privateKeyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, loadedFingerprint, err := LoadPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedFingerprint != fingerprint {
		t.Fatalf("loaded fingerprint = %q, want %q", loadedFingerprint, fingerprint)
	}
	if err := certificate.Leaf.VerifyHostname("management.example"); err != nil {
		t.Fatalf("loaded certificate does not cover configured hostname: %v", err)
	}
}

func TestLoadOrCreateRejectsInvalidNames(t *testing.T) {
	_, _, _, err := LoadOrCreate(t.TempDir(), []string{"bad name"})
	if err == nil {
		t.Fatal("invalid certificate name was accepted")
	}
}

func TestLoadOrCreateConcurrentFirstStart(t *testing.T) {
	dir := t.TempDir()
	const workers = 8
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Go(func() {
			_, fingerprint, _, err := LoadOrCreate(dir, nil)
			if err != nil {
				errors <- err
				return
			}
			results <- fingerprint
		})
	}
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	var fingerprint string
	for current := range results {
		if fingerprint == "" {
			fingerprint = current
			continue
		}
		if current != fingerprint {
			t.Fatalf("concurrent calls loaded different certificates: %q and %q", fingerprint, current)
		}
	}
}
