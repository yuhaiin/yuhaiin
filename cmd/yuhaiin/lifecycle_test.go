package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestServerAndLocalAuthRespectRecoveryLifecycleLock(t *testing.T) {
	directory := t.TempDir()
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("lifecycle lock unsupported")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := run([]string{"-path", directory, "-host", "127.0.0.1:0", "-https=false"}); err == nil {
		t.Fatal("server ignored offline lifecycle owner")
	}
	if err := authCommand([]string{"recover", "-path", directory, "-id", "fixture"}); err == nil {
		t.Fatal("local auth ignored offline lifecycle owner")
	}
	for _, file := range []string{"management.db", "state.db", "management-tls.pem"} {
		if _, err := os.Stat(filepath.Join(directory, file)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("blocked startup mutated deployment data")
		}
	}
}
