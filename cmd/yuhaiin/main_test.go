package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPath(t *testing.T) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		t.Error(err)
		return
	}
	path, err := filepath.Abs(file)
	if err != nil {
		t.Error(err)
		return
	}
	log.Println(filepath.Dir(path))
}
