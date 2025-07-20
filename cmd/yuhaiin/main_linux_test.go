package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceInstallation(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "yuhaiin-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Set test paths
	systemdServicePath = filepath.Join(tempDir, "yuhaiin.service")
	targetBin = filepath.Join(tempDir, "yuhaiin")
	disableSystemdCommands = true // Disable actual systemd commands

	// Create a dummy executable
	dummyExe := filepath.Join(tempDir, "dummy")
	if err := os.WriteFile(dummyExe, []byte("#!/bin/sh\necho 'dummy'"), 0755); err != nil {
		t.Fatalf("Failed to create dummy executable: %v", err)
	}

	// Test installation
	t.Run("Install", func(t *testing.T) {
		// Set the current executable to our dummy
		originalArgs0 := os.Args[0]
		os.Args[0] = dummyExe
		defer func() { os.Args[0] = originalArgs0 }()

		// Create a data directory path for testing
		dataPath := filepath.Join(tempDir, "data")
		hostAddr := "127.0.0.1:8080"

		// Install the service
		err := install([]string{"-host", hostAddr, "-path", dataPath})
		if err != nil {
			t.Fatalf("Failed to install service: %v", err)
		}

		// Check if service file was created
		if _, err := os.Stat(systemdServicePath); os.IsNotExist(err) {
			t.Errorf("Service file was not created at %s", systemdServicePath)
		}

		// Check if binary was copied
		if _, err := os.Stat(targetBin); os.IsNotExist(err) {
			t.Errorf("Binary was not copied to %s", targetBin)
		}

		// Check service file content
		content, err := os.ReadFile(systemdServicePath)
		if err != nil {
			t.Fatalf("Failed to read service file: %v", err)
		}

		// Verify the service file contains the correct binary path
		if !strings.Contains(string(content), targetBin) {
			t.Errorf("Service file does not contain expected binary path: %s", targetBin)
		}

		// Verify the service file contains the correct host address
		if !strings.Contains(string(content), hostAddr) {
			t.Errorf("Service file does not contain expected host address: %s", hostAddr)
		}

		// Verify the service file contains the correct data path
		if !strings.Contains(string(content), dataPath) {
			t.Errorf("Service file does not contain expected data path: %s", dataPath)
		}

		// Test service management functions
		t.Run("ServiceManagement", func(t *testing.T) {
			// Test start function
			if err := start(nil); err != nil {
				t.Errorf("Failed to start service: %v", err)
			}

			// Test stop function
			if err := stop(nil); err != nil {
				t.Errorf("Failed to stop service: %v", err)
			}

			// Test restart function
			if err := restart(nil); err != nil {
				t.Errorf("Failed to restart service: %v", err)
			}
		})
	})

	// Test uninstallation
	t.Run("Uninstall", func(t *testing.T) {
		err := uninstall(nil)
		if err != nil {
			t.Fatalf("Failed to uninstall service: %v", err)
		}

		// Check if service file was removed
		if _, err := os.Stat(systemdServicePath); !os.IsNotExist(err) {
			t.Errorf("Service file was not removed from %s", systemdServicePath)
		}

		// Check if binary was removed
		if _, err := os.Stat(targetBin); !os.IsNotExist(err) {
			t.Errorf("Binary was not removed from %s", targetBin)
		}
	})
}
