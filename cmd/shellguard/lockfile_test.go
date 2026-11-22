package main

import (
	"path/filepath"
	"testing"
)

// `shellguard --send` (e.g. the heartbeat task) can run for a user who has
// never triggered a hook, so the config directory may not exist yet. Taking
// the send lock must create it instead of failing with "path not found".
func TestLockFile_CreatesMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "ShellGuard", "siem_send.lock")
	release, err := lockFile(path, true, true)
	if err != nil {
		t.Fatalf("lockFile on a missing directory: %v", err)
	}
	release()
	if !fileExists(path) {
		t.Errorf("lock file not created at %s", path)
	}
}
