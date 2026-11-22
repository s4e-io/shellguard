package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "policy.key")
	pub, err := keygen(key)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(key); info.Mode().Perm() != 0600 {
		t.Errorf("private key mode %v", info.Mode().Perm())
	}
	if _, err := keygen(key); err == nil {
		t.Error("keygen overwrote an existing key")
	}

	f := filepath.Join(dir, "state.json")
	_ = os.WriteFile(f, []byte(`{"mode":"log only"}`), 0644)
	priv, err := loadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign(priv, f); err != nil {
		t.Fatal(err)
	}
	if err := verify(pub, f); err != nil {
		t.Fatalf("verify: %v", err)
	}
	_ = os.WriteFile(f, []byte(`{"mode":"dev"}`), 0644)
	if err := verify(pub, f); err == nil {
		t.Error("tampered file verified")
	}
}
