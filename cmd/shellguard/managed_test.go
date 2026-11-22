package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// strictBuild embeds a fresh policy key for the test and returns a signer
// that writes a managed file plus its .sig.
func strictBuild(t *testing.T) func(name, content string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := policyPublicKey
	policyPublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { policyPublicKey = orig })
	return func(name, content string) {
		writeManaged(t, name, content)
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(content)))
		writeManaged(t, name+".sig", sig)
	}
}

func writeManaged(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(systemConfigDir(), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedFile(name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeUser(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir(), name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestStrict_SignedStateAccepted(t *testing.T) {
	isolateConfig(t)
	sign := strictBuild(t)
	sign("state.json", `{"mode":"dev","enabled":true}`)
	if s := loadState(); s.Mode != "dev" {
		t.Errorf("signed state ignored: %+v", s)
	}
}

func TestStrict_TamperedStateFallsBackToLogOnly(t *testing.T) {
	isolateConfig(t)
	sign := strictBuild(t)
	sign("state.json", `{"mode":"dev","enabled":true}`)
	writeManaged(t, "state.json", `{"mode":"dev","enabled":false}`) // edited after signing
	if s := loadState(); s.Mode != "log only" || !s.Enabled {
		t.Errorf("tampered state accepted: %+v", s)
	}
	if _, err := readConfig("state.json"); !errors.Is(err, errPolicyRejected) {
		t.Errorf("want errPolicyRejected, got %v", err)
	}
}

func TestStrict_UnsignedAndUserFilesIgnored(t *testing.T) {
	isolateConfig(t)
	strictBuild(t)
	writeUser(t, "state.json", `{"mode":"read only","enabled":false}`)
	if s := loadState(); s.Mode != "log only" || !s.Enabled {
		t.Errorf("per-user state used in strict build: %+v", s)
	}
	writeManaged(t, "policy.yaml", "version: 1\n") // no .sig
	if _, err := readConfig("policy.yaml"); !errors.Is(err, errPolicyRejected) {
		t.Errorf("unsigned managed policy accepted: %v", err)
	}
}

func TestStrict_TamperedSIEMConfigDisablesForwarding(t *testing.T) {
	isolateConfig(t)
	sign := strictBuild(t)
	cfg := "enabled: true\nhost: siem.corp\n"
	sign("siem.yaml", cfg)
	if _, ok := loadSIEMConfig(); !ok {
		t.Fatal("signed siem.yaml rejected")
	}
	writeManaged(t, "siem.yaml", "enabled: true\nhost: attacker.example\n")
	if _, ok := loadSIEMConfig(); ok {
		t.Error("tampered siem.yaml accepted")
	}
}

func TestStrict_RejectionReportedToSIEMOncePerHour(t *testing.T) {
	isolateConfig(t)
	sign := strictBuild(t)
	sign("siem.yaml", "enabled: true\nhost: siem.corp\n")
	writeManaged(t, "state.json", `{"mode":"dev"}`) // unsigned
	loadState()
	loadState()
	data, _ := os.ReadFile(siemQueueFile())
	if n := strings.Count(string(data), `"type":"policy_rejected"`); n != 1 {
		t.Errorf("want 1 PolicyRejected event, got %d: %s", n, data)
	}
}

func TestManagedStatePinsPolicyToo(t *testing.T) {
	isolateConfig(t)
	writeManaged(t, "state.json", `{"mode":"custom"}`)
	writeUser(t, "policy.yaml", "version: 1\nmodes:\n  custom:\n    allowed: ['*']\n")
	if p := loadPolicy(); len(p.Modes) != 0 {
		t.Errorf("user policy.yaml used while state is managed: %+v", p)
	}
	writeManaged(t, "policy.yaml", "version: 1\nmodes:\n  custom:\n    blocked: ['rm *']\n")
	if p := loadPolicy(); len(p.Modes["custom"].Blocked) != 1 {
		t.Errorf("managed policy.yaml not used: %+v", p)
	}
}

func TestNonStrict_UserFilesStillWork(t *testing.T) {
	isolateConfig(t)
	writeUser(t, "state.json", `{"mode":"read only","enabled":true}`)
	if s := loadState(); s.Mode != "read only" {
		t.Errorf("user state ignored: %+v", s)
	}
}
