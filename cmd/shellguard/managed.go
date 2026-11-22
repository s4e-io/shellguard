package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── Managed (admin) config ────────────────────────────────────────────────────
//
// state.json, policy.yaml and siem.yaml are looked up in systemConfigDir()
// first (admin-owned: /Library/Application Support/ShellGuard, /etc/shellguard,
// C:\ProgramData\ShellGuard) and then in the per-user configDir().
//
// Customer builds can embed an Ed25519 public key:
//
//	go build -ldflags "-X main.policyPublicKey=<base64>" ./cmd/shellguard
//
// Such a build is strict: only managed files are read (per-user copies are
// ignored), and each must have a valid detached signature next to it
// (state.json.sig, …) made with `shellguard-sign`. A file that fails the check
// is rejected — state falls back to "log only", policy to the mode defaults,
// SIEM forwarding is turned off — and a PolicyRejected event is sent.

// policyPublicKey is the base64 Ed25519 key managed files must be signed
// with; empty means signatures are not required.
var policyPublicKey = ""

var errPolicyRejected = errors.New("managed config rejected: invalid or missing signature")

func strictPolicy() bool { return policyPublicKey != "" }

func managedFile(name string) string { return filepath.Join(systemConfigDir(), name) }

// configFile returns the path name is read from (for messages and status).
func configFile(name string) string {
	if p := managedFile(name); strictPolicy() || fileExists(p) || managedOnly(name) {
		return p
	}
	return filepath.Join(configDir(), name)
}

// managedOnly: once the admin pins state.json, rules must come from the
// managed policy.yaml too — otherwise a user could edit their own rules for
// the pinned "custom" mode.
func managedOnly(name string) bool {
	return name == "policy.yaml" && fileExists(managedFile("state.json"))
}

// readConfig reads name from the managed or per-user config directory,
// enforcing signatures in strict builds. Returns os.ErrNotExist-wrapping
// errors when there is no file, errPolicyRejected when a signature fails.
func readConfig(name string) ([]byte, error) {
	path := configFile(name)
	data, err := os.ReadFile(path)
	if err != nil || !strictPolicy() {
		return data, err
	}
	if err := verifySignature(data, path+".sig"); err != nil {
		reportRejected(name, err)
		return nil, fmt.Errorf("%s: %w (%v)", path, errPolicyRejected, err)
	}
	return data, nil
}

func verifySignature(data []byte, sigPath string) error {
	pub, err := base64.StdEncoding.DecodeString(policyPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("built-in policy key is malformed")
	}
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("signature missing: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || !ed25519.Verify(pub, data, sig) {
		return errors.New("signature does not match")
	}
	return nil
}

var reportingRejection bool

// reportRejected logs the rejection and, at most once an hour, forwards a
// PolicyRejected event (unless siem.yaml itself was the file rejected).
func reportRejected(name string, cause error) {
	logError("ERROR", fmt.Sprintf("managed %s rejected: %v", name, cause))
	if reportingRejection || name == "siem.yaml" {
		return
	}
	if time.Since(time.Unix(loadSIEMState().LastReject, 0)) < time.Hour {
		return
	}
	reportingRejection = true
	defer func() { reportingRejection = false }()
	updateSIEMState(func(st *siemState) { st.LastReject = time.Now().Unix() })
	forwardToSIEM(systemEvent("policy_rejected", fmt.Sprintf("%s: %v", name, cause)))
}
