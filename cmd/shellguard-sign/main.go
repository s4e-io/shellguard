// shellguard-sign creates the key pair for a customer build and signs the
// managed config files (state.json, policy.yaml, siem.yaml) it accepts.
//
//	shellguard-sign keygen <private-key-file>     prints the public key to embed
//	shellguard-sign sign   <private-key-file> <file>...   writes <file>.sig
//	shellguard-sign verify <public-key> <file>...
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const usage = `usage:
  shellguard-sign keygen <private-key-file>
  shellguard-sign sign   <private-key-file> <file>...
  shellguard-sign verify <public-key-base64> <file>...`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shellguard-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		pub, err := keygen(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("Private key written to %s — keep it offline, it is not needed on endpoints.\n", args[1])
		fmt.Printf("Public key (build with -ldflags \"-X main.policyPublicKey=%s\"):\n%s\n", pub, pub)
	case "sign":
		if len(args) < 3 {
			return errors.New(usage)
		}
		priv, err := loadPrivateKey(args[1])
		if err != nil {
			return err
		}
		for _, f := range args[2:] {
			if err := sign(priv, f); err != nil {
				return err
			}
			fmt.Printf("signed %s → %s.sig\n", f, f)
		}
	case "verify":
		if len(args) < 3 {
			return errors.New(usage)
		}
		for _, f := range args[2:] {
			if err := verify(args[1], f); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			fmt.Printf("%s: OK\n", f)
		}
	default:
		return errors.New(usage)
	}
	return nil
}

// keygen writes the private key (base64 seed) with owner-only permissions
// and returns the base64 public key. It never overwrites an existing key.
func keygen(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a shellguard-sign private key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sign(priv ed25519.PrivateKey, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
	return os.WriteFile(path+".sig", []byte(sig+"\n"), 0644)
}

func verify(pubB64, path string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path + ".sig")
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || !ed25519.Verify(pub, data, sig) {
		return errors.New("signature does not match")
	}
	return nil
}
