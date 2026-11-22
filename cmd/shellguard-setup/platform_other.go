//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Off Windows the setup only runs as a dry run against a fake Windows tree,
// for development: SG_SETUP_ROOT is the fake drive, SG_SETUP_PAYLOAD the
// binary to "install".

var payload = func() []byte {
	data, _ := os.ReadFile(os.Getenv("SG_SETUP_PAYLOAD"))
	return data
}()

func root() string { return os.Getenv("SG_SETUP_ROOT") }

// supported also requires HOME inside the fake tree, so a dry run can never
// edit the developer's real ~/.cursor, ~/.claude, … files.
func supported() bool {
	return root() != "" && strings.HasPrefix(os.Getenv("HOME"), root()+string(filepath.Separator))
}
func isElevated() bool        { return true }
func programDataDir() string  { return filepath.Join(root(), "ProgramData") }
func programFilesDir() string { return filepath.Join(root(), "Program Files") }

func allUserHomes() ([]home, error) {
	entries, err := os.ReadDir(filepath.Join(root(), "Users"))
	if err != nil {
		return nil, err
	}
	var homes []home
	for _, e := range entries {
		dir := filepath.Join(root(), "Users", e.Name())
		if e.IsDir() && exists(filepath.Join(dir, "NTUSER.DAT")) {
			homes = append(homes, home{dir: dir, appData: filepath.Join(dir, "AppData", "Roaming")})
		}
	}
	return homes, nil
}

func lockDownDir(dir string) error {
	fmt.Printf("    (dry run: icacls %s)\n", dir)
	return nil
}

func createHeartbeatTask(exe string) error {
	fmt.Printf("    (dry run: schtasks %q --send)\n", exe)
	return nil
}

func deleteHeartbeatTask() error { return nil }
