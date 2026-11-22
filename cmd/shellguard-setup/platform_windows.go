//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// payload is the shellguard.exe built for the same architecture
// (scripts/build-windows.sh copies it here before building the setup).
//
//go:embed payload/shellguard.exe
var payload []byte

func supported() bool { return true }

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func knownFolder(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	return fallback
}

func programDataDir() string  { return knownFolder(windows.FOLDERID_ProgramData, `C:\ProgramData`) }
func programFilesDir() string { return knownFolder(windows.FOLDERID_ProgramFiles, `C:\Program Files`) }

// allUserHomes lists real profiles (those with NTUSER.DAT), including Default,
// whose files are copied into profiles created later.
func allUserHomes() ([]home, error) {
	root := knownFolder(windows.FOLDERID_UserProfiles, `C:\Users`)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var homes []home
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.EqualFold(name, "Default User") || strings.EqualFold(name, "All Users") || strings.EqualFold(name, "Public") {
			continue
		}
		dir := filepath.Join(root, name)
		if !exists(filepath.Join(dir, "NTUSER.DAT")) {
			continue
		}
		homes = append(homes, home{dir: dir, appData: filepath.Join(dir, "AppData", "Roaming")})
	}
	return homes, nil
}

// lockDownDir makes the managed directory read-only for standard users, so
// they cannot replace the binary or edit the managed state.json / siem.yaml.
// Well-known SIDs keep this independent of the Windows display language.
//
// The ACL is set on the directory only, then the existing files are reset to
// inherit it. Combining /inheritance:r with /T would strip inheritance from
// every file while the (OI)(CI) grants only land on the directory, leaving the
// files with an empty DACL (no access for anyone) — and icacls still exits 0.
func lockDownDir(dir string) error {
	out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", // Administrators
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-545:(OI)(CI)RX", // Users
		"/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil // nothing to reset; `dir\*` would fail to match
	}
	out, err = exec.Command("icacls", filepath.Join(dir, "*"), "/reset", "/T", "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls /reset: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func createHeartbeatTask(exe string) error {
	out, err := exec.Command("schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", "5",
		"/TN", heartbeatTask, "/TR", `"`+exe+`" --send`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteHeartbeatTask() error {
	return exec.Command("schtasks", "/Delete", "/F", "/TN", heartbeatTask).Run()
}
