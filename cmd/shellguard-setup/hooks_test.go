package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInvokeQuoting(t *testing.T) {
	cases := []struct{ got, want string }{
		{psInvoke(`C:\ProgramData\ShellGuard\shellguard.exe`, ""), `C:\ProgramData\ShellGuard\shellguard.exe`},
		{psInvoke(`C:\Users\Jane Doe\AppData\Local\Programs\ShellGuard\shellguard.exe`, "--source vscode"),
			`& 'C:\Users\Jane Doe\AppData\Local\Programs\ShellGuard\shellguard.exe' --source vscode`},
		{psInvoke(`C:\Users\O'Brien\sg.exe`, ""), `& 'C:\Users\O''Brien\sg.exe'`},
		{cmdInvoke(`C:\Users\Jane Doe\sg.exe`, "--source junie"), `"C:\Users\Jane Doe\sg.exe" --source junie`},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got  %s\nwant %s", c.got, c.want)
		}
	}
}

func TestEditCursor_KeepsOthersMigratesLegacyIdempotent(t *testing.T) {
	doc := parse(t, `{
	  "beforeShellExecution": {"command": "/old/shellguard"},
	  "hooks": {"beforeShellExecution": [{"command": "other-guard.exe"}], "afterFileEdit": [{"command": "fmt.exe"}]}
	}`)
	editCursor(doc, `C:\sg\shellguard.exe`, true)
	editCursor(doc, `C:\sg\shellguard.exe`, true) // second install

	if _, legacy := doc["beforeShellExecution"]; legacy {
		t.Error("legacy top-level entry not removed")
	}
	hooks := doc["hooks"].(map[string]any)
	before := hooks["beforeShellExecution"].([]any)
	if len(before) != 2 || before[0].(map[string]any)["command"] != "other-guard.exe" {
		t.Errorf("before hooks wrong: %v", before)
	}
	if len(hooks["afterShellExecution"].([]any)) != 1 || hooks["afterFileEdit"] == nil {
		t.Errorf("hooks wrong: %s", roundTrip(t, doc))
	}
	if doc["version"] != 1 {
		t.Error("version missing")
	}

	editCursor(doc, "", false)
	hooks = doc["hooks"].(map[string]any)
	if len(hooks["beforeShellExecution"].([]any)) != 1 || hooks["afterShellExecution"] != nil {
		t.Errorf("uninstall touched others or left ours: %s", roundTrip(t, doc))
	}
}

func TestEditMatcherGroups_ClaudeSettings(t *testing.T) {
	doc := parse(t, `{
	  "model": "opus",
	  "hooks": {"PreToolUse": [
	    {"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.sh"}]},
	    {"matcher": "Bash", "hooks": [{"type": "command", "command": "C:/old/shellguard.exe"}]}
	  ]}
	}`)
	events := []string{"PreToolUse", "PostToolUse"}
	editMatcherGroups(doc, events, "Bash|PowerShell", claudeHook(`C:\sg\shellguard.exe`), true)
	editMatcherGroups(doc, events, "Bash|PowerShell", claudeHook(`C:\sg\shellguard.exe`), true)

	out := roundTrip(t, doc)
	if strings.Count(out, "shellguard.exe") != 2 || !strings.Contains(out, "audit.sh") || doc["model"] != "opus" {
		t.Errorf("install wrong: %s", out)
	}
	if strings.Contains(out, "C:/old/") {
		t.Error("stale ShellGuard entry not replaced")
	}

	editMatcherGroups(doc, events, "", nil, false)
	out = roundTrip(t, doc)
	if strings.Contains(out, "shellguard") || !strings.Contains(out, "audit.sh") {
		t.Errorf("uninstall wrong: %s", out)
	}
}

func TestEditMatcherGroups_RemovesEmptyHooksKey(t *testing.T) {
	doc := map[string]any{}
	editMatcherGroups(doc, []string{"PreToolUse"}, "Bash", commandHook("shellguard"), true)
	editMatcherGroups(doc, []string{"PreToolUse"}, "", nil, false)
	if len(doc) != 0 {
		t.Errorf("want empty doc, got %s", roundTrip(t, doc))
	}
}

// The Claude Code hook must not depend on a shell: a quoted command string is
// a string literal in PowerShell (used when Git Bash is missing), so the hook
// exited 127 and Claude Code blocked every command.
func TestClaudeHook_ExecForm(t *testing.T) {
	exe := `C:\Users\Jane Doe\AppData\Local\Programs\ShellGuard\shellguard.exe`
	doc := map[string]any{}
	editMatcherGroups(doc, []string{"PreToolUse", "PostToolUse"}, "Bash|PowerShell", claudeHook(exe), true)

	// Round-trip through JSON, as the file on disk would be read back.
	doc = parse(t, roundTrip(t, doc))
	for _, ev := range []string{"PreToolUse", "PostToolUse"} {
		group := doc["hooks"].(map[string]any)[ev].([]any)[0].(map[string]any)
		h := group["hooks"].([]any)[0].(map[string]any)
		cmd, _ := h["command"].(string)
		// ToSlash only rewrites backslashes on Windows, so derive the expectation.
		if cmd != filepath.ToSlash(exe) {
			t.Errorf("%s: command = %q, want the bare path (no quotes)", ev, cmd)
		}
		if strings.ContainsAny(cmd, `"'&`) {
			t.Errorf("%s: command must not carry shell quoting: %q", ev, cmd)
		}
		if args, ok := h["args"].([]any); !ok || len(args) != 0 {
			t.Errorf("%s: want \"args\": [] (exec form), got %v", ev, h["args"])
		}
	}
}

func TestEditJSONFile(t *testing.T) {
	dir := t.TempDir()

	// Missing file → created.
	p := filepath.Join(dir, "a", "hooks.json")
	if err := editJSONFile(p, func(d map[string]any) { d["x"] = 1.0 }); err != nil {
		t.Fatal(err)
	}

	// BOM-prefixed file → parsed, one backup kept.
	b := filepath.Join(dir, "bom.json")
	_ = os.WriteFile(b, []byte("\ufeff{\"keep\":true}"), 0644)
	if err := editJSONFile(b, func(d map[string]any) { d["added"] = true }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(b)
	if !strings.Contains(string(data), `"keep": true`) || !exists(b+".shellguard-backup") {
		t.Errorf("BOM file not handled: %s", data)
	}

	// JSONC (comments) → refused, file untouched.
	c := filepath.Join(dir, "c.json")
	orig := "// comment\n{\"a\":1}"
	_ = os.WriteFile(c, []byte(orig), 0644)
	if err := editJSONFile(c, func(d map[string]any) {}); !errors.Is(err, errNotJSON) {
		t.Fatalf("want errNotJSON, got %v", err)
	}
	if data, _ := os.ReadFile(c); string(data) != orig {
		t.Error("non-JSON file was modified")
	}
}
