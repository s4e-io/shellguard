package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ── Hook command strings ──────────────────────────────────────────────────────
//
// Each AI tool runs its hook command through a different shell on Windows, so
// the binary path has to be quoted for that shell.

// psInvoke: Cursor and Copilot run hooks through PowerShell, where a quoted
// path alone is a string literal — it needs the call operator.
func psInvoke(exe, args string) string {
	cmd := exe
	if strings.ContainsAny(exe, " '&;()") {
		cmd = "& '" + strings.ReplaceAll(exe, "'", "''") + "'"
	}
	return strings.TrimSpace(cmd + " " + args)
}

// cmdInvoke: Junie runs hooks with `cmd /c`.
func cmdInvoke(exe, args string) string {
	return strings.TrimSpace(`"` + exe + `" ` + args)
}

// claudeHook: Claude Code runs a hook's command string through Git Bash, or
// through PowerShell when Git Bash is not installed. No single quoting works
// in both: a quoted path is a program in bash but a string literal in
// PowerShell, so the hook exits 127 — and without Git Bash Claude Code treats
// any exit other than 0 or 2 as "block", which stops every command even in log
// only mode. The exec form ("command" + "args") starts the binary directly,
// with no shell, so spaces in the path need no quoting either.
func claudeHook(exe string) map[string]any {
	return map[string]any{"type": "command", "command": filepath.ToSlash(exe), "args": []any{}}
}

// commandHook is a plain shell-string hook entry (Junie).
func commandHook(cmd string) map[string]any {
	return map[string]any{"type": "command", "command": cmd}
}

func isOurs(cmd any) bool {
	s, _ := cmd.(string)
	return strings.Contains(strings.ToLower(s), "shellguard")
}

// ── Per-tool document edits ───────────────────────────────────────────────────
//
// Every edit removes existing ShellGuard entries first, so install is
// idempotent and uninstall only touches what we added.

// editCursor handles Cursor's hooks.json (version 1 format). It also drops the
// legacy top-level {"beforeShellExecution": {"command": "...shellguard"}} entry.
func editCursor(doc map[string]any, cmd string, add bool) {
	for _, ev := range []string{"beforeShellExecution", "afterShellExecution"} {
		if legacy, ok := doc[ev].(map[string]any); ok && isOurs(legacy["command"]) {
			delete(doc, ev)
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, ev := range []string{"beforeShellExecution", "afterShellExecution"} {
		list, _ := hooks[ev].([]any)
		kept := []any{}
		for _, h := range list {
			if m, ok := h.(map[string]any); ok && isOurs(m["command"]) {
				continue
			}
			kept = append(kept, h)
		}
		if add {
			kept = append(kept, map[string]any{"command": cmd})
		}
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	doc["version"] = 1
	doc["hooks"] = hooks
}

// editMatcherGroups handles the Claude Code / Junie layout:
// {"hooks": {"PreToolUse": [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]}}
// hook is the entry to add (ignored when add is false).
func editMatcherGroups(doc map[string]any, events []string, matcher string, hook map[string]any, add bool) {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, ev := range events {
		groups, _ := hooks[ev].([]any)
		kept := []any{}
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				kept = append(kept, g)
				continue
			}
			inner, _ := gm["hooks"].([]any)
			var rest []any
			for _, h := range inner {
				if hm, ok := h.(map[string]any); ok && isOurs(hm["command"]) {
					continue
				}
				rest = append(rest, h)
			}
			if len(rest) == 0 && len(inner) > 0 {
				continue // group only held our hook
			}
			gm["hooks"] = rest
			kept = append(kept, gm)
		}
		if add {
			// Each event gets its own copy so the encoded JSON has no shared maps.
			entry := make(map[string]any, len(hook))
			for k, v := range hook {
				entry[k] = v
			}
			kept = append(kept, map[string]any{
				"matcher": matcher,
				"hooks":   []any{entry},
			})
		}
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"] = hooks
	}
}

// copilotHooks is the whole content of ~/.copilot/hooks/shellguard.json.
// PascalCase event names select the snake_case payload ShellGuard parses.
func copilotHooks(cmd string) map[string]any {
	entry := func() []any {
		return []any{map[string]any{"type": "command", "command": cmd, "timeoutSec": 10}}
	}
	return map[string]any{
		"version": 1,
		"hooks":   map[string]any{"PreToolUse": entry(), "PostToolUse": entry()},
	}
}

// ── JSON file helpers ─────────────────────────────────────────────────────────

var errNotJSON = errors.New("existing file is not plain JSON — left unchanged, edit it manually")

// editJSONFile applies fn to the JSON object stored at path (missing file →
// empty object). A one-time backup is kept next to the original.
func editJSONFile(path string, fn func(map[string]any)) error {
	doc := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		trimmed := strings.TrimPrefix(string(data), "\ufeff")
		if strings.TrimSpace(trimmed) != "" {
			if json.Unmarshal([]byte(trimmed), &doc) != nil {
				return fmt.Errorf("%s: %w", path, errNotJSON)
			}
		}
		// Back up the original only — never a copy that already has our hook.
		if bak := path + ".shellguard-backup"; !exists(bak) && !strings.Contains(strings.ToLower(string(data)), "shellguard") {
			_ = os.WriteFile(bak, data, 0644)
		}
	case !os.IsNotExist(err):
		return err
	}
	fn(doc)
	return writeJSON(path, doc)
}

func writeJSON(path string, doc any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// fileHasOurHook reports whether a JSON file mentions ShellGuard (for status).
func fileHasOurHook(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(strings.ToLower(string(data)), "shellguard")
}
