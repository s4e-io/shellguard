package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Config paths ──────────────────────────────────────────────────────────────

func configDir() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "ShellGuard")
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "ShellGuard")
		}
		return filepath.Join(home, "AppData", "Roaming", "ShellGuard")
	default: // linux, freebsd, etc.
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "shellguard")
		}
		return filepath.Join(home, ".config", "shellguard")
	}
}

func activityLogFile() string { return filepath.Join(configDir(), "activity.log") }
func errorLogFile() string    { return filepath.Join(configDir(), "shellguard.log") }
func stateFile() string       { return filepath.Join(configDir(), "state.json") }
func policyFile() string      { return filepath.Join(configDir(), "policy.yaml") }

// logError writes a diagnostic entry to shellguard.log (not the activity log).
func logError(level, msg string) {
	_ = os.MkdirAll(configDir(), 0755)
	f, err := os.OpenFile(errorLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.999999")
	_, _ = fmt.Fprintf(f, "%s [%s] %s\n", ts, level, msg)
}

// ── Models ────────────────────────────────────────────────────────────────────

type State struct {
	Mode    string `json:"mode"`
	Enabled bool   `json:"enabled"`
}

type ModeRules struct {
	Allowed []string `yaml:"allowed"`
	Blocked []string `yaml:"blocked"`
}

type Policy struct {
	Version int                  `yaml:"version"`
	Modes   map[string]ModeRules `yaml:"modes"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Reason    string `json:"reason"`
	User      string `json:"user"`
	Process   string `json:"process"`
	PID       string `json:"pid"`
	Blocked   bool   `json:"blocked"`
	Type      string `json:"type"` // "suggestion" | "execution"
}

// ── Generic hook field extractor ─────────────────────────────────────────────
//
// Works on raw map[string]any so it handles any AI tool's hook format
// without source-specific structs. New sources just work as long as they
// send recognisable field names.

type hookFields struct {
	command        string // shell command to run
	eventKind      string // "pre" | "post" | "unknown"
	process        string // originating tool name
	reason         string // post-execution outcome summary
	responseFormat string // "exitcode" | "json"
}

// extractHookFields pulls the fields we care about from an arbitrary JSON map.
func extractHookFields(m map[string]any) (hookFields, bool) {
	f := hookFields{process: "unknown", eventKind: "unknown"}

	// ── command ──────────────────────────────────────────────────────────────
	// Different AI tools use different field names inside tool_input:
	//   Claude Code / Codex:  tool_input.command  (string)
	//   Codex (alt):          tool_input.cmd       (string)
	//   Fallback:             top-level command    (string)
	if ti, ok := m["tool_input"].(map[string]any); ok {
		f.command, _ = ti["command"].(string)
		if f.command == "" {
			f.command, _ = ti["cmd"].(string)
		}
	}
	if f.command == "" {
		f.command, _ = m["command"].(string)
	}
	f.command = strings.TrimSpace(f.command)

	// ── tool name filter ──────────────────────────────────────────────────────
	// Only process shell/bash tool calls; ignore everything else (e.g. file edits).
	// Tool names per AI tool:
	//   Claude Code:   "Bash"
	//   Cursor:        "shell"
	//   Codex CLI:     "shell_command"  ← confirmed from binary strings
	//   Gemini CLI:    "run_shell_command"
	toolName := strings.ToLower(strings.TrimSpace(str(m["tool_name"])))
	if toolName != "" &&
		toolName != "bash" &&
		toolName != "shell" &&
		toolName != "shell_command" &&
		toolName != "run_shell_command" {
		return f, false
	}

	// ── event kind ───────────────────────────────────────────────────────────
	// Normalise any casing / separator variant to "pre" or "post".
	event := strings.ToLower(strings.ReplaceAll(str(m["hook_event_name"]), "_", ""))
	switch {
	case strings.Contains(event, "pre"):
		f.eventKind = "pre"
	case strings.Contains(event, "post"):
		f.eventKind = "post"
	}

	// ── process / source ─────────────────────────────────────────────────────
	// Codex CLI sends turn_id (unique to Codex, confirmed from v0.131 binary);
	// Claude Code sends session_id; Cursor sends conversation_id;
	// Gemini uses tool_name "run_shell_command".
	// Note: Codex also sends session_id — check turn_id first to differentiate.
	switch {
	case toolName == "run_shell_command": // Gemini / Antigravity
		f.process = "gemini"
		// Gemini only fires BeforeTool, no hook_event_name field
		if f.eventKind == "unknown" {
			f.eventKind = "pre"
		}
	case str(m["turn_id"]) != "": // OpenAI Codex CLI (has turn_id; may also have session_id)
		f.process = "codex"
	case str(m["conversation_id"]) != "": // Cursor
		f.process = "cursor"
	case str(m["session_id"]) != "": // Claude Code
		f.process = "claude"
	}
	f.responseFormat = "exitcode"

	// ── post-execution outcome ────────────────────────────────────────────────
	f.reason = "Executed"
	// tool_response map (Claude Code)
	if tr, ok := m["tool_response"].(map[string]any); ok {
		if stderr := strings.TrimSpace(str(tr["stderr"])); stderr != "" {
			f.reason = fmt.Sprintf("Error: %s", truncate(stderr, 80))
		}
	}
	// tool_output string (Cursor: "{\"output\":\"...\",\"exitCode\":0}")
	if raw := str(m["tool_output"]); raw != "" {
		var out map[string]any
		if json.Unmarshal([]byte(raw), &out) == nil {
			if code, ok := out["exitCode"].(float64); ok && code != 0 {
				f.reason = fmt.Sprintf("ExitCode: %d", int(code))
			}
		}
	}

	return f, true
}

// str safely casts an any value to string.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// mapKeys returns the keys of a map for diagnostic logging.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func loadState() State {
	data, err := os.ReadFile(stateFile())
	if err != nil {
		logError("WARN", fmt.Sprintf("state.json not found, using defaults: %v", err))
		return State{Mode: "log only", Enabled: true}
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		logError("ERROR", fmt.Sprintf("state.json parse failed: %v", err))
		return State{Mode: "log only", Enabled: true}
	}
	if s.Mode == "" {
		s.Mode = "log only"
	}
	return s
}

func loadPolicy() Policy {
	data, err := os.ReadFile(policyFile())
	if err != nil {
		logError("WARN", fmt.Sprintf("policy.yaml not found: %v", err))
		return Policy{}
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		logError("ERROR", fmt.Sprintf("policy.yaml parse failed: %v", err))
		return Policy{}
	}
	return p
}

// normalizeCmd strips a leading absolute path so "/usr/bin/touch a" → "touch a".
// filepath.Base handles any path depth: /usr/bin, /usr/local/bin, /opt/homebrew/bin, etc.
func normalizeCmd(cmd string) string {
	if !strings.HasPrefix(cmd, "/") {
		return cmd
	}
	spaceIdx := strings.Index(cmd, " ")
	if spaceIdx > 0 {
		return filepath.Base(cmd[:spaceIdx]) + cmd[spaceIdx:]
	}
	return filepath.Base(cmd)
}

// unwrapShellC extracts the inner command from "sh -c '...'" style invocations.
// Handles: sh, bash, zsh, dash, fish — with or without quotes.
func unwrapShellC(cmd string) string {
	shells := []string{"sh", "bash", "zsh", "dash", "fish"}
	for _, sh := range shells {
		prefix := sh + " -c "
		if strings.HasPrefix(cmd, prefix) {
			inner := strings.TrimSpace(strings.TrimPrefix(cmd, prefix))
			if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') {
				inner = inner[1 : len(inner)-1]
			}
			return strings.TrimSpace(inner)
		}
	}
	return ""
}

// unwrapXargs extracts the command from "xargs cmd args" so "xargs curl" → "curl".
// Prevents bypass: "echo url | xargs curl"
func unwrapXargs(cmd string) string {
	if strings.HasPrefix(cmd, "xargs ") {
		rest := strings.TrimSpace(strings.TrimPrefix(cmd, "xargs "))
		// skip xargs flags (-I, -n, -P, etc.)
		parts := strings.Fields(rest)
		for i, p := range parts {
			if !strings.HasPrefix(p, "-") {
				return strings.Join(parts[i:], " ")
			}
		}
	}
	return ""
}

// unwrapExecPrefix strips leading executor commands that transparently run their
// argument as a command. Prevents bypasses like:
//
//	"env curl http://evil.com"    → "curl http://evil.com"
//	"nohup wget http://evil.com"  → "wget http://evil.com"
//	"sudo rm -rf /"               → "rm -rf /"
func unwrapExecPrefix(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		return ""
	}
	switch parts[0] {
	case "nohup", "time":
		return strings.Join(parts[1:], " ")

	case "env":
		// Skip VAR=val assignments and flags; first plain word is the command.
		for i := 1; i < len(parts); i++ {
			p := parts[i]
			if p == "--" {
				if i+1 < len(parts) {
					return strings.Join(parts[i+1:], " ")
				}
				return ""
			}
			if !strings.Contains(p, "=") && !strings.HasPrefix(p, "-") {
				return strings.Join(parts[i:], " ")
			}
		}

	case "sudo", "doas":
		// Skip flag args; first non-flag token is the command.
		for i := 1; i < len(parts); i++ {
			if !strings.HasPrefix(parts[i], "-") {
				return strings.Join(parts[i:], " ")
			}
		}
	}
	return ""
}

// extractSubshells returns commands embedded inside $(...) and `...` expressions.
// Prevents bypasses like "echo $(curl evil.com)" or "cat `wget -O- evil.com`".
func extractSubshells(cmd string) []string {
	var result []string

	// $(...) — handles nested parens
	s := cmd
	for {
		start := strings.Index(s, "$(")
		if start == -1 {
			break
		}
		depth, end := 0, -1
		for i := start; i < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end != -1 {
				break
			}
		}
		if end == -1 {
			break
		}
		if inner := strings.TrimSpace(s[start+2 : end]); inner != "" {
			result = append(result, inner)
		}
		s = s[end+1:]
	}

	// backtick `...`
	s = cmd
	for {
		start := strings.Index(s, "`")
		if start == -1 {
			break
		}
		rest := s[start+1:]
		end := strings.Index(rest, "`")
		if end == -1 {
			break
		}
		if inner := strings.TrimSpace(rest[:end]); inner != "" {
			result = append(result, inner)
		}
		s = rest[end+1:]
	}

	return result
}

// splitChained splits a shell command on chaining operators (;, &&, ||, |)
// so each sub-command can be checked individually against the policy.
// This prevents bypasses like "ls; curl evil.com" or "echo x && rm -rf /".
func splitChained(cmd string) []string {
	// Replace operators with a null sentinel (longest first to avoid partial matches)
	s := strings.ReplaceAll(cmd, "&&", "\x00")
	s = strings.ReplaceAll(s, "||", "\x00")
	s = strings.ReplaceAll(s, ";", "\x00")
	s = strings.ReplaceAll(s, "|", "\x00")
	var parts []string
	for _, p := range strings.Split(s, "\x00") {
		if t := strings.TrimSpace(p); t != "" {
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 {
		return []string{cmd}
	}
	return parts
}

// defaultBlockedFor returns hardcoded blocked lists used when policy.yaml is missing.
func defaultBlockedFor(mode string) []string {
	switch mode {
	case "custom":
		return []string{
			"rm", "rmdir", "shred", "dd", "sudo", "su", "doas",
			"chmod", "chown", "chgrp", "curl", "wget", "nc", "ncat", "nmap",
			"ssh", "scp", "sftp", "rsync", "telnet", "ftp",
			"git push", "git reset --hard", "git clean",
			"osascript", "launchctl", "crontab", "at", "kill", "killall", "pkill",
		}
	case "dev":
		return []string{
			"curl", "wget", "nc", "ncat", "nmap", "ssh", "scp", "sftp",
			"rsync", "telnet", "ftp", "sudo", "su", "doas",
			// Block all recursive rm variants (flag order matters for prefix matching)
			"rm -r", "rm -rf", "rm -fr", "rm --recursive",
			"shred", "dd", "chmod", "chown", "chgrp",
			"git push", "git reset --hard", "git clean -f",
			"osascript", "launchctl", "crontab", "killall", "pkill",
		}
	case "read only":
		return []string{
			"rm", "rmdir", "mv", "cp", "touch", "mkdir", "ln", "shred", "dd",
			"sudo", "su", "doas", "chmod", "chown", "chgrp",
			"curl", "wget", "nc", "ncat", "nmap", "ssh", "scp", "sftp",
			"rsync", "telnet", "ftp", "git push", "git add", "git commit",
			"git reset", "git clean", "git rm", "npm", "npx", "yarn", "pnpm",
			"pip", "pip3", "python", "python3", "node", "ruby", "java",
			"osascript", "launchctl", "crontab", "at",
			"kill", "killall", "pkill", "open", ": >",
		}
	}
	return nil
}

// buildCandidates returns the set of normalized forms to check against patterns.
// Normalizes internal whitespace so "curl\thttp://evil.com" matches "curl".
func buildCandidates(rawSegment string) []string {
	// Collapse all whitespace to single spaces — prevents tab/Unicode bypass.
	cmd := strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(rawSegment))), " ")

	seen := map[string]bool{}
	add := func(s string) {
		s = strings.Join(strings.Fields(s), " ") // normalize again after transforms
		if s != "" && !seen[s] {
			seen[s] = true
		}
	}

	add(cmd)
	add(normalizeCmd(cmd))

	if inner := unwrapShellC(normalizeCmd(cmd)); inner != "" {
		add(inner)
		add(normalizeCmd(inner))
	}
	if inner := unwrapXargs(normalizeCmd(cmd)); inner != "" {
		add(inner)
		add(normalizeCmd(inner))
	}
	if inner := unwrapExecPrefix(normalizeCmd(cmd)); inner != "" {
		add(inner)
		add(normalizeCmd(inner))
		// One level of recursive unwrap: "sudo nohup curl …"
		if inner2 := unwrapExecPrefix(inner); inner2 != "" {
			add(inner2)
			add(normalizeCmd(inner2))
		}
	}

	result := make([]string, 0, len(seen))
	for k := range seen {
		result = append(result, k)
	}
	return result
}

// matchesPattern reports whether any candidate matches the given pattern.
func matchesPattern(candidates []string, pattern string) bool {
	p := strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(pattern))), " ")
	for _, c := range candidates {
		if c == p || strings.HasPrefix(c, p+" ") {
			return true
		}
	}
	return false
}

// checkSegment checks a single command segment against blocked and allowed lists.
// allowedPatterns is only enforced when non-empty (allowlist model).
func checkSegment(segment string, blockedPatterns, allowedPatterns []string) (blocked bool, reason string) {
	candidates := buildCandidates(segment)

	for _, pattern := range blockedPatterns {
		if matchesPattern(candidates, pattern) {
			return true, fmt.Sprintf("'%s' is blocked.", pattern)
		}
	}

	if len(allowedPatterns) > 0 {
		for _, pattern := range allowedPatterns {
			if matchesPattern(candidates, pattern) {
				return false, ""
			}
		}
		display := strings.Join(strings.Fields(strings.TrimSpace(segment)), " ")
		return true, fmt.Sprintf("'%s' is not in the allowed list.", display)
	}

	return false, ""
}

func isBlocked(command, mode string, policy Policy) (bool, string) {
	rules, hasPolicyRules := policy.Modes[mode]
	blockedPatterns := rules.Blocked
	if !hasPolicyRules || len(blockedPatterns) == 0 {
		// policy.yaml missing or mode not defined — use hardcoded fallback
		blockedPatterns = defaultBlockedFor(mode)
	}
	// allowedPatterns: only enforced when explicitly defined in policy.yaml.
	// Empty = blocklist-only model (no restriction on what else can run).
	allowedPatterns := rules.Allowed

	segments := splitChained(command)
	for _, segment := range segments {
		// Check the segment itself against both blocked and allowed lists.
		if blocked, reason := checkSegment(segment, blockedPatterns, allowedPatterns); blocked {
			return true, fmt.Sprintf("%s (mode: %s)", reason, mode)
		}

		// Check commands embedded in $(...) and `...` against blocked list only.
		// Subshell content isn't the primary command, so allowed list doesn't apply.
		for _, sub := range extractSubshells(segment) {
			if blocked, reason := checkSegment(sub, blockedPatterns, nil); blocked {
				return true, fmt.Sprintf("%s (subshell in: %s, mode: %s)", reason, truncate(segment, 60), mode)
			}
		}
	}
	return false, ""
}

func logEvent(entry LogEntry) {
	_ = os.MkdirAll(configDir(), 0755)
	data, err := json.Marshal(entry)
	if err != nil {
		logError("ERROR", fmt.Sprintf("failed to marshal log entry: %v", err))
		return
	}
	f, err := os.OpenFile(activityLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError("ERROR", fmt.Sprintf("failed to open activity log: %v", err))
		return
	}
	defer f.Close()
	_, _ = f.WriteString(string(data) + "\n")
}

func currentProcess() string {
	// VS Code sets TERM_PROGRAM=vscode in its integrated terminal
	if p := os.Getenv("TERM_PROGRAM"); p != "" {
		if strings.Contains(strings.ToLower(p), "vscode") {
			return "vscode"
		}
		return p
	}
	return fmt.Sprintf("pid:%d", os.Getppid())
}

// ── Core check logic ──────────────────────────────────────────────────────────

func check(command, process, entryType string) int {
	state := loadState()
	policy := loadPolicy()

	user := os.Getenv("USER")
	pid := fmt.Sprintf("%d", os.Getppid())
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.999999")

	if !state.Enabled {
		logEvent(LogEntry{Timestamp: ts, Command: command, Reason: "ShellGuard disabled — pass-through",
			User: user, Process: process, PID: pid, Blocked: false, Type: entryType})
		return 0
	}

	mode := strings.ToLower(strings.TrimSpace(state.Mode))

	if mode == "log only" || mode == "log_only" {
		logEvent(LogEntry{Timestamp: ts, Command: command, Reason: "Logged (log-only mode)",
			User: user, Process: process, PID: pid, Blocked: false, Type: entryType})
		return 0
	}

	// Normalize mode key to match policy.yaml (e.g. "read_only" → "read only")
	modeKey := strings.ReplaceAll(mode, "_", " ")

	blocked, reason := isBlocked(command, modeKey, policy)
	if blocked {
		logEvent(LogEntry{Timestamp: ts, Command: command, Reason: reason,
			User: user, Process: process, PID: pid, Blocked: true, Type: entryType})
		fmt.Fprintf(os.Stderr, "[ShellGuard] Blocked: %s\n", reason)
		return 2 // exit 2 = Claude Code PreToolUse block signal
	}

	logEvent(LogEntry{Timestamp: ts, Command: command, Reason: "Allowed",
		User: user, Process: process, PID: pid, Blocked: false, Type: entryType})
	return 0
}

// ── Modes ─────────────────────────────────────────────────────────────────────

// hookMode: called by any AI tool hook via stdin JSON
func hookMode() {
	raw, _ := io.ReadAll(os.Stdin)

	// Write debug file with restricted permissions — contains sensitive command data.
	// Remove first so permissions are always enforced (WriteFile won't chmod existing files).
	_ = os.MkdirAll(configDir(), 0755)
	debugFile := filepath.Join(configDir(), "last_hook_input.json")
	_ = os.Remove(debugFile)
	_ = os.WriteFile(debugFile, raw, 0600)

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		logError("ERROR", fmt.Sprintf("hook input JSON parse failed: %v — raw: %.200s", err, string(raw)))
		os.Exit(0)
	}

	f, ok := extractHookFields(m)
	if !ok {
		os.Exit(0)
	}
	if f.command == "" {
		logError("WARN", fmt.Sprintf("hook received with empty command: event=%q process=%q raw_keys=%v", str(m["hook_event_name"]), f.process, mapKeys(m)))
		os.Exit(0)
	}

	ts := time.Now().UTC().Format("2006-01-02T15:04:05.999999")
	user := os.Getenv("USER")
	pid := fmt.Sprintf("%d", os.Getppid())

	switch f.eventKind {
	case "post":
		logEvent(LogEntry{Timestamp: ts, Command: f.command, Reason: f.reason,
			User: user, Process: f.process, PID: pid, Blocked: false, Type: "execution"})
		os.Exit(0)
	case "pre":
		os.Exit(check(f.command, f.process, "suggestion"))
	default:
		// Unknown event kind: fail-safe.
		// If the payload has evidence it already ran (tool_response / tool_output),
		// log it as a post-execution event. Otherwise apply the pre-check to avoid
		// silently allowing a command via a crafted hook_event_name.
		_, hasToolResponse := m["tool_response"]
		_, hasToolOutput := m["tool_output"]
		if hasToolResponse || hasToolOutput {
			logEvent(LogEntry{Timestamp: ts, Command: f.command, Reason: f.reason,
				User: user, Process: f.process, PID: pid, Blocked: false, Type: "execution"})
			os.Exit(0)
		}
		logError("WARN", fmt.Sprintf("unknown hook event kind %q from process=%q — applying pre-check", str(m["hook_event_name"]), f.process))
		os.Exit(check(f.command, f.process, "suggestion"))
	}
}

// wrapperMode: used as SHELL replacement — AI tools call: shellguard -c "cmd"
func wrapperMode(args []string) {
	shell, shellFlag := shellBinary()
	if len(args) >= 2 && args[0] == "-c" {
		command := args[1]
		code := check(command, currentProcess(), "execution")
		if code != 0 {
			os.Exit(code)
		}
		cmd := exec.Command(shell, shellFlag, command)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Non -c invocation: pass through to shell
	cmd := exec.Command(shell, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// shellBinary returns the appropriate shell and -c flag for the current OS.
func shellBinary() (string, string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", "/c"
	}
	return "/bin/bash", "-c"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	args := os.Args[1:]

	// shellguard check "some command"
	if len(args) >= 1 && args[0] == "check" {
		command := strings.Join(args[1:], " ")
		code := check(command, "cli", "execution")
		if code == 0 {
			fmt.Printf("[ShellGuard] Allowed: %s\n", command)
		}
		os.Exit(code)
	}

	// Called from Claude Code hook (stdin has JSON, not a tty)
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice == 0 {
		hookMode()
		return
	}

	// Called as shell wrapper
	wrapperMode(args)
}
