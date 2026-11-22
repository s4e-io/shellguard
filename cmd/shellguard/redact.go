package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// ── Redaction ─────────────────────────────────────────────────────────────────
//
// Commands are redacted before they are written anywhere: activity.log,
// last_hook_input.json and the SIEM queue. activity.log is an audit trail, so
// over-masking a value is preferred to keeping a credential in plaintext.

// maxLoggedField caps command/reason bytes in activity.log; it also bounds the
// regex cost on the hook path.
const maxLoggedField = 64 << 10

// defaultRedactors mask common credentials.
// Capture group 1 (when present) is kept; the rest of the match is replaced.
// With three or more groups the last one is kept too.
var defaultRedactors = []*regexp.Regexp{
	// Authorization: Bearer xxx / Basic xxx / Token xxx
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token|digest)\s+)[^\s'"]+`),
	// A bare "Bearer xxx" outside an Authorization header
	regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}`),
	// X-Api-Key: xxx, api_key: xxx
	regexp.MustCompile(`(?i)(\b(?:x-)?api[-_]?key["']?\s*:\s*["']?)[^"'\s,}]+`),
	// SECRET=…, API_KEY=…, DB_PASSWORD="…", export GITHUB_TOKEN=…, SSHPASS=…
	regexp.MustCompile(`(?i)(\b(?:[a-z0-9_]*(?:secret|token|passw(?:or)?d|pwd|api_?key|access_?key|private_?key|credential)[a-z0-9_]*|[a-z0-9_]*(?:pass|pw))\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s;&|]+)`),
	// PROXY_USER='name:secret', CREDS=name:secret
	regexp.MustCompile(`(?i)(\b[a-z0-9_]*(?:user|usr|cred|auth)[a-z0-9_]*\s*=\s*["']?[^:\s'"]+:)[^\s'"@]+`),
	// X='svc_user:secret', X="deploy_bot:secret": the account name gives it away
	regexp.MustCompile(`(?i)(=\s*["'][^:\s'"/]*(?:user|robot|admin|svc|bot)[^:\s'"/]*:)[^\s'"@]+`),
	// "Password: secret" in notes and heredocs
	regexp.MustCompile(`(?i)(\bpass(?:word)?\s*:\s*)(?:"[^"]*"|'[^']*'|[^\s'"\[]\S*)`),
	// Python auth=('user', 'secret')
	regexp.MustCompile(`(?i)(\bauth\s*=\s*\(\s*['"][^'"]*['"]\s*,\s*['"])[^'"]*(['"])`),
	// xfreerdp /p:secret, /pass:secret
	regexp.MustCompile(`(?i)(\s/p(?:ass(?:word)?)?:)(?:"[^"]*"|'[^']*'|\S+)`),
	// "password": "…" inside JSON bodies
	regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api_?key|access_?token|refresh_?token|client_?secret)"\s*:\s*")[^"]*(")`),
	// --password xxx, --token=xxx, --api-key xxx
	regexp.MustCompile(`(?i)(--?(?:password|passwd|pass|token|secret|api-?key|access-?key|client-?secret)(?:=|\s+))(?:"[^"]*"|'[^']*'|\S+)`),
	// sshpass -p xxx
	regexp.MustCompile(`(\bsshpass\b(?:\s+-[a-zA-Z])*\s+-p\s*)(?:"[^"]*"|'[^']*'|\S+)`),
	// curl -u user:pass, curl -U proxyuser:pass, --user / --proxy-user
	regexp.MustCompile(`((?:\s-[uU]\s*|--(?:proxy-)?user[= ])["']?[^:\s'"]+:)(?:"[^"]*"|'[^']*'|[^\s'"@]+)`),
	// mysql -pSecret
	regexp.MustCompile(`(?i)(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&]*?\s-p)\S+`),
	// scheme://user:password@host
	regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)`),
	// Well-known token formats
	regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`),
}

func redact(s string, res []*regexp.Regexp) string {
	for _, re := range res {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			if len(sub) >= 3 {
				return sub[1] + "[REDACTED]" + sub[len(sub)-1]
			}
			if len(sub) == 2 {
				return sub[1] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return redactRandomTokens(s)
}

var tokenRun = regexp.MustCompile(`[A-Za-z0-9_+=-]{24,}`)

// redactRandomTokens masks long standalone strings that mix lower case, upper
// case and digits: generated keys without a known prefix. Hex hashes (lower
// case only), paths and URLs are left alone.
func redactRandomTokens(s string) string {
	idx := tokenRun.FindAllStringIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		if m[0] > 0 && strings.ContainsRune("/.\\", rune(s[m[0]-1])) {
			continue
		}
		if m[1] < len(s) && strings.ContainsRune("/.\\", rune(s[m[1]])) {
			continue
		}
		if !looksRandom(s[m[0]:m[1]]) {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString("[REDACTED]")
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func looksRandom(t string) bool {
	var lower, upper, digits int
	for _, c := range t {
		switch {
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= '0' && c <= '9':
			digits++
		}
	}
	return lower > 0 && upper > 0 && digits >= 2
}

// sanitizeForLog caps and redacts an entry before it is written to activity.log.
func sanitizeForLog(e LogEntry) LogEntry {
	if len(e.Command) > maxLoggedField {
		e.Command = truncateBytes(e.Command, maxLoggedField) + "…[truncated]"
	}
	if len(e.Reason) > maxLoggedField {
		e.Reason = truncateBytes(e.Reason, maxLoggedField) + "…[truncated]"
	}
	e.Command = redact(e.Command, defaultRedactors)
	e.Reason = redact(e.Reason, defaultRedactors)
	return e
}

// ensurePrivate narrows an existing file to owner-only. O_CREATE's mode only
// applies to new files, and older versions (and the Mac app) created 0644.
func ensurePrivate(f *os.File) {
	if runtime.GOOS == "windows" {
		return // ACLs, not mode bits; the profile directory is already per-user
	}
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		_ = f.Chmod(0o600)
	}
}

// redactLogMode rewrites activity.log with every command redacted, for logs
// written before redaction existed: shellguard --redact-log
func redactLogMode() {
	path := activityLogFile()
	in, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ShellGuard] %v\n", err)
		os.Exit(1)
	}
	tmp := path + ".redacting"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		in.Close()
		fmt.Fprintf(os.Stderr, "[ShellGuard] %v\n", err)
		os.Exit(1)
	}
	w := bufio.NewWriterSize(out, 1<<20)
	r := bufio.NewReaderSize(in, 1<<20)
	var lines, changed int
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			lines++
			next, did := redactLogLine(strings.TrimRight(line, "\r\n"))
			if did {
				changed++
			}
			w.WriteString(next + "\n")
		}
		if err != nil {
			break
		}
	}
	in.Close()
	if err := w.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "[ShellGuard] write failed: %v\n", err)
		os.Exit(1)
	}
	out.Close()
	if err := retryFS(func() error { return os.Rename(tmp, path) }); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "[ShellGuard] replace failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[ShellGuard] %s: %d lines, %d redacted.\n", path, lines, changed)
}

// redactLogLine redacts the text fields of one JSONL entry, keeping its other
// fields; a line that is not a JSON object is redacted as plain text. An
// unchanged line is returned as it was.
func redactLogLine(line string) (string, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(line), &m) != nil {
		out := redact(line, defaultRedactors)
		return out, out != line
	}
	changed := false
	for _, k := range []string{"command", "reason"} {
		if v, ok := m[k].(string); ok {
			nv := v
			if len(nv) > maxLoggedField {
				nv = truncateBytes(nv, maxLoggedField) + "…[truncated]"
			}
			nv = redact(nv, defaultRedactors)
			if nv != v {
				m[k] = nv
				changed = true
			}
		}
	}
	if !changed {
		return line, false
	}
	data, err := json.Marshal(m)
	if err != nil {
		out := redact(line, defaultRedactors)
		return out, out != line
	}
	return string(data), true
}
