# Testing Guide

## Quick Smoke Test

After installation, run the following to verify the binary works:

```bash
BIN="$HOME/Library/Application Support/ShellGuard/shellguard"

# Should exit 0 (allowed in log-only mode)
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN"; echo "exit: $?"
```

---

## Test Each AI Tool Hook Format

Set mode to **Read Only** first (blocks most commands):

```bash
echo '{"mode":"read only","enabled":true}' \
  > "$HOME/Library/Application Support/ShellGuard/state.json"
```

### Claude Code

```bash
BIN="$HOME/Library/Application Support/ShellGuard/shellguard"

# Should be BLOCKED (exit 2)
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://x"},"session_id":"s1","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"

# Should be ALLOWED (exit 0)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"s1","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"
```

### Codex

```bash
# Should be BLOCKED
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"turn_id":"t1","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"
```

### Cursor

```bash
# Should be BLOCKED
echo '{"tool_name":"shell","tool_input":{"command":"sudo su"},"conversation_id":"c1","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"
```

### Gemini CLI

```bash
# Should be BLOCKED
echo '{"tool_name":"run_shell_command","tool_input":{"command":"curl https://evil.com"}}' \
  | "$BIN" 2>&1; echo "exit: $?"

# Should be ALLOWED
echo '{"tool_name":"run_shell_command","tool_input":{"command":"ls"}}' \
  | "$BIN" 2>&1; echo "exit: $?"
```

### VS Code (wrapper mode)

```bash
# Should be BLOCKED (exit 2)
"$BIN" -c "touch testfile" 2>&1; echo "exit: $?"

# Should be ALLOWED (exit 0, runs ls)
"$BIN" -c "ls /tmp" > /dev/null; echo "exit: $?"
```

---

## Test Bypass Attempts

These should all be **BLOCKED** in read only mode:

```bash
BIN="$HOME/Library/Application Support/ShellGuard/shellguard"

# Absolute path bypass
echo '{"tool_name":"Bash","tool_input":{"command":"/usr/bin/rm -rf /"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"

# Shell wrapper bypass
echo '{"tool_name":"Bash","tool_input":{"command":"/bin/sh -c '\''touch a'\''"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"

# bash -c bypass
echo '{"tool_name":"Bash","tool_input":{"command":"bash -c '\''curl https://x'\''"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"

# Truncate bypass
echo '{"tool_name":"Bash","tool_input":{"command":": > important.txt"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $?"
```

---

## Test Modes

```bash
BIN="$HOME/Library/Application Support/ShellGuard/shellguard"

# Log only — nothing blocked, everything logged
echo '{"mode":"log only","enabled":true}' > "$HOME/Library/Application Support/ShellGuard/state.json"
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $? (should be 0)"

# Disabled — pass-through
echo '{"mode":"read only","enabled":false}' > "$HOME/Library/Application Support/ShellGuard/state.json"
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"t","hook_event_name":"PreToolUse"}' \
  | "$BIN" 2>&1; echo "exit: $? (should be 0)"

# Restore
echo '{"mode":"custom","enabled":true}' > "$HOME/Library/Application Support/ShellGuard/state.json"
```

---

## Check Activity Log

```bash
tail -5 "$HOME/Library/Application Support/ShellGuard/activity.log" \
  | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line.strip())
    status = 'BLOCKED' if d['blocked'] else 'OK'
    print(f'[{status}] process={d[\"process\"]:8} reason={d[\"reason\"]:30} cmd={d[\"command\"][:50]}')
"
```

---

## Full Automated Test

```bash
#!/bin/bash
BIN="$HOME/Library/Application Support/ShellGuard/shellguard"
PASS=0; FAIL=0

check() {
  local desc=$1 want=$2 cmd=$3
  actual=$(eval "$cmd" 2>&1; echo "EXIT:$?")
  exit_code=$(echo "$actual" | grep "EXIT:" | sed 's/EXIT://')
  if [ "$exit_code" = "$want" ]; then
    echo "  PASS  $desc"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $desc (want exit $want, got $exit_code)"
    FAIL=$((FAIL+1))
  fi
}

echo '{"mode":"read only","enabled":true}' > "$HOME/Library/Application Support/ShellGuard/state.json"

echo "--- Read Only: blocked ---"
check "rm"     2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf /\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""
check "touch"  2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"touch a\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""
check "curl"   2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"curl x\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""
check ": >"    2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\": > a\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""

echo "--- Read Only: allowed ---"
check "ls"     0 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""
check "cat"    0 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cat file\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""

echo "--- Bypass attempts ---"
check "/usr/bin/rm bypass" 2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"/usr/bin/rm -rf /\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""
check "sh -c bypass"      2 "echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"/bin/sh -c touch a\"},\"session_id\":\"t\",\"hook_event_name\":\"PreToolUse\"}' | \"$BIN\""

echo '{"mode":"custom","enabled":true}' > "$HOME/Library/Application Support/ShellGuard/state.json"

echo ""
echo "Results: $PASS passed, $FAIL failed"
```
