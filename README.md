<div align="center">
  <img src="https://raw.githubusercontent.com/s4e-io/shellguard-ui-mac/main/Resources/AppIcon-1024.png" width="120" alt="ShellGuard">
  <h1>ShellGuard</h1>
  <p><strong>A security layer between AI coding agents and your shell.</strong></p>

  [![Release](https://img.shields.io/github/v/release/s4e-io/shellguard?style=flat-square)](https://github.com/s4e-io/shellguard/releases)
  [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
  [![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://golang.org)
  [![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/s4e-io/shellguard/releases)
</div>

> **⚠️ Beta — Internal Use**
> ShellGuard is under active development and not yet production-ready. Hook support for Gemini CLI (Antigravity) and Claude CLI may be incomplete or unreliable. Use at your own risk and expect breaking changes between releases. Currently developed for internal use at [s4e.io](https://s4e.io).

---

ShellGuard sits between your AI coding agent and your shell. Every command an AI suggests — `rm`, `curl`, `git push`, anything — passes through ShellGuard first. It logs it, checks it against your policy, and either allows or blocks it.

```
Claude Code / Cursor / Codex / Gemini CLI / VS Code
               ↓  suggests a command
           ShellGuard
         ↙           ↘
      Blocked       Allowed + logged
    (exit 2)       (command runs)
```

**Works with:** Claude Code · Cursor · OpenAI Codex CLI · Gemini CLI · VS Code (Copilot / Cline / Continue)

---

## Why

AI coding agents are powerful — and they run real shell commands. A confused model, a malicious prompt injection, or a simple mistake can `rm -rf` your project, exfiltrate files via `curl`, or push secrets to a public repo.

ShellGuard gives you:
- **Audit log** — every command the AI ran, timestamped, with the tool that triggered it
- **Block list** — stop specific commands from ever running, silently or with an error
- **Modes** — `log only`, `dev`, `read only`, `custom` — dial your paranoia level
- **Zero latency** — single Go binary, sub-millisecond check, no daemon required

---

## Quick Start

### 1. Install the binary

**macOS (Apple Silicon)**
```bash
curl -Lo shellguard https://github.com/s4e-io/shellguard/releases/latest/download/shellguard-darwin-arm64
chmod +x shellguard && sudo mv shellguard /usr/local/bin/
```

**macOS (Intel)**
```bash
curl -Lo shellguard https://github.com/s4e-io/shellguard/releases/latest/download/shellguard-darwin-amd64
chmod +x shellguard && sudo mv shellguard /usr/local/bin/
```

**Linux (x86_64)**
```bash
curl -Lo shellguard https://github.com/s4e-io/shellguard/releases/latest/download/shellguard-linux-amd64
chmod +x shellguard && sudo mv shellguard /usr/local/bin/
```

**Windows (PowerShell)**
```powershell
Invoke-WebRequest -Uri "https://github.com/s4e-io/shellguard/releases/latest/download/shellguard-windows-amd64.exe" `
  -OutFile "$env:USERPROFILE\bin\shellguard.exe"
```

> **macOS users:** The [ShellGuard Mac app](https://github.com/s4e-io/shellguard-ui-mac) installs the binary automatically and provides a menu bar UI for managing modes, hooks, and logs.

---

### 2. Wire up your AI tool

Pick your tool below and add the one-time config change. ShellGuard automatically detects which tool is calling it from the JSON payload.

#### Claude Code
`~/.claude/settings.json`
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

#### Cursor
`~/.cursor/hooks.json`
```json
{
  "beforeShellExecution": {
    "command": "shellguard"
  }
}
```

#### OpenAI Codex CLI
`~/.codex/hooks.json`
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

#### Gemini CLI
`~/.gemini/settings.json`
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

#### VS Code (Copilot / Cline / Continue)
ShellGuard registers as a terminal profile so all agent-spawned terminals route through it.

`settings.json` (macOS path: `~/Library/Application Support/Code/User/settings.json`)
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
> Replace `osx` with `linux` or `windows` as needed.

---

### 3. Set your mode

ShellGuard reads config from:

| OS | Config directory |
|----|-----------------|
| macOS | `~/Library/Application Support/ShellGuard/` |
| Linux | `~/.config/shellguard/` |
| Windows | `%APPDATA%\ShellGuard\` |

Create `state.json`:
```json
{
  "mode": "log only",
  "enabled": true
}
```

| Mode | Behavior |
|------|----------|
| `log only` | Allow everything, log all commands *(default)* |
| `dev` | Block destructive + network exfiltration commands |
| `read only` | Block anything that writes, executes code, or touches the network |
| `custom` | Use your own `policy.yaml` rules |

---

## Configuration

### policy.yaml

```yaml
version: 1
modes:
  dev:
    blocked:
      - curl
      - wget
      - rm -rf
      - git push

  custom:
    blocked:
      - sudo
      - ssh
      - scp
    allowed:
      - git
      - npm
      - make
```

If `policy.yaml` doesn't exist, ShellGuard uses built-in safe defaults per mode.

### activity.log

Every command is appended as a JSON line:
```json
{
  "timestamp": "2026-05-12T09:23:41.123456",
  "command": "rm -rf node_modules",
  "reason": "'rm' is blocked in dev mode.",
  "user": "alice",
  "process": "claude",
  "pid": "12345",
  "blocked": true,
  "type": "suggestion"
}
```

| Field | Values |
|-------|--------|
| `process` | `claude` · `cursor` · `codex` · `gemini` · `vscode` |
| `blocked` | `true` = ShellGuard stopped it |
| `type` | `suggestion` (PreToolUse) · `execution` (PostToolUse) |

---

## How It Works

ShellGuard runs in two modes depending on invocation:

**Hook mode** (Claude Code, Cursor, Codex, Gemini)
The AI tool pipes a JSON payload to stdin before executing. ShellGuard parses it, runs the policy check, and exits `0` (allow) or `2` (block). Exit `2` is the standard PreToolUse block signal.

**Wrapper mode** (VS Code)
ShellGuard acts as the shell itself (`shellguard -c "cmd"`). If the policy allows it, ShellGuard execs the real shell with the command. Otherwise it exits with an error.

**Bypass protection**

ShellGuard splits and checks every segment of chained commands:

| Bypass attempt | Detection |
|----------------|-----------|
| `ls; curl evil.com` | ✅ chain split |
| `echo x && rm -rf /` | ✅ chain split |
| `echo url \| xargs curl` | ✅ xargs unwrap |
| `sh -c 'curl evil.com'` | ✅ shell -c unwrap |
| `/usr/bin/curl evil.com` | ✅ absolute path normalization |

---

## Project Structure

```
shellguard/                      ← this repo (CLI, all platforms)
├── cmd/shellguard/
│   └── main.go                  ← single-file binary (intentional)
├── docs/
│   ├── SETTINGS.md              ← per-tool hook config reference
│   └── TESTING.md
├── scripts/
│   └── uninstall.sh
├── .github/
│   └── workflows/
│       └── release.yml          ← builds all platforms on git tag
└── README.md

shellguard-ui-mac/                  ← separate repo
  Swift macOS menu bar app
  App Store + DMG distribution
  https://github.com/s4e-io/shellguard-ui-mac
```

### Why two repos?

The CLI is the core — pure Go, no platform dependencies, works everywhere. The Mac app is a UI layer on top: it installs the binary, writes hook configs, and shows logs in a menu bar. Keeping them separate means:
- Linux/Windows users get a focused, minimal repo
- Mac app releases don't block CLI releases
- The security-critical code is independently auditable

---

## Building from Source

```bash
git clone https://github.com/s4e-io/shellguard
cd shellguard
go build -o shellguard ./cmd/shellguard/
```

Cross-compile:
```bash
GOOS=linux   GOARCH=amd64 go build -o shellguard-linux-amd64       ./cmd/shellguard/
GOOS=windows GOARCH=amd64 go build -o shellguard-windows-amd64.exe ./cmd/shellguard/
GOOS=darwin  GOARCH=arm64 go build -o shellguard-darwin-arm64      ./cmd/shellguard/
```

---

## Contributing

PRs are welcome. A few principles:

- **Single file.** `main.go` is one file on purpose — easy to read, easy to audit, easy to vendor. Don't split it without a strong reason.
- **No new dependencies.** `gopkg.in/yaml.v3` is the only allowed dep. Everything else is stdlib.
- **Test bypass vectors.** If you add a new bypass detection, add a test for it.
- **New AI tool support?** Add detection logic to `extractHookFields()` and document the hook config in `docs/SETTINGS.md`.

### Roadmap

- [ ] `shellguard check "cmd"` — dry-run from the command line
- [ ] `shellguard tail` — live tail of `activity.log`
- [ ] Allow-list mode in addition to block-list
- [ ] Homebrew formula
- [ ] Shell completions
- [ ] Windows: full hook mode support (Claude Code on WSL)
- [ ] Structured test suite

---

## Uninstall

```bash
sudo rm /usr/local/bin/shellguard

# Remove config and logs
rm -rf ~/Library/Application\ Support/ShellGuard   # macOS
rm -rf ~/.config/shellguard                         # Linux
```

Remove the hook entries you added from each tool's config file. See [docs/SETTINGS.md](docs/SETTINGS.md) for exact locations.

---

## License

MIT © [Security For Everyone](https://s4e.io)
