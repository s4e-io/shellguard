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
`curl` · `wget` · `nc` · `ncat` · `nmap` · `ssh` · `scp` · `sftp` · `rsync` · `telnet` · `ftp` · `sudo` · `su` · `doas` · `rm -r` / `rm -rf` (any flag order) · `shred` · `dd` · `chmod` · `chown` · `chgrp` · `git push` · `git reset` · `git clean` · `osascript` · `launchctl` · `crontab` · `killall` · `pkill`

### `read only`
Strict. Blocks anything that writes files, runs code, or touches the network.

Default blocked in `read only` mode:
`rm` · `rmdir` · `mv` · `cp` · `touch` · `mkdir` · `ln` · `shred` · `dd` · `install` · `truncate` · `tee` · `sudo` · `su` · `doas` · `chmod` · `chown` · `chgrp` · `curl` · `wget` · `nc` · `ncat` · `nmap` · `ssh` · `scp` · `sftp` · `rsync` · `telnet` · `ftp` · `git push` · `git add` · `git commit` · `git reset` · `git clean` · `git rm` · `git stash` · `git tag` · `git merge` · `git rebase` · `npm` · `npx` · `yarn` · `pnpm` · `pip` · `pip3` · `python` · `python3` · `node` · `ruby` · `java` · `go run` · `sed` · `perl` · `awk` · `osascript` · `launchctl` · `crontab` · `at` · `kill` · `killall` · `pkill` · `open`

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

## siem.yaml

Optional. Forwards every `activity.log` event to a SIEM: syslog with LEEF (QRadar), CEF (Sentinel, ArcSight) or JSON, or HTTPS to Splunk HEC or any JSON endpoint. If the file is absent or `enabled: false`, nothing is sent.

```yaml
enabled: true
host: qradar.example.com
protocol: tls            # tls (recommended) | tcp | udp
port: 6514               # default: 6514 for tls, 514 for tcp/udp
ca_file: /etc/ssl/certs/corp-ca.pem   # trust anchor for the SIEM's certificate
# cert_file / key_file:  client certificate, if the receiver requires mTLS
format: leef             # leef (QRadar native) | cef (Sentinel, ArcSight) | json
timeout_ms: 3000         # connect / write timeout (100–30000)
retry_after_seconds: 60  # after a failure, don't retry for this long
linger_seconds: 5        # background sender waits this long for more events (1–60)
max_queue_mb: 50         # stop queuing (and count drops) above this
max_message_bytes: 4096  # QRadar's default max syslog payload; longer commands are truncated
redact: true             # mask credentials in commands (default on)
redact_patterns:         # extra regexes; group 1, if any, is kept
  - 'internal-key-[A-Za-z0-9]+'
tls_skip_verify: false
```

Over HTTPS (Splunk HTTP Event Collector, or any endpoint that takes JSON):

```yaml
enabled: true
protocol: https
url: https://splunk.example.com:8088/services/collector/event
format: hec              # hec: Splunk envelopes, "Authorization: Splunk <token>"
                         # json: one JSON object per line, "Authorization: Bearer <token>"
token: 0b2c…             # ingestion-only token; readable by every user on the machine
ca_file: /etc/ssl/certs/corp-ca.pem   # ca_file / cert_file / key_file / tls_skip_verify apply here too
```

Each batch is one POST; any 2xx counts as delivered, anything else is retried later. `max_message_bytes` defaults to 16 KB per event over HTTPS. The system proxy (`HTTPS_PROXY`) is honoured.

### Managed (enterprise) config

A machine-wide `siem.yaml`, `state.json` or `policy.yaml` overrides the per-user one, so the user's own copy cannot switch forwarding off or change the mode. When `state.json` is managed, `policy.yaml` is only read from the managed directory too. Install the files admin-owned and world-readable (`0644`); an unreadable or invalid managed `siem.yaml` disables forwarding and logs an error to `shellguard.log`.

| OS | Managed path |
|----|------|
| macOS | `/Library/Application Support/ShellGuard/siem.yaml` |
| Linux | `/etc/shellguard/siem.yaml` |
| Windows | `C:\ProgramData\ShellGuard\siem.yaml` (resolved via the Known Folder API, not `%ProgramData%`) |

### Signed config (strict builds)

A customer build can embed an Ed25519 public key. That build reads **only** the managed files, and each one needs a valid detached signature next to it (`state.json.sig`, `policy.yaml.sig`, `siem.yaml.sig`). Use this when the config is distributed through a channel you don't fully trust (a file share, an MDM payload), or to make an edited file fail loudly instead of silently taking effect.

```bash
go run ./cmd/shellguard-sign keygen policy.key          # once; prints the public key. Keep policy.key offline.
POLICY_PUBKEY=<public key> ./scripts/build-windows.sh   # or: go build -ldflags "-X main.policyPublicKey=<key>"
go run ./cmd/shellguard-sign sign policy.key state.json policy.yaml siem.yaml
go run ./cmd/shellguard-sign verify <public key> state.json
```

When a signature is missing or wrong, the file is rejected: the mode falls back to `log only`, rules to the mode defaults, and SIEM forwarding is turned off (if `siem.yaml` is the file rejected). A `PolicyRejected` event (at most one an hour) goes to the SIEM, and the reason to `shellguard.log`.

Limits: the signature proves who wrote a file, not that it is the latest one — an administrator could put back an older signed file. Anyone who can write the managed directory is already an administrator; the per-user files are what strict builds really shut out.

### How delivery works

1. The hook appends the event to `siem_queue.log` in the per-user config directory and returns. **The hook never touches the network**; the only extra cost is starting a background process when none is running (a few ms).
2. A detached `shellguard --send --quiet` ships the queue in order, checkpoints progress after every batch (`siem_queue.offset`), and stays up for `linger_seconds` so a burst of agent commands uses a single sender. Only one sender runs at a time (OS file lock; released automatically if the process dies).
3. If the SIEM is unreachable, events stay queued and hooks stop starting senders for `retry_after_seconds`. The first hook after that window starts a new attempt.

Guarantees and limits — read these before relying on it:

- **Best effort, not guaranteed delivery.** Syslog has no application-level acknowledgement. Connection resets are detected and retried, but a receiver that accepts data and then discards it cannot be detected.
- **Possible duplicates.** A sender that crashes or loses the connection mid-batch resends that batch (at most 200 events).
- **Queue full.** Above `max_queue_mb`, new events are not queued (they are still in `activity.log`). The number dropped is reported to the SIEM as an `EventsDropped` event once delivery recovers.
- **Redaction is pattern-based.** It catches common forms (`Authorization:` headers, `*_TOKEN=`/`*PASSWORD=`, `--password x`, `mysql -p…`, `user:pass@` URLs, GitHub/GitLab/Slack/OpenAI/AWS/Google key formats), not every secret. Commands are truncated to 16 KB before redaction. `activity.log` gets the same default redaction (see below); `redact_patterns` and `redact: false` apply only to what is sent to the SIEM.
- **Use `tls`.** Over `tcp`/`udp`, commands travel in plaintext; ShellGuard logs a daily warning to `shellguard.log` when this targets a non-loopback host. Over `udp`, an unreachable SIEM usually goes undetected and events are lost.

### Tamper resistance — what it does and doesn't cover

ShellGuard runs as the user, so anything running as that user — including an AI agent — can delete the queue, remove the hooks from the agent's settings, or kill the sender. The managed config only stops the user's own `siem.yaml` from disabling forwarding. Tampered state files (e.g. a future `last_failure`, a leftover lock file) are ignored.

To *detect* tampering, schedule `shellguard --send` as each user. It drains the queue and then sends a `Heartbeat` event (`queued=… dropped=…`). Alert in QRadar when a host stops sending heartbeats, or when `EventsDropped` appears.

```
# macOS / Linux, per user (crontab -e)
*/5 * * * * /usr/local/bin/shellguard --send >/dev/null 2>&1
```
```
:: Windows, per user
schtasks /Create /SC MINUTE /MO 5 /TN "ShellGuard SIEM" /TR "\"C:\Program Files\ShellGuard\shellguard.exe\" --send"
```

`shellguard --send` exits `1` if the SIEM is unreachable (unsent events stay queued) and prints how many events were sent.

### QRadar event format

RFC 3164 syslog lines (`<PRI>timestamp hostname ShellGuard: …`) with a LEEF 1.0 payload:

```
LEEF:1.0|S4E|ShellGuard|1.1.2|CommandBlocked|devTime=2026-05-12T09:23:41.123+0000	devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ	cat=suggestion	sev=7	action=blocked	usrName=alice	process=claude	pid=12345	command=curl evil.com	reason='curl' is blocked. (mode: dev)
```

| Event ID | When | `sev` | Syslog severity |
|----------|------|-------|-----------------|
| `CommandBlocked` | ShellGuard stopped the command | 7 | warning |
| `CommandAllowed` | pre-execution check passed | 3 | informational |
| `CommandExecuted` | post-execution event | 3 | informational |
| `EventsDropped` | queue was full; `reason` has the count | 8 | warning |
| `Heartbeat` | `shellguard --send` ran; `reason` has queue depth | 1 | informational |

The same events in CEF (`format: cef`):

```
CEF:0|S4E|ShellGuard|1.1.2|CommandBlocked|Command blocked|7|rt=1778577821123 dvchost=ws-042 act=blocked cat=suggestion suser=alice sproc=claude spid=12345 cs1Label=command cs1=curl evil.com msg='curl' is blocked. (mode: dev)
```

JSON and HEC events carry the `activity.log` fields plus `event_id` and `host`. `PolicyRejected` (severity 9, syslog warning) is sent when a strict build rejects a managed file.

`usrName` is the OS account (not `$USER`, which is unset on Windows and easy to spoof). Control characters in values are replaced with spaces. In QRadar, add a log source of type *Universal LEEF* (or let auto-discovery pick up the `S4E|ShellGuard` header).

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
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "shellguard" }],
    "afterShellExecution":  [{ "command": "shellguard" }]
  }
}
```

ShellGuard answers with `{"permission":"allow"}` / `{"permission":"deny", ...}` on stdout and exits `2` when blocking. Managed (MDM) locations that users cannot override: `/Library/Application Support/Cursor/hooks.json` (macOS), `/etc/cursor/hooks.json` (Linux), `C:\ProgramData\Cursor\hooks.json` (Windows). On Windows, Cursor runs hooks through PowerShell and prefixes the payload with a UTF-8 BOM, which ShellGuard strips.

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

### VS Code (GitHub Copilot agent) — `~/.copilot/hooks/shellguard.json`

Copilot agent hooks (Preview in VS Code). Use PascalCase event names so the payload uses `hook_event_name` / `tool_name` / `tool_input`:

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse":  [{ "type": "command", "command": "shellguard --source vscode", "timeoutSec": 10 }],
    "PostToolUse": [{ "type": "command", "command": "shellguard --source vscode", "timeoutSec": 10 }]
  }
}
```

Also read from `.github/hooks/*.json` in the repository; managed policy hooks live in `C:\ProgramData\GitHub\Copilot\policy.d\` on Windows. `--source` labels the events, since Copilot's payload is otherwise indistinguishable from Claude Code's.

> The earlier "terminal profile" approach (`terminal.integrated.profiles.*` pointing at ShellGuard) does not work: VS Code starts the profile without `-c`, and ShellGuard then just opens an interactive shell without checking or logging anything.

### Junie CLI (JetBrains) — `~/.junie/config.json`

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "shellguard --source junie" }] }
    ]
  }
}
```

Exit code `2` blocks. Project-level `.junie/config.json` hooks are ignored by default. The Junie / AI Assistant plugins inside JetBrains IDEs have no documented hook mechanism, so their commands are not seen by ShellGuard; use Junie CLI or Claude Code there.

### `--source <name>`

Any hook command may add `--source <name>` to set the `process` field explicitly, overriding auto-detection.

Step-by-step Windows testing for Cursor, VS Code and JetBrains: [WINDOWS_TESTING.md](WINDOWS_TESTING.md).

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
| `command` | The command string, with credentials masked (see below) |
| `reason` | Human-readable allow/block reason |
| `process` | `claude` · `cursor` · `codex` · `gemini` · `vscode` · `cli` |
| `blocked` | `true` = ShellGuard prevented execution |
| `type` | `suggestion` (pre-execution) · `execution` (post-execution) |

**Credentials are masked before writing.** The policy check sees the real command; what is stored in `activity.log`, `last_hook_input.json` and the SIEM queue has passwords, tokens and keys replaced with `[REDACTED]`. Covered forms include `Authorization:`/`Bearer` values, `*_TOKEN=` / `*PASSWORD=` / `*PASS=` / `*PW=` variables, `--password x`, `sshpass -p x`, `curl -u`/`-U user:pass`, `mysql -p…`, `user:pass@` URLs, `"password": "…"` in JSON bodies, Python `auth=('user','pass')`, `xfreerdp /p:`, `Password: x` lines, known token formats (GitHub, GitLab, Slack, OpenAI, AWS, Google, JWT) and long random strings that mix upper case, lower case and digits. A password typed as a bare word (for example `grep hunter2 file`) cannot be recognised. Commands longer than 64 KB are truncated.

**Permissions.** `activity.log` is owner-only (`0600`) on macOS and Linux; a file created with wider permissions by an older version is narrowed on the next write.

**Logs written before 1.1.1** still hold plaintext credentials. Mask them in place, with AI tools idle (events written during the rewrite can be lost):

```bash
shellguard --redact-log
```

It rewrites the file line by line (about 40 s for 100,000 lines) and prints how many lines changed. Fields other than `command` and `reason` are kept.

Parse with `jq`:
```bash
# Show all blocked commands
cat activity.log | jq 'select(.blocked == true)'

# Count by tool
cat activity.log | jq -r '.process' | sort | uniq -c

# Last 20 commands
tail -20 activity.log | jq .
```
