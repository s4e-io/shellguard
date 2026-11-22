# Windows Testing Guide — Cursor, VS Code, JetBrains

This guide walks through testing ShellGuard end to end with AI tools on a Windows machine. If a step does not behave as described, keep `last_hook_input.json` and `shellguard.log` (their locations are listed below).

All commands are for **PowerShell**.

---

## Quick install: ShellGuardSetup.exe (headless)

Use `ShellGuardSetup-amd64.exe` (Intel/AMD) or `ShellGuardSetup-arm64.exe` (ARM) from the release, or build them with `scripts/build-windows.sh`; `shellguard.exe` is embedded. `$env:PROCESSOR_ARCHITECTURE` tells you which one you need.

The installer always sets the mode to **log only** and writes the hooks of every supported tool: Cursor, VS Code (Copilot), Junie and Claude Code. A hook is written even when the tool is not installed yet; the file does nothing until the tool appears, and takes effect on its first launch. Existing tool settings are kept. Before a file is changed for the first time, a `.shellguard-backup` copy is saved next to it. The installer can be run again; it never adds the same hook twice.

**For the current user** (no Administrator needed; double-clicking also works):

```powershell
.\ShellGuardSetup-amd64.exe
.\ShellGuardSetup-amd64.exe install --siem-host qradar.corp --siem-protocol tls --siem-ca C:\certs\corp-ca.pem --heartbeat
```

- Binary: `%LOCALAPPDATA%\Programs\ShellGuard\shellguard.exe`
- Settings: `%APPDATA%\ShellGuard\` (`state.json`, `siem.yaml`)

**For all users** (enterprise; Administrator PowerShell, also works from Intune / SCCM):

```powershell
.\ShellGuardSetup-amd64.exe install --machine --siem-host qradar.corp
```

- Binary and managed settings: `C:\ProgramData\ShellGuard\`. The directory is made read-only for standard users.
- Because `state.json` lives there, **the mode is pinned**: log only stays in effect even if a user edits their own `state.json`.
- Cursor → `C:\ProgramData\Cursor\hooks.json`
- Claude Code → `C:\Program Files\ClaudeCode\managed-settings.json`. Users cannot change these two files.
- VS Code and Junie have no machine-level hook location. Their hooks are written to every user profile and to the `Default` profile, which is copied into profiles created later.
- Existing per-user ShellGuard hooks are removed; otherwise every command would be logged twice.

**With the MSI (Intune / GPO / SCCM):** `ShellGuard-<version>-x64.msi` performs the same `--machine` install as SYSTEM. It also runs on Windows 11 ARM64 through x64 emulation.

```powershell
msiexec /i ShellGuard-1.1.2-x64.msi /qn /l*v sg-msi.log SIEMHOST=qradar.corp SIEMPROTOCOL=tls
msiexec /i ShellGuard-1.1.2-x64.msi /qn SIEMPROTOCOL=https SIEMFORMAT=hec SIEMURL=https://splunk:8088/services/collector/event SIEMTOKEN=...
msiexec /i ShellGuard-1.1.2-x64.msi /qn CONFIGDIR=\\fileserver\shellguard   # signed state.json / policy.yaml / siem.yaml (+ .sig)
msiexec /x ShellGuard-1.1.2-x64.msi /qn
```

Properties: `SIEMHOST`, `SIEMPORT`, `SIEMPROTOCOL` (tls | tcp | udp | https), `SIEMFORMAT` (leef | cef | json; for https: hec | json), `SIEMURL`, `SIEMTOKEN`, `SIEMCA`, `CONFIGDIR`, `TOOLS`. If a step fails, the install is rolled back and any hooks written are removed. `SIEMTOKEN` is kept out of the MSI log. The exe takes the same options as `--siem-format`, `--siem-url`, `--siem-token` and `--config-dir`.

Other commands:

```powershell
.\ShellGuardSetup-amd64.exe status [--machine]      # shows what is installed
.\ShellGuardSetup-amd64.exe uninstall [--machine]   # removes only ShellGuard entries; activity.log is kept
.\ShellGuardSetup-amd64.exe install --tools cursor,vscode   # only these tools (default: all)
```

After installing, fully quit and reopen Cursor, VS Code and JetBrains IDEs. The tests below use `$exe` and `$SG`:

```powershell
$exe = "$env:LOCALAPPDATA\Programs\ShellGuard\shellguard.exe"   # with --machine: C:\ProgramData\ShellGuard\shellguard.exe
$SG  = "$env:APPDATA\ShellGuard"
```

> To switch to `dev` mode and try blocking, edit `C:\ProgramData\ShellGuard\state.json` (as Administrator) for a `--machine` install, or `$SG\state.json` for a per-user install.

The config examples in section 0 and in the tool sections show the manual setup, for when the installer is not used.

---

## 0. Manual install (alternative)

### Binary

Release files: `shellguard-windows-amd64.exe` (Intel/AMD); `scripts/build-windows.sh` also builds `shellguard-arm64.exe` (ARM, e.g. Surface / Snapdragon). Rename it to `shellguard.exe` when copying. `$env:PROCESSOR_ARCHITECTURE` tells you which one you need (`AMD64` / `ARM64`).

```powershell
New-Item -ItemType Directory -Force C:\Tools\ShellGuard | Out-Null
Copy-Item .\shellguard-windows-amd64.exe C:\Tools\ShellGuard\shellguard.exe
Unblock-File C:\Tools\ShellGuard\shellguard.exe   # removes the "Mark of the Web" from a downloaded file
```

> Keep the path free of spaces (`C:\Tools\...`). Cursor runs hooks through PowerShell and Junie through `cmd /c`; a path with spaces causes quoting problems in both.
> The binary is not code-signed, so SmartScreen or Defender may warn on first run.

> ⚠️ Do not run `shellguard.exe` **without arguments and without a pipe**: it enters wrapper mode and opens an interactive `cmd.exe`. Hook tests always use `... | shellguard.exe`.

### Config directory

`%APPDATA%\ShellGuard\` (e.g. `C:\Users\alice\AppData\Roaming\ShellGuard\`).

```powershell
$SG = "$env:APPDATA\ShellGuard"
New-Item -ItemType Directory -Force $SG | Out-Null
'{"mode":"log only","enabled":true}' | Set-Content -Encoding ascii "$SG\state.json"
```

To see blocking as well, switch the mode to `dev` (`curl`, `ssh`, `git push`, `rm -rf` … are blocked):

```powershell
'{"mode":"dev","enabled":true}' | Set-Content -Encoding ascii "$SG\state.json"
```

### Smoke test (no AI tool needed)

```powershell
$exe = "C:\Tools\ShellGuard\shellguard.exe"
'{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"t","tool_input":{"command":"curl https://example.com"}}' | & $exe; "exit: $LASTEXITCODE"
Get-Content "$SG\activity.log" -Tail 1
```

Expected: `exit: 0` in `log only` mode; `[ShellGuard] Blocked: 'curl' is blocked.` and `exit: 2` in `dev` mode. Either way a line is appended to `activity.log`.

### Fake SIEM (when there is no QRadar)

In a separate PowerShell window, a listener that prints incoming syslog lines:

```powershell
$l = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 5514); $l.Start(); "listening: 127.0.0.1:5514"
while ($true) { $c = $l.AcceptTcpClient(); $r = [IO.StreamReader]::new($c.GetStream()); while ($null -ne ($line = $r.ReadLine())) { $line }; $c.Close() }
```

`siem.yaml` (user level):

```powershell
@"
enabled: true
host: 127.0.0.1
port: 5514
protocol: tcp
"@ | Set-Content -Encoding ascii "$SG\siem.yaml"
```

For a real QRadar, set `host` to the QRadar address and prefer `protocol: tls` with `ca_file`. To try the managed (enterprise) config, create the same file as `C:\ProgramData\ShellGuard\siem.yaml` in an **Administrator PowerShell**; when present it overrides the user's file.

Run the smoke test again → a `LEEF:1.0|S4E|ShellGuard|...` line should appear in the listener window within a few seconds (sending happens in the background).

---

## 1. Cursor

Cursor's current hook format (`version: 1`). User-level file: `%USERPROFILE%\.cursor\hooks.json`

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "C:/Tools/ShellGuard/shellguard.exe" }],
    "afterShellExecution":  [{ "command": "C:/Tools/ShellGuard/shellguard.exe" }]
  }
}
```

- For enterprise deployment, the same content goes in `C:\ProgramData\Cursor\hooks.json` (users cannot remove it).
- Fully quit and reopen Cursor.
- ShellGuard answers Cursor with `{"permission":"allow"|"deny"}` JSON and exits `2` when blocking. On Windows it strips the UTF-8 BOM Cursor puts in front of the payload.

**Test:**
1. In `log only` mode, ask the Agent: *"Run `dir` in the terminal"* → two lines with `"process":"cursor"` in `activity.log` (`suggestion` + `execution`).
2. In `dev` mode: *"Run `curl https://example.com`"* → Cursor should not run the command and should show the "[ShellGuard] Blocked" message.

**Known issue:** the Cursor forum reports that the **Cursor CLI** on Windows does not run user-level hooks in interactive sessions. Test with the desktop app.

---

## 2. VS Code (GitHub Copilot agent)

> The "terminal profile" approach from older docs **does not work**: VS Code starts ShellGuard without arguments, and ShellGuard then opens an interactive shell without checking anything. Use Copilot's agent hooks instead (a **Preview** feature in VS Code).

User-level file: `%USERPROFILE%\.copilot\hooks\shellguard.json`

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse":  [{ "type": "command", "command": "C:/Tools/ShellGuard/shellguard.exe --source vscode", "timeoutSec": 10 }],
    "PostToolUse": [{ "type": "command", "command": "C:/Tools/ShellGuard/shellguard.exe --source vscode", "timeoutSec": 10 }]
  }
}
```

- Write event names in **PascalCase** (`PreToolUse`): this selects the `hook_event_name` / `tool_name` / `tool_input` payload ShellGuard understands. camelCase (`preToolUse`) sends a different payload.
- `--source vscode`: Copilot also sends `session_id`, so without it events would be labelled `claude`.
- Repository-level `.github/hooks/*.json` also works; VS Code additionally reads the repository's `.claude/settings.json`.
- Enterprise: `C:\ProgramData\GitHub\Copilot\policy.d\*.json` (policy hooks).
- Turn on `chat.useHooks` if your VS Code has it, and pick agent mode in Copilot chat.

**Test:** the same two steps as for Cursor; expect `"process":"vscode"` in `activity.log`.

**Open question:** the name of VS Code's terminal tool in the payload is not clearly documented. ShellGuard accepts `bash`, `powershell`, `run_in_terminal` and `runInTerminal`, and ignores other tools (file reads etc.). If the agent runs commands but `activity.log` stays empty, check `tool_name` in `%APPDATA%\ShellGuard\last_hook_input.json` and open an issue with it.

---

## 3. JetBrains (IntelliJ, PyCharm, Rider …)

JetBrains' in-IDE **AI Assistant / Junie plugin has no documented hook mechanism**, so ShellGuard **cannot see** commands run by the IDE plugin. These paths work in JetBrains:

### a) Junie CLI

`%USERPROFILE%\.junie\config.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "C:/Tools/ShellGuard/shellguard.exe --source junie" }] }
    ]
  }
}
```

On Windows, Junie runs the hook with `cmd /c` and treats `exit 2` as a block. Junie's docs have no PostToolUse event, so only the before-execution record is written. Hooks in a project's `.junie/config.json` are ignored by default; use the user-level file.

### b) Claude Code inside JetBrains

Claude Code (IDE plugin or the IDE terminal) uses the hooks in `%USERPROFILE%\.claude\settings.json`. The exec form (`"args": []`) starts the binary without a shell, so it works with Git Bash and with PowerShell:

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "Bash|PowerShell", "hooks": [{ "type": "command", "command": "C:/Tools/ShellGuard/shellguard.exe", "args": [] }] }],
    "PostToolUse": [{ "matcher": "Bash|PowerShell", "hooks": [{ "type": "command", "command": "C:/Tools/ShellGuard/shellguard.exe", "args": [] }] }]
  }
}
```

**Test:** have Junie CLI or Claude Code run `dir` and (in dev mode) `curl https://example.com`; expect `junie` / `claude` lines in `activity.log` and a block for curl.

---

## 4. SIEM queue and heartbeat

1. **Stop** the fake SIEM listener (Ctrl+C). Have the agent run a few commands.
   - Commands should run without delay (the hook never waits on the network).
   - Events accumulate in `"$SG\siem_queue.log"` (or `siem_queue.sending`).
2. Start the listener again, then:
   ```powershell
   & C:\Tools\ShellGuard\shellguard.exe --send
   ```
   The queued events should reach the listener in order, followed by a `Heartbeat` line. Run with the listener stopped, it should exit `1` with a "still queued" message.
3. Automatic drain: **60 seconds** (the retry interval) after the listener is back, have the agent run a new command → the queued events should go out on their own.
4. Scheduled heartbeat (every 5 minutes, as the user):
   ```powershell
   schtasks /Create /SC MINUTE /MO 5 /TN "ShellGuard SIEM" /TR "C:\Tools\ShellGuard\shellguard.exe --send"
   ```
   Note: this task may flash a console window each time it runs.

---

## 5. Troubleshooting

| File | Purpose |
|---|---|
| `%APPDATA%\ShellGuard\activity.log` | Every command — the main result |
| `%APPDATA%\ShellGuard\last_hook_input.json` | The raw payload the tool sent last — the first place to look for format problems |
| `%APPDATA%\ShellGuard\shellguard.log` | Errors and warnings (JSON parse errors, SIEM connection errors, queue full …) |
| `%APPDATA%\ShellGuard\siem_queue.log` / `.sending` | SIEM events waiting to be sent |

- **`activity.log` is never created:** the hook is not being called. Check the location of the tool's config file and that it is valid JSON, then fully restart the tool.
- **`last_hook_input.json` exists but `activity.log` is empty:** the payload was not recognised or the tool name was filtered out; include that file in your issue.
- **Commands are not blocked (in `dev` mode):** check that `state.json` really says `dev`, and read the `reason` field in `activity.log`.
- **Nothing reaches the SIEM:** look at `shellguard.log`; the output of `shellguard.exe --send` then shows the error directly.
- **"Access is denied" or a long hang when starting the installer:** Microsoft Defender or SmartScreen is blocking the unsigned exe. Run `Unblock-File` on it, and check Protection history in Windows Security.
