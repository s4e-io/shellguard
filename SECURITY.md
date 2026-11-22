# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. If that is not available to you, email hello@s4e.io with "ShellGuard security" in the subject.

Include the ShellGuard release you use, your OS, the AI tool involved, and a command or payload that reproduces the issue. Please do not open a public issue for a bypass until a fix is released.

## What ShellGuard is, and is not

ShellGuard is an audit log and a guardrail for commands that AI coding tools run. It is not a sandbox. Keep these limits in mind when you rely on it:

- **Block lists are pattern-based.** Commands are split on `;`, `&&`, `||`, `|`, `&` and newlines, normalised and matched against the mode's patterns. Obfuscation such as quote splitting (`c''url`), `$'…'` strings, multi-call binaries (`busybox wget`) or an interpreter (`python -c`, `perl -e`) in `dev` mode can get past a block list. For enforcement, use `read only` mode or a `custom` policy with an `allowed` list.
- **It fails open.** A hook payload that is not valid JSON, a tool ShellGuard does not recognise, and an empty command are allowed, so a broken integration never stops a developer. Every allowed command is still logged when it can be parsed.
- **Per-user config can be edited by the agent.** In a default build, an agent running as the user can change the user's `state.json` or `policy.yaml`. Use the managed config directory (see [docs/SETTINGS.md](docs/SETTINGS.md)), and a strict build with signed config where tampering matters.
- **Redaction is pattern-based.** Common credential forms are masked before anything is written or sent, but an unusual format can slip through. See [docs/SETTINGS.md](docs/SETTINGS.md) for the covered forms.
- **Release binaries are not code-signed yet.** Check them against `checksums.txt` from the release.
