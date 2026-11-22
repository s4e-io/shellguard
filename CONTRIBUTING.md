# Contributing to ShellGuard

Thanks for your interest. ShellGuard is intentionally minimal — a single Go binary with no daemon, no dependencies beyond `yaml.v3` and `golang.org/x/sys`, and a policy check that fits in one file. Keep that spirit in mind.

## Getting started

```bash
git clone https://github.com/s4e-io/shellguard
cd shellguard
go build ./cmd/shellguard/
go test ./...
```

## What we want

| Type | Notes |
|------|-------|
| **New AI tool support** | Add detection to `extractHookFields()` in `main.go` + hook config docs in `docs/SETTINGS.md` |
| **New bypass vector** | Add detection in `isBlocked()` / `splitChained()` / `unwrap*` + a test |
| **Bug fixes** | Always welcome, include a reproduction case |
| **Platform fixes** | Windows and Linux improvements especially needed |

## What we don't want

- Splitting the policy check in `cmd/shellguard/main.go` into packages (defeats the "read it in one sitting" goal)
- New dependencies (keep it stdlib + yaml + x/sys)
- Daemon / background service architecture
- GUI code in this repo (that lives in [shellguard-ui-mac](https://github.com/s4e-io/shellguard-ui-mac))

## Code style

- Standard `gofmt` formatting
- Comment every non-obvious decision
- Error messages start with `[ShellGuard]`
- All log writes go through `logError()` or `logEvent()` — never `fmt.Println` to stderr from library code

## Testing a new tool integration

1. Find the tool's hook documentation
2. Capture a real hook payload: `shellguard` writes the last received payload to `last_hook_input.json` in the config dir
3. Add detection in `extractHookFields()` using the unique field the tool sends
4. Test with `shellguard check "rm -rf /"` after wiring up the hook

## Submitting

- One PR per concern
- Describe *why*, not just *what*
- If it's a security fix, mention it clearly in the PR title

## Questions

Open an issue or email [hello@s4e.io](mailto:hello@s4e.io).
