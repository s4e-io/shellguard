#!/bin/bash
# Shell Guard Uninstaller
# Removes the app, CLI binary, and all AI tool hooks.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  !${NC} $1"; }
info() { echo "  → $1"; }

echo ""
echo ">_! Shell Guard Uninstaller"
echo "─────────────────────────────────────────"
echo ""

# ── 1. Kill running app ────────────────────────────────────────────────────────

if pgrep -x ShellGuardUIApp > /dev/null 2>&1; then
    info "Stopping Shell Guard..."
    pkill -x ShellGuardUIApp && ok "App stopped" || warn "Could not stop app"
fi

# ── 2. Remove app bundle ───────────────────────────────────────────────────────

APP_PATH="/Applications/ShellGuard.app"
if [ -d "$APP_PATH" ]; then
    info "Removing $APP_PATH..."
    rm -rf "$APP_PATH" && ok "App removed"
else
    warn "App not found at $APP_PATH (skipping)"
fi

# ── 3. Remove CLI binary ───────────────────────────────────────────────────────

CLI_PATH="$HOME/Library/Application Support/ShellGuard/shellguard"
if [ -f "$CLI_PATH" ]; then
    info "Removing CLI binary at $CLI_PATH..."
    rm -f "$CLI_PATH" && ok "CLI binary removed"
else
    warn "CLI binary not found at $CLI_PATH (skipping)"
fi

# ── 4. Remove hooks from AI tools ─────────────────────────────────────────────

info "Removing hooks from AI tool configs..."

python3 - <<'PYEOF'
import json, os, sys

home = os.path.expanduser("~")

def patch_json(path, patcher):
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            data = json.load(f)
        patched = patcher(data)
        with open(path, "w") as f:
            json.dump(patched, f, indent=2)
        return True
    except Exception as e:
        print(f"  ! Could not patch {path}: {e}", file=sys.stderr)
        return False

def is_shellguard(cmd):
    return isinstance(cmd, str) and "shellguard" in cmd

def remove_shellguard_from_array(arr):
    """Remove entries whose hooks[] contain a shellguard command."""
    if not isinstance(arr, list):
        return arr
    return [
        e for e in arr
        if not any(is_shellguard(h.get("command", ""))
                   for h in (e.get("hooks") or []))
    ]

# ── Claude Code: ~/.claude/settings.json ──────────────────────────────────────
claude_path = os.path.join(home, ".claude", "settings.json")
def patch_claude(data):
    hooks = data.get("hooks", {})
    for event in list(hooks.keys()):
        hooks[event] = remove_shellguard_from_array(hooks[event])
    data["hooks"] = hooks
    return data

if patch_json(claude_path, patch_claude):
    print("  ✓ Claude Code hooks cleaned")
else:
    print("  ! ~/.claude/settings.json not found (skipping)")

# ── Cursor: ~/.cursor/hooks.json ──────────────────────────────────────────────
cursor_path = os.path.join(home, ".cursor", "hooks.json")
def patch_cursor(data):
    bse = data.get("beforeShellExecution", {})
    if is_shellguard(bse.get("command", "")):
        del data["beforeShellExecution"]
    return data

if patch_json(cursor_path, patch_cursor):
    print("  ✓ Cursor hooks cleaned")
else:
    print("  ! ~/.cursor/hooks.json not found (skipping)")

# ── Codex: ~/.codex/hooks.json ────────────────────────────────────────────────
codex_path = os.path.join(home, ".codex", "hooks.json")
def patch_codex(data):
    outer = data.get("hooks", {})
    for event in list(outer.keys()):
        outer[event] = remove_shellguard_from_array(outer[event])
    data["hooks"] = outer
    return data

if patch_json(codex_path, patch_codex):
    print("  ✓ Codex hooks cleaned")
else:
    print("  ! ~/.codex/hooks.json not found (skipping)")

# ── Gemini / Antigravity: ~/.gemini/settings.json ────────────────────────────
gemini_path = os.path.join(home, ".gemini", "settings.json")
def patch_gemini(data):
    hooks = data.get("hooks", {})
    for event in list(hooks.keys()):
        hooks[event] = remove_shellguard_from_array(hooks[event])
    data["hooks"] = hooks
    return data

if patch_json(gemini_path, patch_gemini):
    print("  ✓ Gemini hooks cleaned")
else:
    print("  ! ~/.gemini/settings.json not found (skipping)")

PYEOF

# ── 5. Optionally remove config & logs ────────────────────────────────────────

CONFIG_DIR="$HOME/Library/Application Support/ShellGuard"
if [ -d "$CONFIG_DIR" ]; then
    echo ""
    read -r -p "  Remove config & logs at $CONFIG_DIR? [y/N] " answer
    case "$answer" in
        [yY][eE][sS]|[yY])
            rm -rf "$CONFIG_DIR" && ok "Config directory removed"
            ;;
        *)
            warn "Config kept at $CONFIG_DIR"
            ;;
    esac
fi

echo ""
echo -e "${GREEN}>_! Shell Guard has been uninstalled.${NC}"
echo ""
