#!/bin/bash
# Builds the Windows deliverables into dist/windows/:
#   ShellGuardSetup-<arch>.exe  headless installer, matching shellguard.exe embedded
#   ShellGuard-<version>-x64.msi  machine-wide MSI for Intune / GPO / SCCM (needs wixl:
#                               `brew install msitools`; skipped when missing)
#   shellguard-sign.exe         signs managed config for strict builds
#
# POLICY_PUBKEY=<base64>  embeds the customer's policy key: the build then only
#                         accepts signed managed config (see docs/SETTINGS.md).
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLI_DIR="$ROOT_DIR"
OUT_DIR="$ROOT_DIR/dist/windows"
PAYLOAD_DIR="$CLI_DIR/cmd/shellguard-setup/payload"
VERSION="$(sed -n 's/^const appVersion = "\(.*\)"/\1/p' "$CLI_DIR/cmd/shellguard/siem.go")"

LDFLAGS="-s -w"
if [ -n "$POLICY_PUBKEY" ]; then
  LDFLAGS="$LDFLAGS -X main.policyPublicKey=$POLICY_PUBKEY"
  echo "strict build: managed config must be signed"
fi

mkdir -p "$OUT_DIR" "$PAYLOAD_DIR"
cd "$CLI_DIR"
trap 'rm -f "$PAYLOAD_DIR/shellguard.exe"' EXIT

for ARCH in amd64 arm64; do
  echo "→ windows/$ARCH"
  GOOS=windows GOARCH=$ARCH go build -trimpath -ldflags="$LDFLAGS" -o "$OUT_DIR/shellguard-$ARCH.exe" ./cmd/shellguard/
  cp "$OUT_DIR/shellguard-$ARCH.exe" "$PAYLOAD_DIR/shellguard.exe"
  GOOS=windows GOARCH=$ARCH go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/ShellGuardSetup-$ARCH.exe" ./cmd/shellguard-setup/
  echo "  $OUT_DIR/ShellGuardSetup-$ARCH.exe"
done
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/shellguard-sign.exe" ./cmd/shellguard-sign/

if ! command -v wixl >/dev/null || ! command -v msibuild >/dev/null; then
  echo "wixl/msibuild not found (brew install msitools) — MSI skipped"
  exit 0
fi
# wixl has no arm64 target; the x64 MSI also runs on Windows 11 ARM (x64 emulation).
MSI="$OUT_DIR/ShellGuard-$VERSION-x64.msi"
wixl -a x64 -D Version="$VERSION" -D SetupExe="$OUT_DIR/ShellGuardSetup-amd64.exe" \
  -o "$MSI" "$ROOT_DIR/packaging/windows/ShellGuard.wxs"
# wixl ignores HideTarget and Secure=yes; set them in the tables directly.
#   3090 = exe from installed file + deferred + no impersonation; +0x2000 hides
#   the command line (it carries SIEMTOKEN) from verbose MSI logs.
msibuild "$MSI" -q "UPDATE CustomAction SET Type=11282 WHERE Action='SetupInstall'"
msibuild "$MSI" -q "UPDATE Property SET Value='WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED;SIEMHOST;SIEMPORT;SIEMPROTOCOL;SIEMFORMAT;SIEMURL;SIEMTOKEN;SIEMCA;CONFIGDIR;TOOLS' WHERE Property='SecureCustomProperties'"
# wixl also mis-sequences two actions; fix them in the table:
#   RemoveExistingProducts lands after InstallFiles (4003) with no InstallExecute
#   before it, so every install fails with error 2613 → move it right after
#   InstallValidate (1400), the standard "afterInstallValidate" slot.
#   SetupUninstall's Before="RemoveFiles" resolves to sequence 1, outside the
#   InstallInitialize..InstallFinalize script, where a deferred action can't
#   run → move it just before RemoveFiles (3500).
msibuild "$MSI" -q "UPDATE InstallExecuteSequence SET Sequence=1450 WHERE Action='RemoveExistingProducts'"
msibuild "$MSI" -q "UPDATE InstallExecuteSequence SET Sequence=3400 WHERE Action='SetupUninstall'"
echo "  $MSI"
