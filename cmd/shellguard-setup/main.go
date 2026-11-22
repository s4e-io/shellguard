// ShellGuardSetup installs ShellGuard on Windows without a UI: it places the
// CLI, pins the mode to "log only", optionally configures SIEM forwarding and
// wires the shell-execution hooks of Cursor, VS Code (Copilot), Junie and
// Claude Code.
//
//	ShellGuardSetup.exe                       per-user install (double-click)
//	ShellGuardSetup.exe install --machine     all users; run as Administrator
//	ShellGuardSetup.exe uninstall [--machine]
//	ShellGuardSetup.exe status [--machine]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const heartbeatTask = "ShellGuard SIEM Heartbeat"

var allTools = []string{"cursor", "vscode", "junie", "claude"}

type siemOpts struct {
	host, protocol, format, url, token, ca string
	port                                   int
}

// managedFiles are copied as-is (with their .sig) by --config-dir, so files
// signed for a strict build reach the endpoint unchanged.
var managedFiles = []string{"state.json", "policy.yaml", "siem.yaml"}

// home is a user profile that receives per-user hook files.
type home struct {
	dir     string // C:\Users\name
	appData string // C:\Users\name\AppData\Roaming
}

// plan describes where everything goes for one install scope.
type plan struct {
	machine bool
	exe     string // installed shellguard.exe
	cfgDir  string // state.json / siem.yaml (managed dir when machine)
	homes   []home
	tools   map[string]bool // explicit --tools selection; nil = all tools
}

func newPlan(machine bool, tools map[string]bool) (plan, error) {
	if machine {
		dir := filepath.Join(programDataDir(), "ShellGuard")
		homes, err := allUserHomes()
		if err != nil {
			return plan{}, err
		}
		return plan{machine: true, exe: filepath.Join(dir, "shellguard.exe"), cfgDir: dir, homes: homes, tools: tools}, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return plan{}, err
	}
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(h, "AppData", "Roaming")
	}
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		local = filepath.Join(h, "AppData", "Local")
	}
	return plan{
		exe:    filepath.Join(local, "Programs", "ShellGuard", "shellguard.exe"),
		cfgDir: filepath.Join(appData, "ShellGuard"),
		homes:  []home{{dir: h, appData: appData}},
		tools:  tools,
	}, nil
}

// wants reports whether a tool's hook should be written. Without --tools every
// supported tool is configured, installed or not: a hook file is inert until
// the tool exists, and a tool installed later is covered from its first run.
func (p plan) wants(tool string) bool { return p.tools == nil || p.tools[tool] }

func cursorUserFile(h home) string { return filepath.Join(h.dir, ".cursor", "hooks.json") }
func claudeUserFile(h home) string { return filepath.Join(h.dir, ".claude", "settings.json") }
func copilotUserFile(h home) string {
	return filepath.Join(h.dir, ".copilot", "hooks", "shellguard.json")
}
func junieUserFile(h home) string { return filepath.Join(h.dir, ".junie", "config.json") }
func cursorManagedFile() string   { return filepath.Join(programDataDir(), "Cursor", "hooks.json") }
func claudeManagedFile() string {
	return filepath.Join(programFilesDir(), "ClaudeCode", "managed-settings.json")
}

// ── Reporting ─────────────────────────────────────────────────────────────────

type report struct{ failed int }

func (r *report) step(name string, err error) {
	if err != nil {
		r.failed++
		fmt.Printf("  ✗ %s: %v\n", name, err)
		return
	}
	fmt.Printf("  ✓ %s\n", name)
}

func (r *report) skip(name, why string) { fmt.Printf("  - %s (%s)\n", name, why) }

// ── Install ───────────────────────────────────────────────────────────────────

func install(p plan, siem siemOpts, configSrc string, heartbeat bool) int {
	r := &report{}
	fmt.Printf("ShellGuard install (%s)\n\n", scopeName(p))

	r.step("shellguard.exe → "+p.exe, installBinary(p.exe))
	if configSrc != "" {
		for _, f := range managedFiles {
			if exists(filepath.Join(configSrc, f)) {
				r.step(f+" (prepared config) → "+p.cfgDir, copyManaged(configSrc, p.cfgDir, f))
			}
		}
	} else {
		r.step("mode: log only → "+filepath.Join(p.cfgDir, "state.json"), writeLogOnlyState(p.cfgDir))
	}
	switch {
	case configSrc != "" && siem.target() != "":
		r.skip("--siem-*", "siem.yaml is taken from --config-dir")
	case siem.target() != "":
		r.step("SIEM → "+siem.target(), writeSIEMConfig(p.cfgDir, siem))
	}
	if p.machine {
		r.step("managed directory locked (users can only read)", lockDownDir(p.cfgDir))
	}

	fmt.Println("\nHooks:")
	installHooks(p, r)

	if heartbeat {
		switch {
		case siem.target() == "" && !exists(filepath.Join(p.cfgDir, "siem.yaml")):
			r.skip("SIEM heartbeat task", "SIEM is not configured")
		case p.machine:
			r.skip("SIEM heartbeat task", "for machine installs, schedule it per user with Intune or GPO")
		default:
			r.step("SIEM heartbeat task (every 5 min)", createHeartbeatTask(p.exe))
		}
	}

	fmt.Println()
	if r.failed > 0 {
		fmt.Printf("%d step(s) failed; see the errors above.\n", r.failed)
		return 1
	}
	fmt.Println("Done. Fully quit and reopen Cursor, VS Code and JetBrains IDEs.")
	fmt.Printf("Command log: %s\n", filepath.Join(userConfigHint(p), "activity.log"))
	return 0
}

func installHooks(p plan, r *report) {
	exe := p.exe
	if p.machine {
		if p.wants("cursor") {
			r.step("Cursor (all users) → "+cursorManagedFile(), editJSONFile(cursorManagedFile(), func(d map[string]any) {
				editCursor(d, psInvoke(exe, ""), true)
			}))
		}
		if p.wants("claude") {
			r.step("Claude Code (all users) → "+claudeManagedFile(), editJSONFile(claudeManagedFile(), func(d map[string]any) {
				editMatcherGroups(d, []string{"PreToolUse", "PostToolUse"}, "Bash|PowerShell", claudeHook(exe), true)
			}))
		}
	}
	for _, h := range p.homes {
		who := filepath.Base(h.dir)
		if p.machine {
			// The managed Cursor / Claude Code files cover every user; a leftover
			// per-user ShellGuard hook would log each command twice.
			if fileHasOurHook(cursorUserFile(h)) {
				r.step("Cursor per-user hook removed ["+who+"]", editJSONFile(cursorUserFile(h), func(d map[string]any) {
					editCursor(d, "", false)
				}))
			}
			if fileHasOurHook(claudeUserFile(h)) {
				r.step("Claude Code per-user hook removed ["+who+"]", editJSONFile(claudeUserFile(h), func(d map[string]any) {
					editMatcherGroups(d, []string{"PreToolUse", "PostToolUse"}, "", nil, false)
				}))
			}
		}
		if !p.machine && p.wants("cursor") {
			r.step("Cursor → "+cursorUserFile(h), editJSONFile(cursorUserFile(h), func(d map[string]any) {
				editCursor(d, psInvoke(exe, ""), true)
			}))
		}
		if !p.machine && p.wants("claude") {
			r.step("Claude Code → "+claudeUserFile(h), editJSONFile(claudeUserFile(h), func(d map[string]any) {
				editMatcherGroups(d, []string{"PreToolUse", "PostToolUse"}, "Bash|PowerShell", claudeHook(exe), true)
			}))
		}
		if p.wants("vscode") {
			r.step("VS Code (Copilot) ["+who+"] → "+copilotUserFile(h), writeJSON(copilotUserFile(h), copilotHooks(psInvoke(exe, "--source vscode"))))
		}
		if p.wants("junie") {
			r.step("Junie ["+who+"] → "+junieUserFile(h), editJSONFile(junieUserFile(h), func(d map[string]any) {
				editMatcherGroups(d, []string{"PreToolUse"}, "Bash", commandHook(cmdInvoke(exe, "--source junie")), true)
			}))
		}
	}
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

func uninstall(p plan) int {
	r := &report{}
	fmt.Printf("Uninstalling ShellGuard (%s)\n\n", scopeName(p))

	edit := func(name, path string, fn func(map[string]any)) {
		if !fileHasOurHook(path) {
			return
		}
		r.step(name+" → "+path, editJSONFile(path, fn))
	}
	removeCursor := func(d map[string]any) { editCursor(d, "", false) }
	removeClaude := func(d map[string]any) {
		editMatcherGroups(d, []string{"PreToolUse", "PostToolUse"}, "", nil, false)
	}
	if p.machine {
		edit("Cursor (all users)", cursorManagedFile(), removeCursor)
		edit("Claude Code (all users)", claudeManagedFile(), removeClaude)
	}
	for _, h := range p.homes {
		edit("Cursor", cursorUserFile(h), removeCursor)
		edit("Claude Code", claudeUserFile(h), removeClaude)
		edit("Junie", junieUserFile(h), func(d map[string]any) {
			editMatcherGroups(d, []string{"PreToolUse"}, "", nil, false)
		})
		if exists(copilotUserFile(h)) {
			r.step("VS Code (Copilot) → "+copilotUserFile(h), os.Remove(copilotUserFile(h)))
		}
	}
	if !p.machine {
		_ = deleteHeartbeatTask()
	}
	if p.machine {
		for _, f := range []string{"state.json", "state.json.sig", "policy.yaml", "policy.yaml.sig", "siem.yaml", "siem.yaml.sig"} {
			if path := filepath.Join(p.cfgDir, f); exists(path) {
				r.step("managed config removed: "+path, os.Remove(path))
			}
		}
	}
	if exists(p.exe) {
		r.step("shellguard.exe removed", removeBinary(p.exe))
	}
	fmt.Println()
	fmt.Println("Command logs (activity.log) were kept for auditing.")
	if r.failed > 0 {
		return 1
	}
	return 0
}

// ── Status ────────────────────────────────────────────────────────────────────

func status(p plan) int {
	fmt.Printf("ShellGuard status (%s)\n\n", scopeName(p))
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("  shellguard.exe   %s  (%s)\n", yes(exists(p.exe)), p.exe)
	var st map[string]any
	if data, err := os.ReadFile(filepath.Join(p.cfgDir, "state.json")); err == nil && json.Unmarshal(data, &st) == nil {
		fmt.Printf("  state.json       mode=%v enabled=%v\n", st["mode"], st["enabled"])
	} else {
		fmt.Printf("  state.json       missing\n")
	}
	fmt.Printf("  siem.yaml        %s\n", yes(exists(filepath.Join(p.cfgDir, "siem.yaml"))))
	if p.machine {
		fmt.Printf("  Cursor (managed)        %s\n", yes(fileHasOurHook(cursorManagedFile())))
		fmt.Printf("  Claude Code (managed)   %s\n", yes(fileHasOurHook(claudeManagedFile())))
	}
	for _, h := range p.homes {
		fmt.Printf("  [%s] Cursor %s · Claude Code %s · VS Code %s · Junie %s\n", filepath.Base(h.dir),
			yes(fileHasOurHook(cursorUserFile(h))), yes(fileHasOurHook(claudeUserFile(h))),
			yes(exists(copilotUserFile(h))), yes(fileHasOurHook(junieUserFile(h))))
	}
	return 0
}

// ── Files ─────────────────────────────────────────────────────────────────────

// installBinary writes the embedded shellguard.exe. A running copy (a hook in
// flight) can't be overwritten on Windows but can be renamed, so the old file
// is moved aside first.
func installBinary(dst string) error {
	if len(payload) == 0 {
		return fmt.Errorf("this installer does not contain shellguard.exe (build it with scripts/build-windows.sh)")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, payload, 0755); err != nil {
		return err
	}
	old := dst + ".old"
	_ = os.Remove(old)
	if exists(dst) {
		if err := os.Rename(dst, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	_ = os.Remove(old) // may fail while a hook still runs it; harmless
	return nil
}

func removeBinary(exe string) error {
	if err := os.Remove(exe); err != nil {
		return err
	}
	_ = os.Remove(exe + ".old")
	_ = os.Remove(filepath.Dir(exe)) // only if empty
	return nil
}

// writeLogOnlyState sets mode/enabled, keeping any other keys already there.
func writeLogOnlyState(dir string) error {
	return editJSONFile(filepath.Join(dir, "state.json"), func(d map[string]any) {
		d["mode"] = "log only"
		d["enabled"] = true
	})
}

// target describes the configured SIEM destination ("" = none).
func (s siemOpts) target() string {
	switch {
	case s.protocol == "https" && s.url != "":
		return fmt.Sprintf("%s (%s)", s.url, s.format)
	case s.protocol != "https" && s.host != "":
		return fmt.Sprintf("%s:%d (%s, %s)", s.host, s.port, s.protocol, s.format)
	}
	return ""
}

func writeSIEMConfig(dir string, s siemOpts) error {
	var b strings.Builder
	if s.protocol == "https" {
		fmt.Fprintf(&b, "enabled: true\nprotocol: https\nurl: %q\nformat: %s\n", s.url, s.format)
		if s.token != "" {
			fmt.Fprintf(&b, "token: %q\n", s.token)
		}
	} else {
		fmt.Fprintf(&b, "enabled: true\nhost: %q\nport: %d\nprotocol: %s\nformat: %s\n", s.host, s.port, s.protocol, s.format)
	}
	if s.ca != "" {
		fmt.Fprintf(&b, "ca_file: %q\n", s.ca)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "siem.yaml"), []byte(b.String()), 0644)
}

// copyManaged copies name and its .sig (when present) from src to dst. A
// stale .sig at the destination is removed so it can't pair with a new file.
func copyManaged(src, dst, name string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	for _, f := range []string{name, name + ".sig"} {
		data, err := os.ReadFile(filepath.Join(src, f))
		if os.IsNotExist(err) && f != name {
			_ = os.Remove(filepath.Join(dst, f))
			continue
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, f), data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func scopeName(p plan) string {
	if p.machine {
		return "all users"
	}
	return "this user"
}

// userConfigHint is where each user's activity.log lives.
func userConfigHint(p plan) string {
	if p.machine {
		return `%APPDATA%\ShellGuard`
	}
	return p.cfgDir
}

// ── CLI ───────────────────────────────────────────────────────────────────────

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	interactive := len(args) == 0 // double-clicked
	defer func() {
		if interactive {
			fmt.Print("\nPress Enter to close...")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
	}()

	action := "install"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("ShellGuardSetup", flag.ContinueOnError)
	machine := fs.Bool("machine", false, "install for all users (run as Administrator)")
	toolsFlag := fs.String("tools", "", "comma-separated: cursor,vscode,junie,claude (default: all)")
	host := fs.String("siem-host", "", "QRadar / syslog server")
	port := fs.Int("siem-port", 0, "SIEM port (default: tls 6514, tcp/udp 514)")
	proto := fs.String("siem-protocol", "tls", "tls | tcp | udp | https")
	format := fs.String("siem-format", "", "syslog: leef | cef | json; https: hec | json (default: leef / hec)")
	url := fs.String("siem-url", "", "https endpoint, e.g. https://splunk:8088/services/collector/event")
	token := fs.String("siem-token", "", "https token (Splunk HEC or Bearer)")
	configDir := fs.String("config-dir", "", "copy state.json / policy.yaml / siem.yaml (and .sig) from this directory")
	ca := fs.String("siem-ca", "", "CA file (PEM) for the SIEM certificate")
	heartbeat := fs.Bool("heartbeat", false, "create a scheduled task that runs `shellguard --send` every 5 minutes")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var tools map[string]bool
	if *toolsFlag != "" {
		tools = map[string]bool{}
		for _, t := range strings.Split(*toolsFlag, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if !slices.Contains(allTools, t) {
				fmt.Fprintf(os.Stderr, "unknown tool %q (valid: %s)\n", t, strings.Join(allTools, ", "))
				return 2
			}
			tools[t] = true
		}
	}
	siem := siemOpts{host: strings.TrimSpace(*host), protocol: strings.ToLower(strings.TrimSpace(*proto)),
		format: strings.ToLower(strings.TrimSpace(*format)), url: strings.TrimSpace(*url), token: *token, ca: *ca, port: *port}
	if siem.url != "" && siem.host == "" {
		siem.protocol = "https" // --siem-url alone implies https
	}
	if siem.protocol == "" {
		siem.protocol = "tls"
	}
	if !slices.Contains([]string{"tls", "tcp", "udp", "https"}, siem.protocol) {
		fmt.Fprintf(os.Stderr, "invalid --siem-protocol %q\n", siem.protocol)
		return 2
	}
	formats := []string{"leef", "cef", "json"}
	if siem.protocol == "https" {
		formats = []string{"hec", "json"}
	}
	if siem.format == "" {
		siem.format = formats[0]
	}
	if !slices.Contains(formats, siem.format) {
		fmt.Fprintf(os.Stderr, "--siem-protocol %s does not support --siem-format %q (valid: %s)\n", siem.protocol, siem.format, strings.Join(formats, ", "))
		return 2
	}
	if siem.protocol == "https" && siem.host != "" && siem.url == "" {
		fmt.Fprintln(os.Stderr, "--siem-protocol https requires --siem-url")
		return 2
	}
	if siem.host != "" {
		if siem.port == 0 {
			siem.port = 514
			if siem.protocol == "tls" {
				siem.port = 6514
			}
		}
	}

	if !supported() {
		fmt.Fprintln(os.Stderr, "ShellGuardSetup runs on Windows only.")
		return 1
	}
	if *machine && action != "status" && !isElevated() {
		fmt.Fprintln(os.Stderr, "--machine requires Administrator (right-click → Run as administrator).")
		return 1
	}
	p, err := newPlan(*machine, tools)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	switch action {
	case "install":
		src := strings.TrimSpace(*configDir)
		if src != "" && !exists(src) {
			fmt.Fprintf(os.Stderr, "--config-dir not found: %s\n", src)
			return 1
		}
		return install(p, siem, src, *heartbeat)
	case "uninstall":
		return uninstall(p)
	case "status":
		return status(p)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (install | uninstall | status)\n", action)
		return 2
	}
}
