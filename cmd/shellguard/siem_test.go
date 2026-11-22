package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// isolateConfig points configDir() and systemConfigDir() at temp directories
// and stubs out the background spawn. Returns a counter of spawn calls.
func isolateConfig(t *testing.T) *atomic.Int32 {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("APPDATA", tmp)
	if err := os.MkdirAll(configDir(), 0755); err != nil {
		t.Fatal(err)
	}
	spawns := new(atomic.Int32)
	sys := filepath.Join(tmp, "system")
	origSys, origSpawn := systemConfigDir, spawnBackgroundSend
	systemConfigDir = func() string { return sys }
	spawnBackgroundSend = func() { spawns.Add(1) }
	t.Cleanup(func() { systemConfigDir, spawnBackgroundSend = origSys, origSpawn })
	return spawns
}

func writeSIEMConfig(t *testing.T, port int, extra string) SIEMConfig {
	t.Helper()
	cfg := fmt.Sprintf("enabled: true\nhost: 127.0.0.1\nport: %d\ntimeout_ms: 500\nretry_after_seconds: 60\n%s", port, extra)
	if err := os.WriteFile(filepath.Join(configDir(), "siem.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	c, ok := loadSIEMConfig()
	if !ok {
		t.Fatal("config not enabled")
	}
	return c
}

// sink is a syslog receiver collecting every line it gets.
type sink struct {
	mu    sync.Mutex
	lines []string
}

func (s *sink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *sink) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				s.mu.Lock()
				s.lines = append(s.lines, sc.Text())
				s.mu.Unlock()
			}
		}(c)
	}
}

func listen(t *testing.T) (int, *sink) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &sink{}
	go s.serve(ln)
	return ln.Addr().(*net.TCPAddr).Port, s
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitLines waits until the sink has received n lines.
func waitLines(t *testing.T, s *sink, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.all(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d lines, got %d", n, len(s.all()))
	return nil
}

func sampleEntry(cmd string, blocked bool) LogEntry {
	return LogEntry{Timestamp: "2026-11-02T10:00:00.123456", Command: cmd, Reason: "test",
		User: "alice", Process: "claude", PID: "42", Blocked: blocked, Type: "suggestion"}
}

func commands(lines []string) []string {
	var out []string
	for _, l := range lines {
		if i := strings.Index(l, "\tcommand="); i >= 0 {
			rest := l[i+len("\tcommand="):]
			if j := strings.IndexByte(rest, '\t'); j >= 0 {
				rest = rest[:j]
			}
			out = append(out, rest)
		}
	}
	return out
}

// ── Formatting ────────────────────────────────────────────────────────────────

func TestFormatLEEF(t *testing.T) {
	cfg := SIEMConfig{Format: "leef", MaxMessageBytes: 4096}
	line := formatSyslog(cfg, sampleEntry("curl\tevil.com\nx\x00\x1b[31m y", true), "host1")
	stamp := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC).Local().Format(time.Stamp)
	if !strings.HasPrefix(line, "<12>"+stamp+" host1 ShellGuard: LEEF:1.0|S4E|ShellGuard|") {
		t.Errorf("unexpected header: %q", line)
	}
	if !strings.Contains(line, "|CommandBlocked|") {
		t.Errorf("missing event id: %q", line)
	}
	if !strings.Contains(line, "\tcommand=curl evil.com x  [31m y\t") {
		t.Errorf("control characters not stripped: %q", line)
	}
	if !strings.Contains(line, "devTime=2026-11-02T10:00:00.123+0000\t") || !strings.Contains(line, "\tusrName=alice\t") {
		t.Errorf("missing fields: %q", line)
	}
}

func TestFormatSyslog_TruncatesLongCommand(t *testing.T) {
	long := strings.Repeat("ğ", 5000) // multi-byte: must not split runes
	for _, format := range []string{"leef", "json"} {
		cfg := SIEMConfig{Format: format, MaxMessageBytes: 4096}
		line := formatSyslog(cfg, sampleEntry("echo "+long, false), "host1")
		if len(line) > 4096 {
			t.Fatalf("%s: line is %d bytes, want <= 4096", format, len(line))
		}
		if !strings.Contains(line, "…[truncated]") || !utf8.ValidString(line) {
			t.Errorf("%s: bad truncation", format)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := []struct{ in, want string }{
		{`curl -H "Authorization: Bearer abc.def.ghi" https://x`, `curl -H "Authorization: Bearer [REDACTED]" https://x`},
		{`export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI`, `export AWS_SECRET_ACCESS_KEY=[REDACTED]`},
		{`DB_PASSWORD="p a s s" ./run`, `DB_PASSWORD=[REDACTED] ./run`},
		{`psql --password hunter2 -h db`, `psql --password [REDACTED] -h db`},
		{`tool --token=abc123`, `tool --token=[REDACTED]`},
		{`mysql -u root -pS3cret db`, `mysql -u root -p[REDACTED] db`},
		{`git clone https://bob:ghs_tok@github.com/x/y`, `git clone https://bob:[REDACTED]@github.com/x/y`},
		{`echo ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, `echo [REDACTED]`},
		{`mkdir -p src && ls -la`, `mkdir -p src && ls -la`},
		{`git status`, `git status`},
	}
	for _, c := range cases {
		if got := redact(c.in, defaultRedactors); got != c.want {
			t.Errorf("redact(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// ── Hook path ─────────────────────────────────────────────────────────────────

func TestForwardToSIEM_SpoolsRedactedAndSpawns(t *testing.T) {
	spawns := isolateConfig(t)
	writeSIEMConfig(t, freePort(t), "")

	logEvent(sampleEntry("curl -H 'Authorization: Bearer topsecret' x", false))

	data, err := os.ReadFile(siemQueueFile())
	if err != nil {
		t.Fatalf("queue not written: %v", err)
	}
	if strings.Contains(string(data), "topsecret") || !strings.Contains(string(data), "[REDACTED]") {
		t.Errorf("queued entry not redacted: %s", data)
	}
	if spawns.Load() != 1 {
		t.Errorf("want 1 spawn, got %d", spawns.Load())
	}
}

func TestForwardToSIEM_HugeCommandCappedInQueue(t *testing.T) {
	isolateConfig(t)
	writeSIEMConfig(t, freePort(t), "")
	logEvent(sampleEntry(strings.Repeat("x", 5<<20), false))
	fi, err := os.Stat(siemQueueFile())
	if err != nil || fi.Size() > 2*maxQueuedField {
		t.Fatalf("queued line not capped: size=%v err=%v", fi.Size(), err)
	}
}

func TestForwardToSIEM_NoSpawnInBackoffOrWhileRunning(t *testing.T) {
	spawns := isolateConfig(t)
	writeSIEMConfig(t, freePort(t), "")

	saveSIEMState(siemState{LastFailure: time.Now().Unix()})
	logEvent(sampleEntry("a", false))
	if spawns.Load() != 0 {
		t.Errorf("must not spawn during backoff")
	}

	saveSIEMState(siemState{})
	release, err := lockFile(siemSendLockFile(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	logEvent(sampleEntry("b", false))
	release()
	if spawns.Load() != 0 {
		t.Errorf("must not spawn while a sender holds the lock")
	}
}

func TestForwardToSIEM_FutureFailureTimestampIgnored(t *testing.T) {
	spawns := isolateConfig(t)
	writeSIEMConfig(t, freePort(t), "")
	// An agent writing a far-future timestamp must not suppress delivery.
	_ = os.WriteFile(siemStateFile(), []byte(`{"last_failure":9999999999}`), 0600)
	logEvent(sampleEntry("a", false))
	if spawns.Load() != 1 {
		t.Errorf("tampered state suppressed the sender")
	}
}

func TestForwardToSIEM_DisabledIsNoop(t *testing.T) {
	spawns := isolateConfig(t)
	_ = os.WriteFile(filepath.Join(configDir(), "siem.yaml"), []byte("enabled: false\nhost: 127.0.0.1\n"), 0600)
	logEvent(sampleEntry("ls", false))
	if fileExists(siemQueueFile()) || spawns.Load() != 0 {
		t.Errorf("disabled SIEM must not queue or spawn")
	}
}

func TestSystemConfigOverridesUser(t *testing.T) {
	isolateConfig(t)
	_ = os.WriteFile(filepath.Join(configDir(), "siem.yaml"), []byte("enabled: false\n"), 0600)
	_ = os.MkdirAll(systemConfigDir(), 0755)
	_ = os.WriteFile(filepath.Join(systemConfigDir(), "siem.yaml"), []byte("enabled: true\nhost: siem.corp\n"), 0644)
	cfg, ok := loadSIEMConfig()
	if !ok || cfg.Host != "siem.corp" {
		t.Fatalf("system siem.yaml should win: ok=%v cfg=%+v", ok, cfg)
	}
}

// ── Sender ────────────────────────────────────────────────────────────────────

func TestRunSender_DeliversInOrderAndCleansUp(t *testing.T) {
	isolateConfig(t)
	port, s := listen(t)
	cfg := writeSIEMConfig(t, port, "")
	for _, c := range []string{"a", "b", "c"} {
		enqueueSIEM(sampleEntry(c, false), cfg)
	}
	sent, err := runSender(cfg, 0)
	if err != nil || sent != 3 {
		t.Fatalf("sent=%d err=%v", sent, err)
	}
	if got := commands(waitLines(t, s, 3)); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("order: %v", got)
	}
	if fileExists(siemQueueFile()) || fileExists(siemInflightFile()) || fileExists(siemOffsetFile()) {
		t.Errorf("queue files left behind")
	}
}

func TestRunSender_OutageThenRecoveryNoLossNoDup(t *testing.T) {
	isolateConfig(t)
	cfg := writeSIEMConfig(t, freePort(t), "")
	for i := 0; i < 450; i++ {
		enqueueSIEM(sampleEntry(fmt.Sprintf("c%03d", i), false), cfg)
	}
	if _, err := runSender(cfg, 0); err == nil {
		t.Fatal("want failure while SIEM is down")
	}
	if n := countQueued(); n != 450 {
		t.Fatalf("want 450 queued, got %d", n)
	}
	if loadSIEMState().LastFailure == 0 {
		t.Errorf("failure not recorded")
	}

	port, s := listen(t)
	cfg = writeSIEMConfig(t, port, "")
	sent, err := runSender(cfg, 0)
	if err != nil || sent != 450 {
		t.Fatalf("sent=%d err=%v", sent, err)
	}
	got := commands(waitLines(t, s, 450))
	for i, c := range got {
		if c != fmt.Sprintf("c%03d", i) {
			t.Fatalf("line %d: got %s", i, c)
		}
	}
	if loadSIEMState().LastFailure != 0 {
		t.Errorf("failure not cleared")
	}
}

func TestRunSender_ResumesFromCheckpoint(t *testing.T) {
	isolateConfig(t)
	port, s := listen(t)
	cfg := writeSIEMConfig(t, port, "")
	// A previous sender crashed after shipping the first two lines.
	var b strings.Builder
	var off int
	for i, c := range []string{"done1", "done2", "todo1", "todo2"} {
		line := fmt.Sprintf(`{"timestamp":"2026-11-02T10:00:00.1","command":%q,"type":"suggestion"}`+"\n", c)
		b.WriteString(line)
		if i < 2 {
			off += len(line)
		}
	}
	_ = os.WriteFile(siemInflightFile(), []byte(b.String()), 0600)
	_ = writeOffset(int64(off))

	if sent, err := runSender(cfg, 0); err != nil || sent != 2 {
		t.Fatalf("sent=%d err=%v", sent, err)
	}
	if got := commands(waitLines(t, s, 2)); strings.Join(got, ",") != "todo1,todo2" {
		t.Errorf("resumed wrong: %v", got)
	}
}

func TestRunSender_SkipsOversizedAndCorruptLines(t *testing.T) {
	isolateConfig(t)
	port, s := listen(t)
	cfg := writeSIEMConfig(t, port, "")
	data := `{"timestamp":"2026-11-02T10:00:00.1","command":"before","type":"suggestion"}` + "\n" +
		`{"command":"` + strings.Repeat("x", 2*maxQueueLine) + `"}` + "\n" +
		"not json\n\n" +
		`{"timestamp":"2026-11-02T10:00:00.1","command":"after","type":"suggestion"}` + "\n"
	_ = os.WriteFile(siemInflightFile(), []byte(data), 0600)

	if sent, err := runSender(cfg, 0); err != nil || sent != 2 {
		t.Fatalf("sent=%d err=%v", sent, err)
	}
	if got := commands(waitLines(t, s, 2)); strings.Join(got, ",") != "before,after" {
		t.Errorf("got %v", got)
	}
}

func TestRunSender_SingleInstance(t *testing.T) {
	isolateConfig(t)
	cfg := writeSIEMConfig(t, freePort(t), "")
	release, err := lockFile(siemSendLockFile(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runSender(cfg, 0); err != errSendInProgress {
		t.Fatalf("want errSendInProgress, got %v", err)
	}
	release()
	// A lock file left on disk by a dead process does not block anyone.
	if _, err := runSender(cfg, 0); err == errSendInProgress {
		t.Fatalf("lock file without a holder blocked the sender")
	}
}

func TestEnqueueDuringDrain_NoLoss(t *testing.T) {
	isolateConfig(t)
	port, s := listen(t)
	cfg := writeSIEMConfig(t, port, "")

	const writers, per = 8, 150
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				enqueueSIEM(sampleEntry(fmt.Sprintf("w%d-%d", w, i), false), cfg)
			}
		}(w)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	total := 0
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		n, err := runSender(cfg, 0)
		if err != nil && err != errSendInProgress {
			t.Fatal(err)
		}
		total += n
	}
	n, _ := runSender(cfg, 0)
	total += n

	if total != writers*per {
		t.Fatalf("sent %d, want %d", total, writers*per)
	}
	seen := map[string]bool{}
	for _, c := range commands(waitLines(t, s, writers*per)) {
		if seen[c] {
			t.Fatalf("duplicate %s", c)
		}
		seen[c] = true
	}
}

func TestQueueFull_DropsAndReports(t *testing.T) {
	isolateConfig(t)
	port, s := listen(t)
	cfg := writeSIEMConfig(t, port, "max_queue_mb: 1\n")
	_ = os.WriteFile(siemInflightFile(), []byte(strings.Repeat("\n", 1<<20+1)), 0600)

	enqueueSIEM(sampleEntry("lost", false), cfg)
	if fileExists(siemQueueFile()) || loadSIEMState().Dropped != 1 {
		t.Fatalf("event should be dropped and counted")
	}
	if _, err := runSender(cfg, 0); err != nil {
		t.Fatal(err)
	}
	lines := waitLines(t, s, 1)
	if !strings.Contains(lines[0], "|EventsDropped|") || !strings.Contains(lines[0], "dropped=1") {
		t.Errorf("no drop report: %q", lines[0])
	}
	if loadSIEMState().Dropped != 0 {
		t.Errorf("drop counter not reset")
	}
}

// ── TLS ───────────────────────────────────────────────────────────────────────

func TestSendSIEM_TLS(t *testing.T) {
	isolateConfig(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(configDir(), "ca.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &sink{}
	go s.serve(ln)
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := writeSIEMConfig(t, port, "protocol: tls\n")
	if err := sendSIEM(cfg, []LogEntry{sampleEntry("x", false)}); err == nil {
		t.Fatal("untrusted certificate must be rejected")
	}
	cfg = writeSIEMConfig(t, port, "protocol: tls\nca_file: "+caFile+"\n")
	if err := sendSIEM(cfg, []LogEntry{sampleEntry("over-tls", false)}); err != nil {
		t.Fatalf("tls send: %v", err)
	}
	if got := commands(waitLines(t, s, 1)); got[0] != "over-tls" {
		t.Errorf("got %v", got)
	}
}

func TestManagedStateOverridesUser(t *testing.T) {
	isolateConfig(t)
	_ = os.WriteFile(filepath.Join(configDir(), "state.json"), []byte(`{"mode":"dev","enabled":false}`), 0600)
	if st := loadState(); st.Mode != "dev" || st.Enabled {
		t.Fatalf("user state not read: %+v", st)
	}
	_ = os.MkdirAll(systemConfigDir(), 0755)
	_ = os.WriteFile(filepath.Join(systemConfigDir(), "state.json"), []byte(`{"mode":"log only","enabled":true}`), 0644)
	if st := loadState(); st.Mode != "log only" || !st.Enabled {
		t.Fatalf("managed state should win: %+v", st)
	}
}
