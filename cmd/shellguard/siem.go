package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ── SIEM forwarding (syslog LEEF/CEF/JSON, HTTPS HEC/JSON) ──────────────────
//
// Spool first, ship in the background:
//
//  1. The hook appends the event (redacted, size-capped) to siem_queue.log and
//     returns — no network I/O on the hook path.
//  2. If no sender is running and the SIEM is not in failure backoff, the hook
//     starts a detached `shellguard --send --quiet`.
//  3. The sender holds an OS lock (flock / LockFileEx — released by the kernel
//     if it crashes), moves the queue to siem_queue.sending under the queue
//     lock, ships it in batches and checkpoints progress in siem_queue.offset,
//     then lingers briefly so bursts of agent commands reuse one sender.
//
// Syslog has no application-level acknowledgement: delivery is best effort
// (a SIEM that accepts and then drops data cannot be detected). Within that,
// events are sent in order, a crash resumes from the last checkpoint, and an
// interrupted batch may be sent twice.

const appVersion = "1.1.2"

const (
	maxQueuedField = 16 << 10 // command/reason bytes kept per queued event
	maxQueueLine   = 1 << 20  // queue lines longer than this are skipped as corrupt
	sendBatch      = 200
)

var (
	errLocked         = errors.New("locked")
	errSendInProgress = errors.New("another SIEM send is already running")
)

// systemConfigDir holds the machine-wide, admin-owned config. A siem.yaml
// there overrides the per-user one. A variable so tests can redirect it.
var systemConfigDir = platformSystemConfigDir

func siemConfigFile() string { return configFile("siem.yaml") }

func siemQueueFile() string     { return filepath.Join(configDir(), "siem_queue.log") }
func siemInflightFile() string  { return filepath.Join(configDir(), "siem_queue.sending") }
func siemOffsetFile() string    { return filepath.Join(configDir(), "siem_queue.offset") }
func siemQueueLockFile() string { return filepath.Join(configDir(), "siem_queue.lock") }
func siemSendLockFile() string  { return filepath.Join(configDir(), "siem_send.lock") }
func siemStateFile() string     { return filepath.Join(configDir(), "siem_state.json") }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ── Config ────────────────────────────────────────────────────────────────────

type SIEMConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	Protocol        string   `yaml:"protocol"` // "tls" | "tcp" | "udp" | "https"
	Format          string   `yaml:"format"`   // syslog: "leef" | "cef" | "json"; https: "hec" | "json"
	URL             string   `yaml:"url"`      // https only, e.g. https://splunk:8088/services/collector/event
	Token           string   `yaml:"token"`    // https only: HEC token ("Splunk <token>") or bearer token
	TimeoutMs       int      `yaml:"timeout_ms"`
	RetryAfterSec   int      `yaml:"retry_after_seconds"`
	LingerSec       int      `yaml:"linger_seconds"`
	MaxQueueMB      int      `yaml:"max_queue_mb"`
	MaxMessageBytes int      `yaml:"max_message_bytes"`
	CAFile          string   `yaml:"ca_file"`
	CertFile        string   `yaml:"cert_file"`
	KeyFile         string   `yaml:"key_file"`
	TLSSkipVerify   bool     `yaml:"tls_skip_verify"`
	Redact          *bool    `yaml:"redact"`
	RedactPatterns  []string `yaml:"redact_patterns"`

	redactors []*regexp.Regexp
}

func clamp(v, lo, hi int) int { return max(lo, min(v, hi)) }

// loadSIEMConfig returns the config and whether forwarding is active.
func loadSIEMConfig() (SIEMConfig, bool) {
	path := siemConfigFile()
	data, err := readConfig("siem.yaml")
	if err != nil {
		if !os.IsNotExist(err) {
			// e.g. an admin-managed siem.yaml installed without read permission for users
			logError("ERROR", fmt.Sprintf("cannot read %s — SIEM forwarding disabled: %v", path, err))
		}
		return SIEMConfig{}, false
	}
	var c SIEMConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		logError("ERROR", fmt.Sprintf("%s parse failed — SIEM forwarding disabled: %v", path, err))
		return SIEMConfig{}, false
	}
	if !c.Enabled {
		return c, false
	}
	c.Host = strings.TrimSpace(c.Host)
	c.URL = strings.TrimSpace(c.URL)
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	if c.Protocol == "" {
		c.Protocol = "tcp"
	}
	c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	switch c.Protocol {
	case "https":
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			logError("WARN", fmt.Sprintf("%s: protocol https needs a valid url — forwarding disabled", path))
			return c, false
		}
		c.Host = u.Hostname()
		if c.Format != "hec" {
			c.Format = "json"
		}
		if c.MaxMessageBytes <= 0 {
			c.MaxMessageBytes = 16 << 10
		}
	case "tcp", "udp", "tls":
		if c.Format != "json" && c.Format != "cef" {
			c.Format = "leef"
		}
	default:
		logError("WARN", fmt.Sprintf("%s: unknown protocol %q — using tcp", path, c.Protocol))
		c.Protocol = "tcp"
		c.Format = "leef"
	}
	if c.Host == "" {
		logError("WARN", fmt.Sprintf("%s: enabled but host is empty — forwarding disabled", path))
		return c, false
	}
	if c.Port == 0 {
		if c.Protocol == "tls" {
			c.Port = 6514
		} else {
			c.Port = 514
		}
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = 3000
	}
	c.TimeoutMs = clamp(c.TimeoutMs, 100, 30000)
	if c.RetryAfterSec <= 0 {
		c.RetryAfterSec = 60
	}
	if c.LingerSec <= 0 {
		c.LingerSec = 5
	}
	c.LingerSec = clamp(c.LingerSec, 1, 60)
	if c.MaxQueueMB <= 0 {
		c.MaxQueueMB = 50
	}
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = 4096 // QRadar's default max syslog payload length
	}
	c.MaxMessageBytes = clamp(c.MaxMessageBytes, 512, 64<<10)

	if c.Redact == nil || *c.Redact {
		c.redactors = append(c.redactors, defaultRedactors...)
	}
	for _, p := range c.RedactPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			logError("WARN", fmt.Sprintf("%s: invalid redact pattern %q: %v", path, p, err))
			continue
		}
		c.redactors = append(c.redactors, re)
	}
	return c, true
}

// prepareForSIEM redacts and size-caps an entry before it is queued, so the
// queue never holds plaintext credentials or unbounded lines.
// Capping first keeps regex cost on the hook path bounded.
func prepareForSIEM(e LogEntry, cfg SIEMConfig) LogEntry {
	if len(e.Command) > maxQueuedField {
		e.Command = truncateBytes(e.Command, maxQueuedField) + "…[truncated]"
	}
	if len(e.Reason) > maxQueuedField {
		e.Reason = truncateBytes(e.Reason, maxQueuedField) + "…[truncated]"
	}
	e.Command = redact(e.Command, cfg.redactors)
	e.Reason = redact(e.Reason, cfg.redactors)
	return e
}

// ── State ─────────────────────────────────────────────────────────────────────

type siemState struct {
	LastFailure int64 `json:"last_failure"` // unix seconds of last delivery failure
	Dropped     int64 `json:"dropped"`      // events dropped because the queue was full
	LastWarn    int64 `json:"last_warn"`    // last insecure-config warning
	LastReject  int64 `json:"last_reject"`  // last PolicyRejected event
}

// loadSIEMState treats the user-writable state file as untrusted: timestamps
// in the future (which would suppress delivery indefinitely) are ignored.
func loadSIEMState() siemState {
	var st siemState
	if data, err := os.ReadFile(siemStateFile()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	now := time.Now().Unix()
	if st.LastFailure > now || st.LastFailure < 0 {
		st.LastFailure = 0
	}
	if st.LastWarn > now || st.LastWarn < 0 {
		st.LastWarn = 0
	}
	if st.Dropped < 0 {
		st.Dropped = 0
	}
	return st
}

func saveSIEMState(st siemState) {
	data, _ := json.Marshal(st)
	_ = writeFileAtomic(siemStateFile(), data)
}

func updateSIEMState(fn func(*siemState)) {
	st := loadSIEMState()
	fn(&st)
	saveSIEMState(st)
}

func inBackoff(cfg SIEMConfig, st siemState) bool {
	return st.LastFailure > 0 &&
		time.Since(time.Unix(st.LastFailure, 0)) < time.Duration(cfg.RetryAfterSec)*time.Second
}

func writeFileAtomic(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.tmp%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := retryFS(func() error { return os.Rename(tmp, path) }); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// retryFS retries a filesystem operation that can fail transiently on Windows
// while antivirus or the indexer briefly holds the file open.
func retryFS(op func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = op(); err == nil || os.IsNotExist(err) {
			return err
		}
		time.Sleep(time.Duration(20*(i+1)) * time.Millisecond)
	}
	return err
}

// ── Hook path ─────────────────────────────────────────────────────────────────

// forwardToSIEM is called after every logEvent. It only touches local files
// and may start a detached sender; it never waits on the network.
func forwardToSIEM(entry LogEntry) {
	cfg, ok := loadSIEMConfig()
	if !ok {
		return
	}
	enqueueSIEM(prepareForSIEM(entry, cfg), cfg)
	if inBackoff(cfg, loadSIEMState()) || senderRunning() {
		return
	}
	spawnBackgroundSend()
}

// senderRunning probes the sender lock without holding it.
func senderRunning() bool {
	release, err := lockFile(siemSendLockFile(), true, true)
	if err == nil {
		release()
		return false
	}
	if !errors.Is(err, errLocked) {
		// Can't even open the lock file — a sender would fail the same way,
		// so don't spawn one per hook.
		logError("ERROR", fmt.Sprintf("SIEM send lock unusable: %v", err))
	}
	return true
}

// spawnBackgroundSend starts a detached `shellguard --send --quiet`. A variable
// so tests can stub it out (the test binary must not re-exec itself).
var spawnBackgroundSend = func() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "--send", "--quiet")
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		logError("WARN", fmt.Sprintf("failed to start background SIEM send: %v", err))
		return
	}
	_ = cmd.Process.Release()
}

func queueBytes() int64 {
	var n int64
	for _, p := range []string{siemQueueFile(), siemInflightFile()} {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// enqueueSIEM appends one entry under the shared queue lock, so the sender
// can never rotate the file between our open and write.
func enqueueSIEM(entry LogEntry, cfg SIEMConfig) {
	_ = os.MkdirAll(configDir(), 0755)
	if queueBytes() > int64(cfg.MaxQueueMB)<<20 {
		var first bool
		updateSIEMState(func(st *siemState) { first = st.Dropped == 0; st.Dropped++ })
		if first {
			logError("ERROR", fmt.Sprintf("SIEM queue exceeds %d MB — dropping events until it drains", cfg.MaxQueueMB))
		}
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	release, err := lockFile(siemQueueLockFile(), false, false)
	if err != nil {
		logError("WARN", fmt.Sprintf("SIEM queue lock failed, appending without it: %v", err))
		release = func() {}
	}
	defer release()
	f, err := os.OpenFile(siemQueueFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logError("ERROR", fmt.Sprintf("failed to open SIEM queue: %v", err))
		return
	}
	_, _ = f.Write(append(data, '\n'))
	f.Close()
}

// ── Sender ────────────────────────────────────────────────────────────────────

// runSender drains the queue while holding the sender lock, lingering for
// `linger` after the last event. Returns how many events were sent.
func runSender(cfg SIEMConfig, linger time.Duration) (int, error) {
	sent := 0
	for attempt := 0; attempt < 3; attempt++ {
		release, err := lockFile(siemSendLockFile(), true, true)
		if errors.Is(err, errLocked) {
			if attempt == 0 {
				return 0, errSendInProgress
			}
			return sent, nil // another sender took over the backlog
		}
		if err != nil {
			return sent, err
		}
		n, err := drain(cfg, linger)
		sent += n
		if err == nil {
			err = reportDropped(cfg)
		}
		release()
		if err != nil {
			updateSIEMState(func(st *siemState) { st.LastFailure = time.Now().Unix() })
			return sent, err
		}
		updateSIEMState(func(st *siemState) { st.LastFailure = 0 })
		// A hook that appended while we still held the lock did not spawn a
		// sender; it appended before probing, so this check sees its event.
		if !fileExists(siemQueueFile()) && !fileExists(siemInflightFile()) {
			break
		}
	}
	return sent, nil
}

func drain(cfg SIEMConfig, linger time.Duration) (int, error) {
	sent := 0
	idleSince := time.Now()
	for {
		n, err := drainOnce(cfg)
		sent += n
		if err != nil {
			return sent, err
		}
		if n > 0 {
			idleSince = time.Now()
		}
		if time.Since(idleSince) >= linger {
			return sent, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// drainOnce ships siem_queue.sending (resuming at the checkpoint) and then
// rotates and ships siem_queue.log until both are empty.
func drainOnce(cfg SIEMConfig) (int, error) {
	sent := 0
	for {
		if !fileExists(siemInflightFile()) {
			rotated, err := rotateQueue()
			if err != nil || !rotated {
				return sent, err
			}
		}
		n, err := sendInflight(cfg)
		sent += n
		if err != nil {
			return sent, err
		}
		if err := clearInflight(); err != nil {
			return sent, err
		}
	}
}

func rotateQueue() (bool, error) {
	release, err := lockFile(siemQueueLockFile(), true, false)
	if err != nil {
		return false, err
	}
	defer release()
	if !fileExists(siemQueueFile()) {
		return false, nil
	}
	if err := writeOffset(0); err != nil {
		return false, err
	}
	if err := retryFS(func() error { return os.Rename(siemQueueFile(), siemInflightFile()) }); err != nil {
		return false, err
	}
	return true, nil
}

// clearInflight removes a fully sent file. If removal keeps failing it is
// truncated instead, and the run stops, so the same events are never resent.
func clearInflight() error {
	err := retryFS(func() error { return os.Remove(siemInflightFile()) })
	if err != nil && !os.IsNotExist(err) {
		if terr := os.Truncate(siemInflightFile(), 0); terr != nil {
			return fmt.Errorf("cannot remove sent queue file: %w", err)
		}
		_ = writeOffset(0)
		return fmt.Errorf("sent queue file truncated but not removed: %w", err)
	}
	_ = os.Remove(siemOffsetFile())
	return nil
}

func readOffset() int64 {
	data, err := os.ReadFile(siemOffsetFile())
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func writeOffset(n int64) error {
	return writeFileAtomic(siemOffsetFile(), []byte(strconv.FormatInt(n, 10)))
}

// readQueueLine reads one '\n'-terminated line. Lines longer than limit are
// consumed and returned as nil so one bad record can't wedge the queue.
func readQueueLine(r *bufio.Reader, limit int) (line []byte, consumed int, err error) {
	var buf []byte
	tooLong := false
	for {
		chunk, e := r.ReadSlice('\n')
		consumed += len(chunk)
		if !tooLong {
			if len(buf)+len(chunk) > limit {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(e, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return nil, consumed, e
		}
		return bytes.TrimRight(buf, "\r\n"), consumed, e
	}
}

// sendInflight streams siem_queue.sending from the saved offset, sending in
// batches and checkpointing after each one.
func sendInflight(cfg SIEMConfig) (int, error) {
	f, err := os.Open(siemInflightFile())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	pos := readOffset()
	if fi, err := f.Stat(); err == nil && pos > fi.Size() {
		pos = 0
	}
	if _, err := f.Seek(pos, io.SeekStart); err != nil {
		return 0, err
	}

	sent, skipped := 0, 0
	var batch []LogEntry
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := sendSIEM(cfg, batch); err != nil {
			return err
		}
		sent += len(batch)
		batch = batch[:0]
		return writeOffset(pos)
	}

	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, n, rerr := readQueueLine(r, maxQueueLine)
		if n == 0 && rerr == io.EOF {
			break
		}
		pos += int64(n)
		var e LogEntry
		switch {
		case line == nil:
			skipped++
		case len(line) == 0:
		case json.Unmarshal(line, &e) != nil:
			skipped++
		default:
			batch = append(batch, e)
		}
		if len(batch) >= sendBatch {
			if err := flush(); err != nil {
				return sent, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return sent, rerr
		}
	}
	if skipped > 0 {
		logError("WARN", fmt.Sprintf("skipped %d corrupt or oversized SIEM queue line(s)", skipped))
	}
	return sent, flush()
}

// reportDropped tells the SIEM how many events were lost to a full queue.
func reportDropped(cfg SIEMConfig) error {
	st := loadSIEMState()
	if st.Dropped == 0 {
		return nil
	}
	if err := sendSIEM(cfg, []LogEntry{systemEvent("dropped", fmt.Sprintf("dropped=%d max_queue_mb=%d", st.Dropped, cfg.MaxQueueMB))}); err != nil {
		return err
	}
	n := st.Dropped
	updateSIEMState(func(st *siemState) { st.Dropped = max(st.Dropped-n, 0) })
	return nil
}

func systemEvent(kind, reason string) LogEntry {
	return LogEntry{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.999999"),
		Reason:    reason,
		User:      currentUser(),
		Process:   "shellguard",
		PID:       strconv.Itoa(os.Getpid()),
		Type:      kind,
	}
}

func countQueued() int {
	n := 0
	for i, p := range []string{siemInflightFile(), siemQueueFile()} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if i == 0 {
			_, _ = f.Seek(readOffset(), io.SeekStart)
		}
		buf := make([]byte, 64<<10)
		for {
			k, err := f.Read(buf)
			n += bytes.Count(buf[:k], []byte{'\n'})
			if err != nil {
				break
			}
		}
		f.Close()
	}
	return n
}

// warnInsecure logs weak transport settings at most once a day.
func warnInsecure(cfg SIEMConfig) {
	var msgs []string
	if cfg.Protocol != "tls" && !strings.HasPrefix(strings.ToLower(cfg.URL), "https://") {
		if ip := net.ParseIP(cfg.Host); ip == nil || !ip.IsLoopback() {
			msgs = append(msgs, fmt.Sprintf("events are sent to %s in plaintext over %s — use protocol: tls", cfg.Host, cfg.Protocol))
		}
	}
	if cfg.TLSSkipVerify {
		msgs = append(msgs, "tls_skip_verify is on — the SIEM's certificate is not checked")
	}
	if len(msgs) == 0 {
		return
	}
	st := loadSIEMState()
	if time.Since(time.Unix(st.LastWarn, 0)) < 24*time.Hour {
		return
	}
	for _, m := range msgs {
		logError("WARN", "SIEM: "+m)
	}
	updateSIEMState(func(st *siemState) { st.LastWarn = time.Now().Unix() })
}

// ── Transport ─────────────────────────────────────────────────────────────────

// sendSIEM opens one connection and writes every entry as a syslog line.
func sendSIEM(cfg SIEMConfig, entries []LogEntry) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

	var conn net.Conn
	var err error
	switch cfg.Protocol {
	case "https":
		return sendHTTP(cfg, entries)
	case "tls":
		tlsCfg, terr := siemTLSConfig(cfg)
		if terr != nil {
			return terr
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsCfg)
	default:
		conn, err = net.DialTimeout(cfg.Protocol, addr, timeout)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	hostname := syslogHostname()
	w := bufio.NewWriter(conn)
	for _, e := range entries {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		// Newline-terminated framing — accepted by QRadar for both TCP and UDP.
		if _, err := w.WriteString(formatSyslog(cfg, e, hostname) + "\n"); err != nil {
			return err
		}
		if cfg.Protocol == "udp" {
			if err := w.Flush(); err != nil { // one datagram per event
				return err
			}
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := w.Flush(); err != nil {
		return err
	}
	return confirmClose(conn)
}

// siemTLSConfig builds the client TLS config (custom CA, optional mTLS).
func siemTLSConfig(cfg SIEMConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify, MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file contains no valid certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// sendHTTP posts the batch in one request: Splunk HEC envelopes ("hec") or
// newline-delimited JSON ("json"). Any 2xx status counts as delivered.
func sendHTTP(cfg SIEMConfig, entries []LogEntry) error {
	tlsCfg, err := siemTLSConfig(cfg)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutMs) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}
	hostname := syslogHostname()
	var body bytes.Buffer
	for _, e := range entries {
		body.WriteString(fitMessage(cfg.MaxMessageBytes, e, func(e LogEntry) string {
			if cfg.Format == "hec" {
				return formatHEC(e, hostname)
			}
			return formatJSON(e, hostname)
		}))
		body.WriteByte('\n')
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ShellGuard/"+appVersion)
	if cfg.Token != "" {
		scheme := "Bearer "
		if cfg.Format == "hec" {
			scheme = "Splunk "
		}
		req.Header.Set("Authorization", scheme+cfg.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("SIEM HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// confirmClose half-closes a stream connection and briefly waits for the peer,
// so a reset (SIEM died or refused the data) is reported as a failure. A quiet
// or orderly close counts as success — syslog has no real acknowledgement.
func confirmClose(conn net.Conn) error {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	if err := cw.CloseWrite(); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := io.Copy(io.Discard, conn)
	if err == nil || isTimeout(err) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	if isConnReset(err) {
		return err
	}
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ── Formatting ────────────────────────────────────────────────────────────────

// syslogHostname returns a header-safe hostname (no spaces, never empty).
func syslogHostname() string {
	h, _ := os.Hostname()
	h = strings.Join(strings.Fields(h), "")
	if h == "" {
		return "localhost"
	}
	return h
}

// formatSyslog builds an RFC 3164 syslog line carrying a LEEF 1.0 (or JSON)
// payload, truncating the command so the line fits in max_message_bytes.
func formatSyslog(cfg SIEMConfig, e LogEntry, hostname string) string {
	t, err := time.ParseInLocation("2006-01-02T15:04:05.999999", e.Timestamp, time.UTC)
	if err != nil {
		t = time.Now().UTC()
	}
	// facility user(1); severity warning(4) for blocked/dropped, informational(6) otherwise
	pri := 1*8 + 6
	if e.Blocked || e.Type == "dropped" || e.Type == "policy_rejected" {
		pri = 1*8 + 4
	}
	// RFC 3164 timestamps are local time without a zone; LEEF/CEF carry the zone.
	header := fmt.Sprintf("<%d>%s %s ShellGuard: ", pri, t.Local().Format(time.Stamp), hostname)

	return fitMessage(cfg.MaxMessageBytes, e, func(e LogEntry) string {
		switch cfg.Format {
		case "json":
			return header + formatJSON(e, hostname)
		case "cef":
			return header + formatCEF(e, t, hostname)
		}
		return header + formatLEEF(e, t)
	})
}

// fitMessage renders e, truncating the command (then the reason) so the
// result fits in max bytes.
func fitMessage(maxBytes int, e LogEntry, render func(LogEntry) string) string {
	line := render(e)
	if over := len(line) - maxBytes; over > 0 {
		const marker = "…[truncated]"
		keep := len(e.Command) - over - len(marker) - 16 // headroom for escaping
		e.Command = truncateBytes(e.Command, max(keep, 0)) + marker
		line = render(e)
		if len(line) > maxBytes {
			e.Reason = truncateBytes(e.Reason, 64)
			line = truncateBytes(render(e), maxBytes)
		}
	}
	return line
}

// truncateBytes cuts s to at most n bytes without splitting a UTF-8 rune.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func eventID(e LogEntry) string {
	switch {
	case e.Blocked:
		return "CommandBlocked"
	case e.Type == "execution":
		return "CommandExecuted"
	case e.Type == "heartbeat":
		return "Heartbeat"
	case e.Type == "dropped":
		return "EventsDropped"
	case e.Type == "policy_rejected":
		return "PolicyRejected"
	default:
		return "CommandAllowed"
	}
}

func formatLEEF(e LogEntry, t time.Time) string {
	sev, action := "3", "allowed"
	switch {
	case e.Blocked:
		sev, action = "7", "blocked"
	case e.Type == "dropped":
		sev, action = "8", "dropped"
	case e.Type == "policy_rejected":
		sev, action = "9", "policy_rejected"
	case e.Type == "heartbeat":
		sev, action = "1", "heartbeat"
	}
	fields := [][2]string{
		{"devTime", t.UTC().Format("2006-01-02T15:04:05.000-0700")},
		{"devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
		{"cat", e.Type},
		{"sev", sev},
		{"action", action},
		{"usrName", e.User},
		{"process", e.Process},
		{"pid", e.PID},
		{"command", e.Command},
		{"reason", e.Reason},
	}
	var b strings.Builder
	fmt.Fprintf(&b, "LEEF:1.0|S4E|ShellGuard|%s|%s|", appVersion, eventID(e))
	for i, f := range fields {
		if i > 0 {
			b.WriteByte('\t')
		}
		b.WriteString(f[0])
		b.WriteByte('=')
		b.WriteString(leefEscape(f[1]))
	}
	return b.String()
}

// jsonEvent is the JSON / HEC event body: the activity.log fields plus the
// event ID and host, so every format carries the same information.
type jsonEvent struct {
	LogEntry
	Event string `json:"event_id"`
	Host  string `json:"host"`
}

func formatJSON(e LogEntry, hostname string) string {
	data, _ := json.Marshal(jsonEvent{e, eventID(e), hostname})
	return string(data)
}

// formatHEC builds one Splunk HTTP Event Collector envelope.
func formatHEC(e LogEntry, hostname string) string {
	t, err := time.ParseInLocation("2006-01-02T15:04:05.999999", e.Timestamp, time.UTC)
	if err != nil {
		t = time.Now().UTC()
	}
	data, _ := json.Marshal(map[string]any{
		"time":       float64(t.UnixMilli()) / 1000,
		"host":       hostname,
		"source":     "shellguard",
		"sourcetype": "shellguard:activity",
		"event":      jsonEvent{e, eventID(e), hostname},
	})
	return string(data)
}

// formatCEF builds an ArcSight CEF:0 payload (Sentinel, ArcSight, Splunk, …).
func formatCEF(e LogEntry, t time.Time, hostname string) string {
	sev, action := "3", "allowed"
	switch {
	case e.Blocked:
		sev, action = "7", "blocked"
	case e.Type == "dropped":
		sev, action = "8", "dropped"
	case e.Type == "policy_rejected":
		sev, action = "9", "policy_rejected"
	case e.Type == "heartbeat":
		sev, action = "1", "heartbeat"
	}
	names := map[string]string{
		"CommandBlocked": "Command blocked", "CommandExecuted": "Command executed",
		"CommandAllowed": "Command allowed", "Heartbeat": "Heartbeat", "EventsDropped": "Events dropped",
		"PolicyRejected": "Managed policy rejected",
	}
	id := eventID(e)
	ext := [][2]string{
		{"rt", strconv.FormatInt(t.UnixMilli(), 10)},
		{"dvchost", hostname},
		{"act", action},
		{"cat", e.Type},
		{"suser", e.User},
		{"sproc", e.Process},
		{"spid", e.PID},
		{"cs1Label", "command"},
		{"cs1", e.Command},
		{"msg", e.Reason},
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|S4E|ShellGuard|%s|%s|%s|%s|", appVersion, id, cefHeaderEscape(names[id]), sev)
	for i, f := range ext {
		if f[1] == "" {
			continue
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f[0])
		b.WriteByte('=')
		b.WriteString(cefValueEscape(f[1]))
	}
	return strings.TrimRight(b.String(), " ")
}

// cefHeaderEscape escapes CEF header fields (backslash and pipe).
func cefHeaderEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(leefEscape(s))
}

// cefValueEscape escapes CEF extension values (backslash and equals) after
// replacing control characters, so a value can never start a new key.
func cefValueEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`).Replace(leefEscape(s))
}

// leefEscape replaces every control character (including tab, the attribute
// delimiter, NUL and ANSI escapes) and Unicode line separators with a space.
func leefEscape(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}

// ── CLI ───────────────────────────────────────────────────────────────────────

// sendMode implements `shellguard --send` (manual / cron: drain, then send a
// heartbeat) and `--send --quiet` (background sender started by hooks).
func sendMode(args []string) {
	quiet := len(args) > 0 && args[0] == "--quiet"
	cfg, ok := loadSIEMConfig()
	if !ok {
		if !quiet {
			fmt.Fprintf(os.Stderr, "[ShellGuard] SIEM forwarding is not enabled (%s)\n", siemConfigFile())
		}
		os.Exit(1)
	}
	warnInsecure(cfg)

	linger := time.Duration(0)
	if quiet {
		linger = time.Duration(cfg.LingerSec) * time.Second
	}
	sent, err := runSender(cfg, linger)
	if errors.Is(err, errSendInProgress) {
		if !quiet {
			fmt.Println("[ShellGuard] Another SIEM send is already running.")
		}
		return
	}
	if err != nil {
		remaining := countQueued()
		logError("WARN", fmt.Sprintf("SIEM send failed: %v (sent %d, %d still queued)", err, sent, remaining))
		if !quiet {
			fmt.Fprintf(os.Stderr, "[ShellGuard] SIEM send failed: %v (sent %d, %d still queued)\n", err, sent, remaining)
		}
		os.Exit(1)
	}
	if quiet {
		return
	}
	// Heartbeat: lets the SIEM alert when a host goes silent (agent removed
	// the hooks, deleted the queue, …). Schedule `shellguard --send` to use it.
	hb := systemEvent("heartbeat", fmt.Sprintf("queued=%d dropped=%d", countQueued(), loadSIEMState().Dropped))
	if err := sendSIEM(cfg, []LogEntry{hb}); err != nil {
		fmt.Fprintf(os.Stderr, "[ShellGuard] SIEM heartbeat failed: %v\n", err)
		os.Exit(1)
	}
	if sent == 0 {
		fmt.Println("[ShellGuard] SIEM queue is empty; heartbeat sent.")
		return
	}
	fmt.Printf("[ShellGuard] Sent %d queued event(s) and a heartbeat to SIEM.\n", sent)
}
