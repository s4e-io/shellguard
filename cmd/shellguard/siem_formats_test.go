package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFormatCEF(t *testing.T) {
	cfg := SIEMConfig{Format: "cef", MaxMessageBytes: 4096}
	e := sampleEntry(`rm -rf a=b c\d|e`+"\nx\x1b[31m", true)
	line := formatSyslog(cfg, e, "host1")
	if !strings.Contains(line, " ShellGuard: CEF:0|S4E|ShellGuard|"+appVersion+"|CommandBlocked|Command blocked|7|") {
		t.Errorf("unexpected header: %q", line)
	}
	if !strings.Contains(line, `cs1Label=command cs1=rm -rf a\=b c\\d|e x [31m`) {
		t.Errorf("extension value not escaped: %q", line)
	}
	if !strings.Contains(line, "rt=1793613600123 ") || !strings.Contains(line, " suser=alice ") || !strings.Contains(line, " act=blocked ") {
		t.Errorf("missing fields: %q", line)
	}
	if strings.ContainsAny(line, "\n\x1b") {
		t.Errorf("control characters kept: %q", line)
	}
}

func TestFormatSyslog_CEFAndJSONTruncate(t *testing.T) {
	long := strings.Repeat("ğ=", 3000)
	for _, format := range []string{"cef", "json"} {
		line := formatSyslog(SIEMConfig{Format: format, MaxMessageBytes: 2048}, sampleEntry(long, false), "h")
		if len(line) > 2048 || !utf8.ValidString(line) || !strings.Contains(line, "…[truncated]") {
			t.Errorf("%s: bad truncation (%d bytes)", format, len(line))
		}
	}
}

func TestFormatJSON_CarriesEventIDAndHost(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(formatJSON(sampleEntry("ls", true), "h1")), &m); err != nil {
		t.Fatal(err)
	}
	if m["event_id"] != "CommandBlocked" || m["host"] != "h1" || m["command"] != "ls" || m["blocked"] != true {
		t.Errorf("unexpected json: %v", m)
	}
}

func TestLoadSIEMConfig_HTTPS(t *testing.T) {
	isolateConfig(t)
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(configDir(), "siem.yaml"), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("enabled: true\nprotocol: https\n")
	if _, ok := loadSIEMConfig(); ok {
		t.Error("https without url must stay disabled")
	}
	write("enabled: true\nprotocol: https\nurl: https://splunk.corp:8088/services/collector/event\nformat: hec\ntoken: t\n")
	c, ok := loadSIEMConfig()
	if !ok || c.Host != "splunk.corp" || c.Format != "hec" || c.MaxMessageBytes != 16<<10 {
		t.Errorf("unexpected config: %+v ok=%v", c, ok)
	}
	write("enabled: true\nhost: q\nformat: hec\n")
	if c, _ := loadSIEMConfig(); c.Format != "leef" {
		t.Errorf("hec over syslog must fall back to leef, got %q", c.Format)
	}
}

// hecServer is a fake Splunk HEC endpoint. It fails while down is set.
type hecServer struct {
	mu     sync.Mutex
	events []map[string]any
	auth   []string
	down   atomic.Bool
}

func (h *hecServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.down.Load() {
		http.Error(w, `{"text":"Server is busy","code":9}`, http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.auth = append(h.auth, r.Header.Get("Authorization"))
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			h.events = append(h.events, m)
		}
	}
	_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
}

func (h *hecServer) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, e := range h.events {
		if ev, ok := e["event"].(map[string]any); ok {
			out = append(out, ev["command"].(string))
		}
	}
	return out
}

func TestRunSender_HECOutageThenRecovery(t *testing.T) {
	isolateConfig(t)
	srv := &hecServer{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	cfgText := "enabled: true\nprotocol: https\nformat: hec\ntoken: abc\ntimeout_ms: 2000\nurl: " + ts.URL + "/services/collector/event\n"
	if err := os.WriteFile(filepath.Join(configDir(), "siem.yaml"), []byte(cfgText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, ok := loadSIEMConfig()
	if !ok {
		t.Fatal("config not enabled")
	}

	srv.down.Store(true)
	for i := range 250 {
		enqueueSIEM(sampleEntry("cmd"+strconv.Itoa(i), false), cfg)
	}
	if _, err := runSender(cfg, 0); err == nil {
		t.Fatal("want error while HEC is down")
	}
	srv.down.Store(false)
	if n, err := runSender(cfg, 0); err != nil || n != 250 {
		t.Fatalf("sent %d, err %v", n, err)
	}
	got := srv.commands()
	if len(got) != 250 || got[0] != "cmd0" || got[249] != "cmd249" {
		t.Fatalf("got %d events, first/last wrong: %v", len(got), got[:min(3, len(got))])
	}
	if srv.auth[0] != "Splunk abc" {
		t.Errorf("auth header %q", srv.auth[0])
	}
	ev := srv.events[0]
	if ev["sourcetype"] != "shellguard:activity" || ev["time"] == nil {
		t.Errorf("bad HEC envelope: %v", ev)
	}
	if countQueued() != 0 {
		t.Error("queue not empty after delivery")
	}
}

func TestSendHTTP_JSONBearer(t *testing.T) {
	var auth, ctype string
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ctype = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
	}))
	defer ts.Close()
	cfg := SIEMConfig{Protocol: "https", Format: "json", URL: ts.URL, Token: "tok", TimeoutMs: 2000, MaxMessageBytes: 16 << 10}
	if err := sendSIEM(cfg, []LogEntry{sampleEntry("a", false), sampleEntry("b", true)}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if auth != "Bearer tok" || ctype != "application/json" || len(lines) != 2 || !strings.Contains(lines[1], `"event_id":"CommandBlocked"`) {
		t.Errorf("auth=%q ctype=%q body=%s", auth, ctype, body)
	}
}

func TestSendHTTP_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer ts.Close()
	cfg := SIEMConfig{Protocol: "https", Format: "json", URL: ts.URL, TimeoutMs: 100, MaxMessageBytes: 4096}
	if err := sendSIEM(cfg, []LogEntry{sampleEntry("a", false)}); err == nil {
		t.Error("want timeout error")
	}
}
