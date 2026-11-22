package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestRedact_MoreFormats(t *testing.T) {
	cases := []struct{ in, want string }{
		{`sshpass -p 'Examp1ePassw0rd' ssh root@192.0.2.10`, `sshpass -p [REDACTED] ssh root@192.0.2.10`},
		{`sshpass -p hunter2 scp a b:`, `sshpass -p [REDACTED] scp a b:`},
		{`SSHPASS=hunter2 sshpass -e ssh host`, `SSHPASS=[REDACTED] sshpass -e ssh host`},
		{`curl -U 'svc_user:Not-Real-Pass!1' https://h`, `curl -U 'svc_user:[REDACTED]' https://h`},
		{`curl -u admin:s3cret https://h`, `curl -u admin:[REDACTED] https://h`},
		{`curl --user=bob:pw https://h`, `curl --user=bob:[REDACTED] https://h`},
		{`curl -H "X-Api-Key: abcd1234" https://h`, `curl -H "X-Api-Key: [REDACTED]" https://h`},
		{`echo Bearer abcdefghijkl`, `echo Bearer [REDACTED]`},
		{`curl -d '{"user":"a","password":"p4ss"}' h`, `curl -d '{"user":"a","password":"[REDACTED]"}' h`},
		{`echo eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4fw`, `echo [REDACTED]`},
		{`deploy --key EXAMPLEkeyEXAMPLEkey1234`, `deploy --key EXAMPLEkeyEXAMPLEkey1234`[:13] + `[REDACTED]`},
		{`export APP_PW='Examp1ePassw0rd'; run`, `export APP_PW=[REDACTED]; run`},
		{`s=Session(url, auth=('deploy','Examp1ePassw0rd'))`, `s=Session(url, auth=('deploy','[REDACTED]'))`},
		{`xfreerdp /v:192.0.2.10 /u:alice /p:'x y' /cert:ignore`, `xfreerdp /v:192.0.2.10 /u:alice /p:[REDACTED] /cert:ignore`},
		{`PXU='svc_user:Not-Real-Pass!1'`, `PXU='svc_user:[REDACTED]'`},
		{`TOK='deploy_bot:EXAMPLEexampleEXAMPLEexample0000'`, `TOK='deploy_bot:[REDACTED]'`},
		{"- User: alice\n- Pass: Examp1ePassw0rd\n", "- User: alice\n- Pass: [REDACTED]\n"},
		// left alone
		{`git push -u origin main`, `git push -u origin main`},
		{`docker run -p 8080:80 nginx`, `docker run -p 8080:80 nginx`},
		{`git show 3b9f0d6c1e8a47b2c5d0e9f13a7b6c48d2e1f05a`, `git show 3b9f0d6c1e8a47b2c5d0e9f13a7b6c48d2e1f05a`},
		{`cat /Users/alice/projects/ShellGuardSetupAmd64Build2026/x`, `cat /Users/alice/projects/ShellGuardSetupAmd64Build2026/x`},
		{`go test ./... -run TestManagedStateOverridesUser`, `go test ./... -run TestManagedStateOverridesUser`},
	}
	for _, c := range cases {
		if got := redact(c.in, defaultRedactors); got != c.want {
			t.Errorf("redact(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestLogEvent_RedactsAndIsPrivate(t *testing.T) {
	isolateConfig(t)
	// A log created by an older version or the Mac app, readable by everyone.
	if err := os.WriteFile(activityLogFile(), []byte(`{"command":"old"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logEvent(sampleEntry("sshpass -p hunter2 ssh root@host", false))

	data, _ := os.ReadFile(activityLogFile())
	if strings.Contains(string(data), "hunter2") || !strings.Contains(string(data), "sshpass -p [REDACTED]") {
		t.Errorf("activity.log not redacted:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(activityLogFile())
		if st.Mode().Perm() != 0o600 {
			t.Errorf("activity.log mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestLogEvent_CapsHugeCommand(t *testing.T) {
	isolateConfig(t)
	logEvent(sampleEntry("echo "+strings.Repeat("a", 5<<20), false))
	st, _ := os.Stat(activityLogFile())
	if st.Size() > maxLoggedField+4096 {
		t.Errorf("activity.log line is %d bytes", st.Size())
	}
}

func TestRedactLogLine_KeepsOtherFields(t *testing.T) {
	in := `{"command":"export GITHUB_TOKEN=ghp_x","reason":"","user":"alice","pid":"1","blocked":true,"extra":"kept"}`
	out, did := redactLogLine(in)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil || !did {
		t.Fatal(err, did)
	}
	if m["command"] != "export GITHUB_TOKEN=[REDACTED]" || m["user"] != "alice" || m["blocked"] != true || m["extra"] != "kept" {
		t.Errorf("got %v", m)
	}
	clean := `{"command":"git status","user":"alice"}`
	if got, did := redactLogLine(clean); got != clean || did {
		t.Errorf("clean line rewritten: %q", got)
	}
	if got, _ := redactLogLine("not json --password x"); got != "not json --password [REDACTED]" {
		t.Errorf("plain line: %q", got)
	}
}
