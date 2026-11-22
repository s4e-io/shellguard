package main

import (
	"encoding/json"
	"testing"
)

// Payload shapes taken from each tool's hook documentation.
func TestExtractHookFields_ToolPayloads(t *testing.T) {
	cases := []struct {
		name, payload                   string
		command, kind, process, respFmt string
	}{
		{"cursor before (current docs)",
			`{"hook_event_name":"beforeShellExecution","command":"curl x","cwd":"C:\\p","conversation_id":"c1","generation_id":"g","cursor_version":"2.1"}`,
			"curl x", "pre", "cursor", "cursor"},
		{"cursor after",
			`{"hook_event_name":"afterShellExecution","command":"ls","conversation_id":"c1","cursor_version":"2.1"}`,
			"ls", "post", "cursor", "cursor"},
		{"copilot PascalCase, tool_input as JSON string",
			`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"powershell","tool_input":"{\"command\":\"Remove-Item x\"}"}`,
			"Remove-Item x", "pre", "claude", "exitcode"},
		{"copilot camelCase",
			`{"sessionId":"s","toolName":"bash","toolArgs":{"command":"git push"}}`,
			"git push", "unknown", "unknown", "exitcode"},
		{"vscode run_in_terminal",
			`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"run_in_terminal","tool_input":{"command":"npm i","explanation":"x"}}`,
			"npm i", "pre", "claude", "exitcode"},
		{"junie",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"dir"}}`,
			"dir", "pre", "unknown", "exitcode"},
	}
	for _, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.payload), &m); err != nil {
			t.Fatalf("%s: bad payload: %v", c.name, err)
		}
		f, ok := extractHookFields(m)
		if !ok {
			t.Errorf("%s: filtered out", c.name)
			continue
		}
		if f.command != c.command || f.eventKind != c.kind || f.process != c.process || f.responseFormat != c.respFmt {
			t.Errorf("%s: got command=%q kind=%q process=%q fmt=%q", c.name, f.command, f.eventKind, f.process, f.responseFormat)
		}
	}
}

func TestExtractHookFields_NonShellToolIgnored(t *testing.T) {
	m := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "read_file", "tool_input": map[string]any{"path": "x"}}
	if _, ok := extractHookFields(m); ok {
		t.Error("read_file should be ignored")
	}
}
