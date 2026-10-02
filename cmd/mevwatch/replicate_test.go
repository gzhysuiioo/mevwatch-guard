package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

func TestCLISuccess(t *testing.T) {
	input := `{
	  "currentTerm": 2,
	  "committedIndex": 1,
	  "log": [{"index": 1, "term": 2, "command": "a"}],
	  "requests": [
	    {"term": 2, "prevLogIndex": 1, "prevLogTerm": 2, "entries": [
	      {"index": 2, "term": 2, "command": "b"}
	    ], "leaderCommit": 2}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(out.Results) != 1 || !out.Results[0].Accepted {
		t.Fatalf("unexpected results: %+v", out.Results)
	}
	if out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("unexpected final state: %+v", out)
	}
}

func TestCLIEmptyInput(t *testing.T) {
	// 无请求、无日志：输出可解析，results 为空数组而不是 null。
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(`{}`), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := strings.TrimSpace(stdout.String())
	if !strings.Contains(body, `"results": []`) {
		t.Fatalf("empty results should serialize as [], got: %s", body)
	}
	if !strings.Contains(body, `"finalLog": []`) {
		t.Fatalf("empty log should serialize as [], got: %s", body)
	}
}

func TestCLIErrors(t *testing.T) {
	cases := []string{
		`not json`,
		`{"currentTerm": 2, "committedIndex": 9, "log": [], "requests": []}`,
		`{"currentTerm": 0, "log": [{"index": 1, "term": 2, "command": "a"}]}`,
	}
	for _, input := range cases {
		var stdout, stderr bytes.Buffer
		code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("input %q: exit code = %d, want 1", input, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("input %q: unexpected stdout on error: %s", input, stdout.String())
		}
		if !strings.Contains(stderr.String(), "replicate:") {
			t.Fatalf("input %q: error message missing prefix: %s", input, stderr.String())
		}
	}
}

func TestCLIApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [{"index": 1, "term": 1, "command": "set a=1"}],
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 3,
	     "entries": [
	       {"index": 2, "term": 1, "command": "set b=two words"},
	       {"index": 3, "term": 1, "command": "delete a"}
	     ]}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if out.FinalAppliedIndex != 3 || out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply state: idx=%d err=%+v", out.FinalAppliedIndex, out.FinalApplyError)
	}
	want := map[string]string{"b": "two words"}
	if !reflect.DeepEqual(out.FinalKV, want) {
		t.Fatalf("finalKV = %+v, want %+v", out.FinalKV, want)
	}
	if len(out.Results) != 1 || out.Results[0].AppliedIndex != 3 || out.Results[0].ApplyError != nil {
		t.Fatalf("unexpected per-request apply state: %+v", out.Results)
	}
}

func TestCLIApplyKVDisabledOmitsFields(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "not a kv command"}]}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, field := range []string{"appliedIndex", "applyError", "finalKV", "finalAppliedIndex", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("output contains %q when applyKV omitted: %s", field, body)
		}
	}
}

func TestCLIApplyKVErrorExitCodeUnchanged(t *testing.T) {
	// 已提交命令格式错误不改变退出码：复制成功与应用失败分别表达。
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "applyKV": true,
	  "log": [{"index": 1, "term": 1, "command": "bad"}],
	  "requests": []
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 even with apply error; stderr=%s", code, stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 {
		t.Fatalf("expected apply error at index 1, got %+v", out.FinalApplyError)
	}
}

func TestHelpMentionsApplyKV(t *testing.T) {
	// replicateHelp writes to os.Stdout; capture via a pipe.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	commandHelp("replicate")
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	help := buf.String()
	for _, fragment := range []string{"applyKV", "set <key>=<value>", "delete <key>", "appliedIndex", "finalKV"} {
		if !strings.Contains(help, fragment) {
			t.Fatalf("help text missing %q", fragment)
		}
	}
}
