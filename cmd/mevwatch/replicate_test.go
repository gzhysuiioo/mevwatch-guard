package main

import (
	"bytes"
	"encoding/json"
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

func TestCLIApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [{"index": 1, "term": 1, "command": "set x=1"}],
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "entries": [
	      {"index": 2, "term": 1, "command": "set y=a b=c"},
	      {"index": 3, "term": 1, "command": "delete x"}
	    ], "leaderCommit": 3}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, fragment := range []string{
		`"appliedIndex": 3`,
		`"applyError": null`,
		`"finalAppliedIndex": 3`,
		`"finalApplyError": null`,
		`"y": "a b=c"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
	if strings.Contains(body, `"x"`) {
		t.Fatalf("deleted key must not appear in finalKV:\n%s", body)
	}

	// 相同输入必须得到相同输出。
	var again bytes.Buffer
	if code := runReplicateIO(strings.NewReader(input), &again, &stderr); code != 0 {
		t.Fatalf("second run exit code = %d", code)
	}
	if again.String() != body {
		t.Fatalf("non-deterministic output:\n%s\n%s", body, again.String())
	}
}

func TestCLIApplyKVFormatError(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
	      {"index": 1, "term": 1, "command": "set ok=1"},
	      {"index": 2, "term": 1, "command": "set broken"}
	    ], "leaderCommit": 2}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, fragment := range []string{
		`"accepted": true`,
		`"appliedIndex": 1`,
		`"index": 2`,
		`"finalAppliedIndex": 1`,
		`"ok": "1"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
}

func TestCLIApplyKVOmittedKeepsOutputShape(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [{"index": 1, "term": 1, "command": "set x=1"}],
	  "requests": []
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV omitted: output must not contain %q:\n%s", field, body)
		}
	}
}

func TestCLIOverflowEntryIndexIsFieldError(t *testing.T) {
	// prevLogIndex 取 int 最大值、首条真实条目索引以最小负值给出（恰好是
	// 回绕后的位置）：必须按字段错误拒绝且不抬高任期，随后的合法追加正常接受。
	input := `{
	  "currentTerm": 2,
	  "committedIndex": 1,
	  "log": [{"index": 1, "term": 2, "command": "a"}],
	  "requests": [
	    {"term": 9, "prevLogIndex": 9223372036854775807, "prevLogTerm": 0,
	     "entries": [{"index": -9223372036854775808, "term": 9, "command": "evil"}],
	     "leaderCommit": 0},
	    {"term": 3, "prevLogIndex": 1, "prevLogTerm": 2,
	     "entries": [{"index": 2, "term": 3, "command": "b"}],
	     "leaderCommit": 2}
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
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "not consecutive") {
		t.Fatalf("first request should be an index-gap field error, got %+v", out.Results[0])
	}
	if out.Results[0].Term != 2 {
		t.Fatalf("field error must not bump term, got %d", out.Results[0].Term)
	}
	if !out.Results[1].Accepted {
		t.Fatalf("valid follow-up request rejected: %+v", out.Results[1])
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("unexpected final state: %+v", out)
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
