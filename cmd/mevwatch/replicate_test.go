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

// applyKV 下同索引同任期但命令不同的冲突：整条请求原子拒绝，日志与键值表
// 不留部分效果，较高任期按规则保留。
func TestCLIApplyKVSameTermCommandConflict(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "set balance=10"},
	    {"index": 2, "term": 1, "command": "set balance=20"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
	      {"index": 1, "term": 1, "command": "set balance=10"},
	      {"index": 2, "term": 1, "command": "set balance=999"},
	      {"index": 3, "term": 2, "command": "set receipt=ok"}
	    ], "leaderCommit": 3}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("replication rejection is normal output, stderr must be empty, got %q", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("expected same-term command conflict rejection, got %+v", result)
	}
	if result.Term != 2 {
		t.Fatalf("higher term must survive the rejection, got %d", result.Term)
	}
	if result.CommittedIndex != 1 {
		t.Fatalf("rejection must not move committedIndex, got %d", result.CommittedIndex)
	}
	if result.Conflict != nil {
		t.Fatalf("command conflict must not carry a prev-log-mismatch hint: %+v", result.Conflict)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 1 {
		t.Fatalf("appliedIndex should stay at 1, got %+v", result.AppliedIndex)
	}
	if result.ApplyError != nil {
		t.Fatalf("rejected commands must not produce an applyError: %+v", result.ApplyError)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if len(out.FinalLog) != 2 ||
		out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "set balance=10"}) ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 1, Command: "set balance=20"}) {
		t.Fatalf("final log must be the original two entries, got %+v", out.FinalLog)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["balance"] != "10" {
		t.Fatalf("conflicting command and new entry must leave no trace, finalKV=%v", out.FinalKV)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 || out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply state: appliedIndex=%+v applyError=%+v", out.FinalAppliedIndex, out.FinalApplyError)
	}
	if strings.Contains(stdout.String(), `"conflict"`) {
		t.Fatalf("output must not contain a conflict hint:\n%s", stdout.String())
	}
}

// 同一输入内先冲突拒绝、后合法请求：前一条结果保留当时状态，后续请求正常
// 接受并推进提交与应用。
func TestCLIApplyKVConflictThenRecovery(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "set balance=10"},
	    {"index": 2, "term": 1, "command": "set balance=20"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
	      {"index": 1, "term": 1, "command": "set balance=10"},
	      {"index": 2, "term": 1, "command": "set balance=999"},
	      {"index": 3, "term": 2, "command": "set receipt=ok"}
	    ], "leaderCommit": 3},
	    {"term": 2, "prevLogIndex": 1, "prevLogTerm": 1, "entries": [
	      {"index": 2, "term": 1, "command": "set balance=20"},
	      {"index": 3, "term": 2, "command": "set receipt=ok"}
	    ], "leaderCommit": 3}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty, got %q", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(out.Results) != 2 {
		t.Fatalf("expected 2 results in input order, got %+v", out.Results)
	}
	first := out.Results[0]
	if first.Accepted || first.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("first result must keep the conflict rejection, got %+v", first)
	}
	if first.Term != 2 || first.CommittedIndex != 1 {
		t.Fatalf("first result must reflect the state at that time, got %+v", first)
	}
	if first.AppliedIndex == nil || *first.AppliedIndex != 1 || first.ApplyError != nil {
		t.Fatalf("first result apply state must not become the final state: %+v", first)
	}
	second := out.Results[1]
	if !second.Accepted || second.Reason != mevwatch.ReasonOK {
		t.Fatalf("valid follow-up request rejected: %+v", second)
	}
	if second.Term != 2 || second.CommittedIndex != 3 {
		t.Fatalf("unexpected state after follow-up: %+v", second)
	}
	if second.AppliedIndex == nil || *second.AppliedIndex != 3 || second.ApplyError != nil {
		t.Fatalf("unexpected apply state after follow-up: %+v", second)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 3 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if len(out.FinalLog) != 3 ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 1, Command: "set balance=20"}) ||
		out.FinalLog[2] != (mevwatch.LogEntry{Index: 3, Term: 2, Command: "set receipt=ok"}) {
		t.Fatalf("final log must keep the original index 2, got %+v", out.FinalLog)
	}
	if len(out.FinalKV) != 2 || out.FinalKV["balance"] != "20" || out.FinalKV["receipt"] != "ok" {
		t.Fatalf("unexpected finalKV: %v", out.FinalKV)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 3 || out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply state: appliedIndex=%+v applyError=%+v", out.FinalAppliedIndex, out.FinalApplyError)
	}
}

// 冲突位置的替换命令本身格式错误：拒绝仍由复制冲突决定，未进入日志的命令
// 不产生 applyError，也不影响随后的合法请求。
func TestCLIApplyKVConflictWithMalformedReplacement(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "set balance=10"},
	    {"index": 2, "term": 1, "command": "set balance=20"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
	      {"index": 1, "term": 1, "command": "set balance=10"},
	      {"index": 2, "term": 1, "command": "set balance"}
	    ], "leaderCommit": 2},
	    {"term": 2, "prevLogIndex": 1, "prevLogTerm": 1, "entries": [
	      {"index": 2, "term": 1, "command": "set balance=20"}
	    ], "leaderCommit": 2}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty, got %q", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(out.Results) != 2 {
		t.Fatalf("expected 2 results, got %+v", out.Results)
	}
	first := out.Results[0]
	if first.Accepted || first.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("rejection must be decided by the replication conflict, got %+v", first)
	}
	if first.ApplyError != nil {
		t.Fatalf("a command that never entered the log must not produce an applyError: %+v", first.ApplyError)
	}
	if first.AppliedIndex == nil || *first.AppliedIndex != 1 {
		t.Fatalf("appliedIndex should stay at 1, got %+v", first.AppliedIndex)
	}
	second := out.Results[1]
	if !second.Accepted || second.CommittedIndex != 2 {
		t.Fatalf("valid follow-up request rejected: %+v", second)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["balance"] != "20" {
		t.Fatalf("unexpected finalKV: %v", out.FinalKV)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 2 || out.FinalApplyError != nil {
		t.Fatalf("the malformed replacement must not surface as an apply error: appliedIndex=%+v applyError=%+v",
			out.FinalAppliedIndex, out.FinalApplyError)
	}
	if strings.Contains(stdout.String(), "invalid command") {
		t.Fatalf("no command format error should appear in the output:\n%s", stdout.String())
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
