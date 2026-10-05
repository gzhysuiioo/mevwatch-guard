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

// 初始日志：任期 1，索引 1 set balance=10、索引 2 set balance=20，仅索引 1
// 已提交；applyKV 开启。冲突请求从日志起点携带与索引 1 完全相同的条目，在
// 索引 2 同任期换命令（set balance=999），并在索引 3 携带新写入，leaderCommit 3。
const applyKVConflictInputPrefix = `{
  "currentTerm": 1,
  "committedIndex": 1,
  "log": [
    {"index": 1, "term": 1, "command": "set balance=10"},
    {"index": 2, "term": 1, "command": "set balance=20"}
  ],
  "applyKV": true,
  "requests": [`

// 随后以任期 2 正确匹配原有索引 2，追加索引 3 set receipt=ok 并提交到 3。
const applyKVFollowUpRequest = `
    {"term": 2, "prevLogIndex": 2, "prevLogTerm": 1, "entries": [
      {"index": 3, "term": 2, "command": "set receipt=ok"}
    ], "leaderCommit": 3}`

func TestCLIApplyKVSameTermCommandConflictThenSuccess(t *testing.T) {
	input := applyKVConflictInputPrefix + `
    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
      {"index": 1, "term": 1, "command": "set balance=10"},
      {"index": 2, "term": 1, "command": "set balance=999"},
      {"index": 3, "term": 2, "command": "set receipt=stolen"}
    ], "leaderCommit": 3},` + applyKVFollowUpRequest + `
  ]
}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	// 复制拒绝属于正常输出：退出码 0、标准错误为空、标准输出是完整 JSON。
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty, got: %s", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}

	if len(out.Results) != 2 {
		t.Fatalf("want 2 results in input order, got %d", len(out.Results))
	}
	first, second := out.Results[0], out.Results[1]

	// 第一条：同索引同任期命令不同而整条拒绝，且不附带前置日志不匹配的 conflict。
	if first.Accepted || first.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("first request should be rejected for same-term command conflict, got %+v", first)
	}
	if first.Conflict != nil {
		t.Fatalf("command-conflict rejection must not carry conflict hint, got %+v", first.Conflict)
	}
	// 较高任期保留为 2；提交与应用位置仍是 1；没有任何应用错误。
	if first.Term != 2 {
		t.Fatalf("term should stay bumped to 2, got %d", first.Term)
	}
	if first.CommittedIndex != 1 {
		t.Fatalf("first result committedIndex = %d, want 1 (state at rejection time)", first.CommittedIndex)
	}
	if first.AppliedIndex == nil || *first.AppliedIndex != 1 {
		t.Fatalf("first result appliedIndex = %v, want 1", first.AppliedIndex)
	}
	if first.ApplyError != nil {
		t.Fatalf("rejected entries must not be applied, got applyError %+v", first.ApplyError)
	}

	// 第二条：合法请求照常接受。结果次序为先拒绝、后成功。
	if !second.Accepted || second.Reason != mevwatch.ReasonOK {
		t.Fatalf("follow-up request should be accepted, got %+v", second)
	}
	if second.Conflict != nil {
		t.Fatalf("accepted request must not carry conflict hint, got %+v", second.Conflict)
	}
	if second.Term != 2 || second.CommittedIndex != 3 {
		t.Fatalf("second result term/commit = %d/%d, want 2/3", second.Term, second.CommittedIndex)
	}
	if second.AppliedIndex == nil || *second.AppliedIndex != 3 {
		t.Fatalf("second result appliedIndex = %v, want 3", second.AppliedIndex)
	}
	if second.ApplyError != nil {
		t.Fatalf("unexpected apply error on follow-up: %+v", second.ApplyError)
	}

	// 最终状态：原有索引 2 保留，索引 3 是合法的 receipt=ok；冲突命令与被拒
	// 新条目都没有留下任何效果。
	wantLog := []mevwatch.LogEntry{
		{Index: 1, Term: 1, Command: "set balance=10"},
		{Index: 2, Term: 1, Command: "set balance=20"},
		{Index: 3, Term: 2, Command: "set receipt=ok"},
	}
	if len(out.FinalLog) != len(wantLog) {
		t.Fatalf("finalLog = %+v, want %+v", out.FinalLog, wantLog)
	}
	for i, want := range wantLog {
		if out.FinalLog[i] != want {
			t.Fatalf("finalLog[%d] = %+v, want %+v (full: %+v)", i, out.FinalLog[i], want, out.FinalLog)
		}
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 3 {
		t.Fatalf("final term/commit = %d/%d, want 2/3", out.FinalTerm, out.FinalCommittedIndex)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 3 {
		t.Fatalf("finalAppliedIndex = %v, want 3", out.FinalAppliedIndex)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("finalApplyError = %+v, want none", out.FinalApplyError)
	}
	if kv := out.FinalKV; len(kv) != 2 || kv["balance"] != "20" || kv["receipt"] != "ok" {
		t.Fatalf("finalKV = %+v, want balance=20 receipt=ok", kv)
	}
	if strings.Contains(stdout.String(), "balance=999") || strings.Contains(stdout.String(), "receipt=stolen") {
		t.Fatalf("rejected entries leaked into output:\n%s", stdout.String())
	}
}

func TestCLIApplyKVSameTermConflictLeavesStateUntouchedWhenInputEnds(t *testing.T) {
	// 输入只到冲突请求为止：日志仍是原来的两条，键值表只有 balance=10。
	input := applyKVConflictInputPrefix + `
    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
      {"index": 1, "term": 1, "command": "set balance=10"},
      {"index": 2, "term": 1, "command": "set balance=999"},
      {"index": 3, "term": 2, "command": "set receipt=stolen"}
    ], "leaderCommit": 3}
  ]
}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty, got: %s", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}

	wantLog := []mevwatch.LogEntry{
		{Index: 1, Term: 1, Command: "set balance=10"},
		{Index: 2, Term: 1, Command: "set balance=20"},
	}
	if len(out.FinalLog) != len(wantLog) {
		t.Fatalf("finalLog = %+v, want original two entries %+v", out.FinalLog, wantLog)
	}
	for i, want := range wantLog {
		if out.FinalLog[i] != want {
			t.Fatalf("finalLog[%d] = %+v, want %+v", i, out.FinalLog[i], want)
		}
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final term/commit = %d/%d, want 2/1", out.FinalTerm, out.FinalCommittedIndex)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %v, want 1", out.FinalAppliedIndex)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("finalApplyError = %+v, want none", out.FinalApplyError)
	}
	if kv := out.FinalKV; len(kv) != 1 || kv["balance"] != "10" {
		t.Fatalf("finalKV = %+v, want only balance=10", kv)
	}
}

func TestCLIApplyKVConflictMalformedCommandNoApplyError(t *testing.T) {
	// 冲突位置的替换命令本身是格式错误的键值命令（set 缺少 '='）：拒绝原因
	// 仍由复制冲突决定，未进入日志的命令不得被当作已提交命令产生 applyError，
	// 也不能阻止随后的合法请求。
	input := applyKVConflictInputPrefix + `
    {"term": 2, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
      {"index": 1, "term": 1, "command": "set balance=10"},
      {"index": 2, "term": 1, "command": "set broken"},
      {"index": 3, "term": 2, "command": "set new=1"}
    ], "leaderCommit": 3},` + applyKVFollowUpRequest + `
  ]
}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty, got: %s", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}

	if len(out.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(out.Results))
	}
	first := out.Results[0]
	if first.Accepted || first.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("malformed replacement must still be rejected for replication conflict, got %+v", first)
	}
	if first.Conflict != nil {
		t.Fatalf("command-conflict rejection must not carry conflict hint, got %+v", first.Conflict)
	}
	if first.ApplyError != nil {
		t.Fatalf("uncommitted malformed command must not produce applyError, got %+v", first.ApplyError)
	}
	if first.AppliedIndex == nil || *first.AppliedIndex != 1 {
		t.Fatalf("first result appliedIndex = %v, want 1", first.AppliedIndex)
	}
	if !out.Results[1].Accepted {
		t.Fatalf("valid follow-up must still be accepted: %+v", out.Results[1])
	}
	if out.FinalApplyError != nil {
		t.Fatalf("finalApplyError = %+v, want none", out.FinalApplyError)
	}
	if out.FinalCommittedIndex != 3 || out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 3 {
		t.Fatalf("final commit/apply = %d/%v, want 3/3", out.FinalCommittedIndex, out.FinalAppliedIndex)
	}
	if kv := out.FinalKV; kv["balance"] != "20" || kv["receipt"] != "ok" {
		t.Fatalf("finalKV = %+v, want balance=20 receipt=ok", kv)
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
