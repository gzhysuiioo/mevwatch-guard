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

// TestCLIApplyKVFirstEntryTermBridgeFieldError 端到端锁定任期衔接规则的输出约定：
// 当前任期 2、idx1/idx2 任期 1/2（balance=100 已提交、balance=200 未提交）。
// 任期 7 的请求首条日志任期 1 低于声明的前置任期 2，即使 leaderCommit 很大、
// 命令本身格式错误，也按字段错误拒绝：reason 固定为完整的
// "invalid request: entry terms are not non-decreasing"，不输出 conflict，任期
// 不抬高，未提交尾部不生效，错误命令不产生 applyError。声明的前置任期与本地也
// 不一致时仍是同一条字段错误。随后任期 3 的合法请求追加并提交到 3。
func TestCLIApplyKVFirstEntryTermBridgeFieldError(t *testing.T) {
	input := `{
	  "currentTerm": 2,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "set balance=100"},
	    {"index": 2, "term": 2, "command": "set balance=200"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 7, "prevLogIndex": 2, "prevLogTerm": 2, "leaderCommit": 9,
	     "entries": [{"index": 3, "term": 1, "command": "set broken"}]},
	    {"term": 7, "prevLogIndex": 2, "prevLogTerm": 5, "leaderCommit": 9,
	     "entries": [{"index": 3, "term": 1, "command": "set broken"}]},
	    {"term": 3, "prevLogIndex": 2, "prevLogTerm": 2, "leaderCommit": 3,
	     "entries": [{"index": 3, "term": 2, "command": "set receipt=ok"}]}
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
	if len(out.Results) != 3 {
		t.Fatalf("expected 3 results, got %+v", out.Results)
	}
	for i := 0; i < 2; i++ {
		r := out.Results[i]
		if r.Accepted {
			t.Fatalf("result %d must be rejected, got %+v", i, r)
		}
		if r.Reason != "invalid request: entry terms are not non-decreasing" {
			t.Fatalf("result %d reason = %q, want the exact field-error reason", i, r.Reason)
		}
		if r.Conflict != nil {
			t.Fatalf("result %d must not carry a conflict hint: %+v", i, r.Conflict)
		}
		if r.Term != 2 || r.CommittedIndex != 1 {
			t.Fatalf("result %d state = term %d ci %d, want term 2 ci 1", i, r.Term, r.CommittedIndex)
		}
		if r.AppliedIndex == nil || *r.AppliedIndex != 1 {
			t.Fatalf("result %d appliedIndex = %+v, want 1", i, r.AppliedIndex)
		}
		if r.ApplyError != nil {
			t.Fatalf("result %d must not surface the rejected command's format error: %+v", i, r.ApplyError)
		}
	}
	legal := out.Results[2]
	if !legal.Accepted || legal.Reason != mevwatch.ReasonOK {
		t.Fatalf("valid follow-up request must succeed: %+v", legal)
	}
	if legal.Term != 3 || legal.CommittedIndex != 3 {
		t.Fatalf("legal result state = term %d ci %d, want term 3 ci 3", legal.Term, legal.CommittedIndex)
	}
	if legal.AppliedIndex == nil || *legal.AppliedIndex != 3 || legal.ApplyError != nil {
		t.Fatalf("legal result apply state = %+v %+v, want appliedIndex 3 and no error",
			legal.AppliedIndex, legal.ApplyError)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 3 {
		t.Fatalf("unexpected final state: term=%d ci=%d", out.FinalTerm, out.FinalCommittedIndex)
	}
	if len(out.FinalLog) != 3 ||
		out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "set balance=100"}) ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 2, Command: "set balance=200"}) ||
		out.FinalLog[2] != (mevwatch.LogEntry{Index: 3, Term: 2, Command: "set receipt=ok"}) {
		t.Fatalf("final log = %+v, want original two plus receipt entry", out.FinalLog)
	}
	if len(out.FinalKV) != 2 || out.FinalKV["balance"] != "200" || out.FinalKV["receipt"] != "ok" {
		t.Fatalf("finalKV = %v, want balance=200 and receipt=ok", out.FinalKV)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 3 || out.FinalApplyError != nil {
		t.Fatalf("final apply state = %+v %+v, want appliedIndex 3 and no error",
			out.FinalAppliedIndex, out.FinalApplyError)
	}
	body := stdout.String()
	if strings.Contains(body, "conflict") {
		t.Fatalf("output must not contain a conflict hint:\n%s", body)
	}
	if strings.Contains(body, "set broken") {
		t.Fatalf("the rejected entry's command must not appear in output:\n%s", body)
	}
}

// incrSuffixReplacementInput 构造一个以 incr count=10 为已提交前缀（计数 "10"）、
// 未提交后缀为 incr count=100 与一条非法增量 incr count=1.5 的初始状态，并附上
// 一条从后缀起点 idx2 替换的请求（具体条目与提交位置由参数决定），用于端到端
// 锁定任期冲突替换 incr 后缀时的公开 JSON 输出。
func incrSuffixReplacementInput(requestJSON string) string {
	return `{
  "currentTerm": 2,
  "committedIndex": 1,
  "log": [
    {"index": 1, "term": 1, "command": "incr count=10"},
    {"index": 2, "term": 1, "command": "incr count=100"},
    {"index": 3, "term": 1, "command": "incr count=1.5"}
  ],
  "applyKV": true,
  "requests": [
    ` + requestJSON + `
  ]
}`
}

// runReplicateJSON 执行一次 replicate，断言正常完成（退出码 0、stderr 为空），
// 并把 stdout 解码为结果。
func runReplicateJSON(t *testing.T, input string) mevwatch.ReplicateOutput {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("normal completion must leave stderr empty, got %q", stderr.String())
	}
	var out mevwatch.ReplicateOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	return out
}

// TestCLIApplyKVIncrTermConflictReplacesSuffix 端到端锁定任务主场景的公开 JSON：
// 初始已提交 incr count=10（计数 "10"），未提交后缀含 incr count=100 与
// incr count=1.5。请求匹配前置 idx1，在 idx2 以不同任期（旧 1、新 2）只带一条
// incr count=-3 并提交到 2。最终计数应为 "7"，旧后缀两条从 finalLog 消失；
// 被丢弃的合法增量与非法增量都不影响计数，且没有应用错误。
func TestCLIApplyKVIncrTermConflictReplacesSuffix(t *testing.T) {
	input := incrSuffixReplacementInput(
		`{"term": 2, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 2,
	     "entries": [{"index": 2, "term": 2, "command": "incr count=-3"}]}`)
	out := runReplicateJSON(t, input)
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != mevwatch.ReasonOK {
		t.Fatalf("different-term replacement must be accepted: %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("accepted replacement must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 2 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 2 ci 2", result.Term, result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 2 {
		t.Fatalf("result appliedIndex = %+v, want 2", result.AppliedIndex)
	}
	if result.ApplyError != nil {
		t.Fatalf("replacement incr must apply cleanly: %+v", result.ApplyError)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 2 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if len(out.FinalLog) != 2 ||
		out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "incr count=10"}) ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 2, Command: "incr count=-3"}) {
		t.Fatalf("final log must drop the old suffix and keep the committed prefix: %+v", out.FinalLog)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 2 {
		t.Fatalf("final appliedIndex = %+v, want 2", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["count"] != "7" {
		t.Fatalf("finalKV = %v, want count=7 (10 on the committed prefix, then -3)", out.FinalKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", out.FinalApplyError)
	}
}

// TestCLIApplyKVIncrSameTermConflictRejects 端到端锁定区分情形一：冲突位置的
// 索引与任期都与旧条目相同（idx2 仍是任期 1），只是命令变成 incr count=-3。
// 整条请求按现有同任期命令冲突拒绝：accepted=false 并给出具体原因，无 conflict
// 键；旧后缀不能被提交、新命令不能被应用；日志、计数 "10"、提交与应用位置保持
// 原样；较高请求任期 3 仍按现有规则保留。
func TestCLIApplyKVIncrSameTermConflictRejects(t *testing.T) {
	input := incrSuffixReplacementInput(
		`{"term": 3, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 3,
	     "entries": [
	       {"index": 2, "term": 1, "command": "incr count=-3"},
	       {"index": 3, "term": 3, "command": "set other=x"}
	     ]}`)
	out := runReplicateJSON(t, input)
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonCommandConflictSameTerm {
		t.Fatalf("expected same-term command conflict rejection, got %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("command conflict must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 3 {
		t.Fatalf("higher request term must survive rejection, term = %d, want 3", result.Term)
	}
	if result.CommittedIndex != 1 {
		t.Fatalf("commit moved on rejection: %d, want 1", result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 1 || result.ApplyError != nil {
		t.Fatalf("result apply state = %+v %+v, want appliedIndex 1 and no error",
			result.AppliedIndex, result.ApplyError)
	}
	if len(out.FinalLog) != 3 ||
		out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "incr count=10"}) ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 1, Command: "incr count=100"}) ||
		out.FinalLog[2] != (mevwatch.LogEntry{Index: 3, Term: 1, Command: "incr count=1.5"}) {
		t.Fatalf("log must be unchanged after the atomic rejection: %+v", out.FinalLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 1 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %+v, want 1", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["count"] != "10" {
		t.Fatalf("finalKV = %v, want only count=10", out.FinalKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", out.FinalApplyError)
	}
}

// TestCLIApplyKVIncrTermConflictBadDeltaApplyError 端到端锁定区分情形二：不同
// 任期的替换本身合法（idx2 旧任期 1、新任期 3），但新条目 incr count=x 的增量
// 不是整数。复制与提交成功（接受、提交位置到 2、日志完成替换，旧后缀消失），
// 只有提交后的应用在正常 JSON 中报告错误：appliedIndex 停在 1，applyError 指向
// idx2 并给出具体原因，计数保留 "10"。调用正常完成（退出码 0、stderr 为空）。
func TestCLIApplyKVIncrTermConflictBadDeltaApplyError(t *testing.T) {
	input := incrSuffixReplacementInput(
		`{"term": 3, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 2,
	     "entries": [{"index": 2, "term": 3, "command": "incr count=x"}]}`)
	out := runReplicateJSON(t, input)
	result := out.Results[0]
	if !result.Accepted || result.Reason != mevwatch.ReasonOK {
		t.Fatalf("replication of the legal replacement must succeed: %+v", result)
	}
	if result.Term != 3 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 3 ci 2", result.Term, result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 1 {
		t.Fatalf("result appliedIndex = %+v, want 1 (stopped before the bad new entry)", result.AppliedIndex)
	}
	if result.ApplyError == nil || result.ApplyError.Index != 2 ||
		result.ApplyError.Reason != mevwatch.ApplyReasonIncrBadDelta {
		t.Fatalf("result applyError = %+v, want index 2 bad delta", result.ApplyError)
	}
	if len(out.FinalLog) != 2 ||
		out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "incr count=10"}) ||
		out.FinalLog[1] != (mevwatch.LogEntry{Index: 2, Term: 3, Command: "incr count=x"}) {
		t.Fatalf("final log must reflect the successful replacement: %+v", out.FinalLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %+v, want 1", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["count"] != "10" {
		t.Fatalf("finalKV = %v, want only count=10 (bad new incr leaves the table unchanged)", out.FinalKV)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != mevwatch.ApplyReasonIncrBadDelta {
		t.Fatalf("final applyError = %+v, want index 2 bad delta", out.FinalApplyError)
	}
}

// TestCLIApplyKVIncrTermConflictDisabledShape 不开启 applyKV 时，不同任期替换
// 照常进行，但 incr 只是普通字符串：输出保持现状形状，没有任何应用字段。
func TestCLIApplyKVIncrTermConflictDisabledShape(t *testing.T) {
	input := `{
  "currentTerm": 2,
  "committedIndex": 1,
  "log": [
    {"index": 1, "term": 1, "command": "incr count=10"},
    {"index": 2, "term": 1, "command": "incr count=100"},
    {"index": 3, "term": 1, "command": "incr count=1.5"}
  ],
  "requests": [
    {"term": 2, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 2,
     "entries": [{"index": 2, "term": 2, "command": "incr count=-3"}]}
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
	if !out.Results[0].Accepted || out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("replication should succeed without applyKV: %+v", out)
	}
	body := stdout.String()
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q:\n%s", field, body)
		}
	}
	if !strings.Contains(body, "incr count=-3") {
		t.Fatalf("incr command must be replicated verbatim:\n%s", body)
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
