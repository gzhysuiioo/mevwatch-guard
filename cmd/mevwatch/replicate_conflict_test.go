package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// runReplicateRaw 执行一次 replicate，断言正常完成（退出码 0、stderr 为空），
// 同时返回解码后的结果与原始输出文本：conflict 键“完全不出现”与“出现但为
// null”只能通过原始文本区分。
func runReplicateRaw(t *testing.T, input string) (mevwatch.ReplicateOutput, string) {
	t.Helper()
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
	return out, stdout.String()
}

// TestCLIConflictHintTermMismatchApplyKV 端到端锁定前置索引存在但任期不同时的
// 拒绝答复（开启 applyKV）：本地四条日志任期依次为 1、2、2、2，已提交到 3
// （计数 1+10+100="111"），idx4 的 incr count=1000 是未提交尾部。请求把 idx4
// 作为前置日志却声称其任期为 3，并携带更高任期 5：
//   - accepted=false，reason 为既有的前置日志不匹配原因；
//   - conflict 的 term 是 idx4 的本地任期 2，index 是该任期在完整本地日志中的
//     首次出现位置 2——它落在已提交前缀内，不能因开启键值应用而改成提交位置之后；
//   - 任期提升保留（结果与最终任期都是 5），但日志、提交位置 3、已应用位置 3
//     都保持请求前的值，未提交尾部的增量不改变键值表（计数仍是 "111"），被拒绝
//     的命令不出现在输出中。
func TestCLIConflictHintTermMismatchApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 2,
	  "committedIndex": 3,
	  "log": [
	    {"index": 1, "term": 1, "command": "set count=1"},
	    {"index": 2, "term": 2, "command": "incr count=10"},
	    {"index": 3, "term": 2, "command": "incr count=100"},
	    {"index": 4, "term": 2, "command": "incr count=1000"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 5, "prevLogIndex": 4, "prevLogTerm": 3, "leaderCommit": 4,
	     "entries": [{"index": 5, "term": 5, "command": "set hacked=yes"}]}
	  ]
	}`
	out, body := runReplicateRaw(t, input)
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonPrevLogMismatch {
		t.Fatalf("expected prev-log-mismatch rejection, got %+v", result)
	}
	if result.Conflict == nil ||
		*result.Conflict != (mevwatch.ConflictHint{Index: 2, Term: 2}) {
		t.Fatalf("conflict = %+v, want {index 2, term 2}: first occurrence of the local term, "+
			"even though it lies inside the committed prefix", result.Conflict)
	}
	if result.Term != 5 {
		t.Fatalf("higher request term must survive the rejection, term = %d, want 5", result.Term)
	}
	if result.CommittedIndex != 3 {
		t.Fatalf("rejection must not move committedIndex, got %d, want 3", result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 3 || result.ApplyError != nil {
		t.Fatalf("result apply state = %+v %+v, want appliedIndex 3 and no error",
			result.AppliedIndex, result.ApplyError)
	}
	if out.FinalTerm != 5 || out.FinalCommittedIndex != 3 {
		t.Fatalf("unexpected final state: term=%d ci=%d, want term 5 ci 3",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	wantLog := []mevwatch.LogEntry{
		{Index: 1, Term: 1, Command: "set count=1"},
		{Index: 2, Term: 2, Command: "incr count=10"},
		{Index: 3, Term: 2, Command: "incr count=100"},
		{Index: 4, Term: 2, Command: "incr count=1000"},
	}
	if len(out.FinalLog) != len(wantLog) {
		t.Fatalf("final log has %d entries, want %d (unchanged): %+v",
			len(out.FinalLog), len(wantLog), out.FinalLog)
	}
	for i, want := range wantLog {
		if out.FinalLog[i] != want {
			t.Fatalf("final log[%d] = %+v, want %+v (rejection must not touch the log)",
				i, out.FinalLog[i], want)
		}
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 3 {
		t.Fatalf("finalAppliedIndex = %+v, want 3", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["count"] != "111" {
		t.Fatalf("finalKV = %v, want only count=111 (uncommitted incr count=1000 must not apply)",
			out.FinalKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", out.FinalApplyError)
	}
	if strings.Contains(body, "hacked") {
		t.Fatalf("the rejected entry's command must not appear in the output:\n%s", body)
	}
}

// TestCLIConflictHintBeyondLogEndApplyKV 端到端锁定前置索引越过本地日志末尾时
// 的建议：指向末尾加一、term 明确输出为 0。这是正常的单条复制拒绝，整次调用
// 仍成功输出完整 JSON（退出码 0、stderr 为空），提交位置与键值表保持原样。
func TestCLIConflictHintBeyondLogEndApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 2,
	  "log": [
	    {"index": 1, "term": 1, "command": "set a=1"},
	    {"index": 2, "term": 1, "command": "set b=2"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 5, "prevLogTerm": 1, "entries": [], "leaderCommit": 2}
	  ]
	}`
	out, body := runReplicateRaw(t, input)
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonPrevLogMismatch {
		t.Fatalf("expected prev-log-mismatch rejection, got %+v", result)
	}
	if result.Conflict == nil ||
		*result.Conflict != (mevwatch.ConflictHint{Index: 3, Term: 0}) {
		t.Fatalf("conflict = %+v, want {index 3, term 0} (last local index plus one)",
			result.Conflict)
	}
	if result.Term != 1 || result.CommittedIndex != 2 {
		t.Fatalf("rejection must not change state, got term %d ci %d, want term 1 ci 2",
			result.Term, result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 2 || result.ApplyError != nil {
		t.Fatalf("result apply state = %+v %+v, want appliedIndex 2 and no error",
			result.AppliedIndex, result.ApplyError)
	}
	if len(out.FinalKV) != 2 || out.FinalKV["a"] != "1" || out.FinalKV["b"] != "2" {
		t.Fatalf("finalKV = %v, want a=1 and b=2 unchanged", out.FinalKV)
	}
	// term 0 必须明确输出，不能省略。
	if !strings.Contains(body, `"term": 0`) {
		t.Fatalf("conflict hint must print term 0 explicitly:\n%s", body)
	}
}

// TestCLIConflictHintEmptyLogApplyKVShape 端到端锁定空日志开启 applyKV 时的拒绝
// 输出形状：前置索引越过末尾（空日志）建议为 index 1、term 0；应用字段仍完整
// 出现——已应用位置为 0、键值表为 {}、应用错误为 null，而不是整体缺省。
func TestCLIConflictHintEmptyLogApplyKVShape(t *testing.T) {
	input := `{
	  "currentTerm": 0,
	  "committedIndex": 0,
	  "log": [],
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 3, "prevLogTerm": 2, "entries": [], "leaderCommit": 0}
	  ]
	}`
	out, body := runReplicateRaw(t, input)
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonPrevLogMismatch {
		t.Fatalf("expected prev-log-mismatch rejection, got %+v", result)
	}
	if result.Conflict == nil ||
		*result.Conflict != (mevwatch.ConflictHint{Index: 1, Term: 0}) {
		t.Fatalf("conflict = %+v, want {index 1, term 0} for an empty log", result.Conflict)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 0 || result.ApplyError != nil {
		t.Fatalf("result apply state = %+v %+v, want appliedIndex 0 and no error",
			result.AppliedIndex, result.ApplyError)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 0 {
		t.Fatalf("finalAppliedIndex = %+v, want 0", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 0 {
		t.Fatalf("finalKV = %v, want empty", out.FinalKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", out.FinalApplyError)
	}
	for _, fragment := range []string{
		`"appliedIndex": 0`,
		`"applyError": null`,
		`"finalAppliedIndex": 0`,
		`"finalKV": {}`,
		`"finalApplyError": null`,
		`"conflict"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
}

// TestCLIStaleTermTakesPriorityOverConflictHint 端到端锁定低任期请求的优先级：
// 即使前置日志同时不匹配（本地 idx1 任期 1，请求声称 2），也按低任期拒绝、
// 维持原任期 5，且输出中完全没有 conflict 字段——不是输出 null，也不误给
// 重发建议。日志、提交位置与键值表全部保持原样。
func TestCLIStaleTermTakesPriorityOverConflictHint(t *testing.T) {
	input := `{
	  "currentTerm": 5,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "set x=1"}
	  ],
	  "applyKV": true,
	  "requests": [
	    {"term": 3, "prevLogIndex": 1, "prevLogTerm": 2, "leaderCommit": 2,
	     "entries": [{"index": 2, "term": 3, "command": "set y=2"}]}
	  ]
	}`
	out, body := runReplicateRaw(t, input)
	if len(out.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", out.Results)
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != mevwatch.ReasonStaleTerm {
		t.Fatalf("lower term must reject as stale term even with a mismatched prev log, got %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("stale-term rejection must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 5 || result.CommittedIndex != 1 {
		t.Fatalf("stale-term rejection must keep state, got term %d ci %d, want term 5 ci 1",
			result.Term, result.CommittedIndex)
	}
	if result.AppliedIndex == nil || *result.AppliedIndex != 1 || result.ApplyError != nil {
		t.Fatalf("result apply state = %+v %+v, want appliedIndex 1 and no error",
			result.AppliedIndex, result.ApplyError)
	}
	if out.FinalTerm != 5 || out.FinalCommittedIndex != 1 || len(out.FinalLog) != 1 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["x"] != "1" {
		t.Fatalf("finalKV = %v, want only x=1", out.FinalKV)
	}
	// 公开约定：输出中完全没有 conflict 字段（注意拒绝原因文本不含该键名，
	// 因此按键名判断）；也绝不能出现 "conflict": null。
	if strings.Contains(body, `"conflict"`) {
		t.Fatalf("stale-term rejection output must not contain a conflict key at all:\n%s", body)
	}
	if strings.Contains(body, "set y=2") {
		t.Fatalf("the rejected entry's command must not appear in the output:\n%s", body)
	}
}

// TestCLIConflictHintWithoutApplyKV 保留两条既有公开约定：applyKV 未开启时输出
// 省略全部应用字段（前置日志不匹配的 conflict 建议照常给出）；成功请求不携带
// conflict。同一次调用内先接受一条合法追加、再拒绝一条越界前置，逐条核对。
func TestCLIConflictHintWithoutApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 1,
	  "log": [
	    {"index": 1, "term": 1, "command": "a"}
	  ],
	  "requests": [
	    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 2,
	     "entries": [{"index": 2, "term": 1, "command": "b"}]},
	    {"term": 1, "prevLogIndex": 9, "prevLogTerm": 1, "entries": [], "leaderCommit": 0}
	  ]
	}`
	out, body := runReplicateRaw(t, input)
	if len(out.Results) != 2 {
		t.Fatalf("expected 2 results, got %+v", out.Results)
	}
	first := out.Results[0]
	if !first.Accepted || first.Reason != mevwatch.ReasonOK {
		t.Fatalf("valid append must be accepted: %+v", first)
	}
	if first.Conflict != nil {
		t.Fatalf("accepted request must not carry a conflict hint: %+v", first.Conflict)
	}
	second := out.Results[1]
	if second.Accepted || second.Reason != mevwatch.ReasonPrevLogMismatch {
		t.Fatalf("expected prev-log-mismatch rejection, got %+v", second)
	}
	if second.Conflict == nil ||
		*second.Conflict != (mevwatch.ConflictHint{Index: 3, Term: 0}) {
		t.Fatalf("conflict = %+v, want {index 3, term 0} (log grew to length 2)", second.Conflict)
	}
	if out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	// conflict 键只在被拒绝的第二条结果里出现一次。
	if count := strings.Count(body, `"conflict"`); count != 1 {
		t.Fatalf("conflict key should appear exactly once (the rejected result), got %d:\n%s",
			count, body)
	}
	// applyKV 未开启：整条输出不含任何应用字段。
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q:\n%s", field, body)
		}
	}
}
