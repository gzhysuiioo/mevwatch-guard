package main

import (
	"bytes"
	"strings"
	"testing"
)

// runReplicateExpectFailure 执行一次 replicate，断言它在读取输入阶段失败：
// 退出码 1、标准输出完全为空（不允许输出任何结果 JSON，即使前面的请求都
// 合法也不能只给部分结果），标准错误带有 replicate: 前缀且包含 wantPath
// 指出的字段完整位置。
func runReplicateExpectFailure(t *testing.T, input, wantPath string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("input %q: exit code = %d, want 1", input, code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("input %q: field-type failure must produce no result JSON, got stdout: %s",
			input, stdout.String())
	}
	message := stderr.String()
	if !strings.HasPrefix(message, "replicate:") {
		t.Fatalf("input %q: error must keep the replicate: prefix, got %q", input, message)
	}
	if !strings.Contains(message, wantPath) {
		t.Fatalf("input %q: error must name the full field path %q, got %q",
			input, wantPath, message)
	}
	if !strings.Contains(message, "null") {
		t.Fatalf("input %q: error must point at the explicit null value, got %q", input, message)
	}
}

// TestCLINullNumericFieldsRejected 锁定每个已识别数值字段在显式写成 null 时
// 的读取阶段拒绝，以及错误消息中的完整位置：初始字段直接给字段名，请求与
// 条目从 0 开始计数（第二条请求的提交位置必须标为 requests[1].leaderCommit）。
// 字段名只改字母大小写时沿用既有识别方式，不能借大小写绕过。
func TestCLINullNumericFieldsRejected(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantPath string
	}{
		{
			name:     "initial currentTerm",
			input:    `{"currentTerm": null}`,
			wantPath: "currentTerm",
		},
		{
			name:     "initial committedIndex",
			input:    `{"currentTerm": 2, "committedIndex": null, "log": [{"index": 1, "term": 1, "command": "a"}]}`,
			wantPath: "committedIndex",
		},
		{
			name:     "initial log entry index",
			input:    `{"currentTerm": 1, "committedIndex": 0, "log": [{"index": null, "term": 1, "command": "a"}]}`,
			wantPath: "log[0].index",
		},
		{
			name:     "initial log entry term second entry",
			input:    `{"currentTerm": 2, "committedIndex": 0, "log": [{"index": 1, "term": 1, "command": "a"}, {"index": 2, "term": null, "command": "b"}]}`,
			wantPath: "log[1].term",
		},
		{
			name:     "request term",
			input:    `{"currentTerm": 1, "requests": [{"term": null, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [], "leaderCommit": 0}]}`,
			wantPath: "requests[0].term",
		},
		{
			name:     "request prevLogIndex",
			input:    `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": null, "prevLogTerm": 0, "entries": [], "leaderCommit": 0}]}`,
			wantPath: "requests[0].prevLogIndex",
		},
		{
			name:     "request prevLogTerm",
			input:    `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": null, "entries": [], "leaderCommit": 0}]}`,
			wantPath: "requests[0].prevLogTerm",
		},
		{
			name: "second request leaderCommit is index 1",
			input: `{"currentTerm": 1, "committedIndex": 0, "log": [], "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [], "leaderCommit": 0},
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [], "leaderCommit": null}
			]}`,
			wantPath: "requests[1].leaderCommit",
		},
		{
			name:     "request entry index",
			input:    `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [{"index": null, "term": 1, "command": "x"}], "leaderCommit": 0}]}`,
			wantPath: "requests[0].entries[0].index",
		},
		{
			name: "request entry term second entry",
			input: `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [
			  {"index": 1, "term": 1, "command": "x"},
			  {"index": 2, "term": null, "command": "y"}
			], "leaderCommit": 0}]}`,
			wantPath: "requests[0].entries[1].term",
		},
		{
			name:     "case-only change at initial level",
			input:    `{"CURRENTTERM": null}`,
			wantPath: "currentTerm",
		},
		{
			name:     "case-only change CommittedIndex",
			input:    `{"CommittedINDEX": null}`,
			wantPath: "committedIndex",
		},
		{
			name:     "case-only change request LeaderCommit",
			input:    `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "LEADERCOMMIT": null}]}`,
			wantPath: "requests[0].leaderCommit",
		},
		{
			name:     "case-only change entry TERM",
			input:    `{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [{"index": 1, "TERM": null}], "leaderCommit": 0}]}`,
			wantPath: "requests[0].entries[0].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectFailure(t, tc.input, tc.wantPath)
		})
	}
}

// TestCLINullCommittedIndexMustNotDropCommitProtection 锁定任务主场景：当前
// 任期 2、初始日志有一条索引 1 任期 1 的条目，但 committedIndex 被显式写成
// null。旧行为把它静默当成 0（“尚无提交”），随后任期 3 的请求便能从日志
// 起点覆盖这条日志并返回接受结果；修复后必须在读取输入阶段直接失败，既不
// 运行复制，也不产生任何结果 JSON。
func TestCLINullCommittedIndexMustNotDropCommitProtection(t *testing.T) {
	input := `{
	  "currentTerm": 2,
	  "committedIndex": null,
	  "log": [{"index": 1, "term": 1, "command": "set a=1"}],
	  "requests": [
	    {"term": 3, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 3, "command": "set a=2"}]}
	  ]
	}`
	runReplicateExpectFailure(t, input, "committedIndex")
}

// TestCLINullLeaderCommitRejectsWholeDocument 锁定“前面的请求都合法、后面某条
// 请求的 leaderCommit 为 null”时的边界：整份输入被拒绝，不输出前面请求的
// 部分结果，也不能把这条请求降格为一次普通复制拒绝（普通拒绝是退出码 0 的
// 正常输出 JSON，这里标准输出必须为空）。
func TestCLINullLeaderCommitRejectsWholeDocument(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0,
	     "entries": [{"index": 1, "term": 1, "command": "a"}], "leaderCommit": 1},
	    {"term": 2, "prevLogIndex": 1, "prevLogTerm": 1, "entries": [], "leaderCommit": null}
	  ]
	}`
	runReplicateExpectFailure(t, input, "requests[1].leaderCommit")
}

// TestCLINullFieldOnUncommittedEntryFailsAtRead 未提交条目的数值字段为 null
// 也必须在读取输入阶段失败，不能延迟到它被提交时才判断：请求本身不提交
// （leaderCommit 仍为 0），不允许因为“暂时用不到”就放行。
func TestCLINullFieldOnUncommittedEntryFailsAtRead(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0,
	     "entries": [{"index": 1, "term": null, "command": "a"}], "leaderCommit": 0}
	  ]
	}`
	runReplicateExpectFailure(t, input, "requests[0].entries[0].term")
}

// TestCLINullValidationKeepsOmissionAndZeroSemantics 区分显式 null 与省略：
// 省略仍采用现有默认值（{} 仍是合法空初始状态），合法数字 0 保持原有含义，
// 尤其是日志起点的索引 0 与任期 0。
func TestCLINullValidationKeepsOmissionAndZeroSemantics(t *testing.T) {
	t.Run("empty object", func(t *testing.T) {
		runReplicateRaw(t, `{}`)
	})

	t.Run("omitted request numeric fields default to zero", func(t *testing.T) {
		// 省略全部数值字段等价于任期 0、日志起点、提交位置 0 的空心跳：
		// 是一次正常（成功）复制，而不是字段类型错误。
		out, _ := runReplicateRaw(t, `{"currentTerm": 0, "requests": [{"entries": []}]}`)
		if len(out.Results) != 1 || !out.Results[0].Accepted {
			t.Fatalf("omitted numeric fields must keep their zero-value defaults, got %+v", out.Results)
		}
	})

	t.Run("omitted entry fields stay an ordinary field rejection", func(t *testing.T) {
		// 省略条目 index/term 仍按逻辑层既有规则判为索引不连续的普通请求
		// 拒绝（退出码 0、结果在标准输出），而不是读取阶段失败。
		out, _ := runReplicateRaw(t, `{"currentTerm": 1, "requests": [
		  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0,
		   "entries": [{"command": "a"}], "leaderCommit": 0}
		]}`)
		if len(out.Results) != 1 || out.Results[0].Accepted {
			t.Fatalf("omitted entry index/term must keep the ordinary field rejection, got %+v", out.Results)
		}
	})

	t.Run("explicit zero marks the log origin", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{
		  "currentTerm": 0, "committedIndex": 0, "log": [],
		  "requests": [
		    {"term": 0, "prevLogIndex": 0, "prevLogTerm": 0,
		     "entries": [{"index": 1, "term": 0, "command": "a"}], "leaderCommit": 0}
		  ]
		}`)
		// 真实条目任期 0 仍是既有的字段规则拒绝，但属于普通请求结果，
		// 证明数字 0 被如实传入逻辑层，没有被误判为 null 类型错误。
		if len(out.Results) != 1 || out.Results[0].Accepted {
			t.Fatalf("zero entry term keeps its ordinary field-rule rejection, got %+v", out.Results)
		}
	})

	t.Run("explicit zeroes on a legal heartbeat", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{
		  "currentTerm": 0, "committedIndex": 0,
		  "requests": [{"term": 0, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [], "leaderCommit": 0}]
		}`)
		if len(out.Results) != 1 || !out.Results[0].Accepted || out.FinalTerm != 0 {
			t.Fatalf("explicit origin zeroes must replicate normally, got %+v", out)
		}
	})
}

// TestCLINullOnArraysAndUnknownKeysUnchanged 数组字段及无关键里的 null 沿用
// 既有处理，不受数值校验影响：
//   - log/requests/entries 写成 null 与省略同义；
//   - 任意层级的无关键（含与其他层级数值字段同名的键）取 null 被忽略；
//   - 数组元素为 null 仍按零值条目进入既有逻辑（请求是普通字段拒绝，初始
//     日志是非法初始状态）。
func TestCLINullOnArraysAndUnknownKeysUnchanged(t *testing.T) {
	t.Run("null array fields behave like omitted", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{"currentTerm": 1, "committedIndex": 0, "log": null, "requests": null}`)
		if len(out.Results) != 0 || len(out.FinalLog) != 0 {
			t.Fatalf("null arrays must keep their old meaning, got %+v", out)
		}
	})

	t.Run("null entries array behaves like omitted", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{"currentTerm": 1, "requests": [
		  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": null, "leaderCommit": 0}
		]}`)
		if len(out.Results) != 1 || !out.Results[0].Accepted {
			t.Fatalf("null entries must stay a normal empty heartbeat, got %+v", out.Results)
		}
	})

	t.Run("null unknown keys at every level are ignored", func(t *testing.T) {
		runReplicateRaw(t, `{
		  "foo": null,
		  "currentTerm": 1, "committedIndex": 0,
		  "log": [{"index": 1, "term": 1, "command": "a", "extra": null, "leaderCommit": null}],
		  "requests": [
		    {"bar": null, "term": 1, "prevLogIndex": 1, "prevLogTerm": 1,
		     "entries": [{"index": 2, "term": 1, "command": "b", "committedIndex": null, "currentTerm": null}],
		     "leaderCommit": 2}
		  ]
		}`)
	})

	t.Run("null element in request entries is an ordinary rejection", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{"currentTerm": 1, "requests": [
		  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [null], "leaderCommit": 0}
		]}`)
		if len(out.Results) != 1 || out.Results[0].Accepted {
			t.Fatalf("a null entry element must keep its ordinary field rejection, got %+v", out.Results)
		}
	})

	t.Run("null element in initial log is an invalid initial state", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runReplicateIO(strings.NewReader(
			`{"currentTerm": 1, "committedIndex": 0, "log": [null]}`), &stdout, &stderr)
		if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "replicate:") {
			t.Fatalf("null initial-log element must keep the invalid-initial-state failure, "+
				"code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), "must be a number, got null") {
			t.Fatalf("a null array element must not be reported as a numeric-field type error: %s",
				stderr.String())
		}
	})
}

// TestCLINumericFieldWrongTypeStillParseError 数值字段写成非数字、非 null 的
// 其他类型仍是读取阶段失败，与既有 JSON 解码错误同样以退出码 1、空标准输出
// 和 replicate: 前缀结束。
func TestCLINumericFieldWrongTypeStillParseError(t *testing.T) {
	cases := []string{
		`{"currentTerm": "2"}`,
		`{"committedIndex": true}`,
		`{"currentTerm": 1, "requests": [{"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "entries": [{"index": 1, "term": [1], "command": "x"}], "leaderCommit": 0}]}`,
		`{"currentTerm": {"term": 1}}`,
	}
	for _, input := range cases {
		var stdout, stderr bytes.Buffer
		code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
		if code != 1 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "replicate:") {
			t.Fatalf("input %q: code=%d stdout=%q stderr=%q, want a parse failure",
				input, code, stdout.String(), stderr.String())
		}
	}
}
