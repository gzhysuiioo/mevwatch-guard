package main

import (
	"bytes"
	"strings"
	"testing"
)

// 未知字段里的合法大数（1e400 这类超出 float64 范围的指数形式数字、超出
// 64 位整数范围的大整数）不参与跟随者状态计算，不能决定复制功能能否使用：
// 无论它们出现在根对象、请求对象、日志条目，还是未知字段自己的嵌套对象与
// 数组里，输入都必须按“删除了这些未知字段”来接受。未知对象内部即使出现
// currentTerm、term、index 等已识别名称，也不能当成真实状态字段检查。
func TestCLIUnknownFieldBigNumberAccepted(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "applyKV": true,
	  "extra": 1e400,
	  "unknownObj": {"currentTerm": 1e400, "term": 123456789012345678901234567890,
	                 "index": 1e400, "nested": [1e400, {"leaderCommit": 1e400}]},
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 2,
	     "meta": {"term": 1e400, "list": [1e400]},
	     "entries": [
	       {"index": 1, "term": 1, "command": "set count=7", "x": 1e400},
	       {"index": 2, "term": 1, "command": "incr count=-2",
	        "y": {"index": 1e400, "term": [1e400]}}
	     ]}
	  ],
	  "tail": [1e400]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, fragment := range []string{
		`"accepted": true`,
		`"term": 1`,
		`"committedIndex": 2`,
		`"appliedIndex": 2`,
		`"applyError": null`,
		`"finalTerm": 1`,
		`"finalCommittedIndex": 2`,
		`"finalAppliedIndex": 2`,
		`"count": "5"`,
		`"finalApplyError": null`,
		`"command": "set count=7"`,
		`"command": "incr count=-2"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
	// 未知字段不带进输出。
	if strings.Contains(body, "1e400") || strings.Contains(body, "extra") ||
		strings.Contains(body, "unknownObj") || strings.Contains(body, "meta") {
		t.Fatalf("unknown fields must not leak into output:\n%s", body)
	}
}

// 关闭键值应用时未知大数同样不影响复制，输出保持原有形状（无 KV 字段）。
func TestCLIUnknownFieldBigNumberAcceptedWithoutApplyKV(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "log": [],
	  "extra": 1e400,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 2,
	     "unknown": 1e400,
	     "entries": [
	       {"index": 1, "term": 1, "command": "set count=7"},
	       {"index": 2, "term": 1, "command": "incr count=-2"}
	     ]}
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
		`"finalTerm": 1`,
		`"finalCommittedIndex": 2`,
		`"command": "set count=7"`,
		`"command": "incr count=-2"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
	for _, absent := range []string{"appliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, absent) {
			t.Fatalf("output without applyKV must not contain %s:\n%s", absent, body)
		}
	}
}

// 已识别的真实数值字段仍遵守原有类型与范围限制：同样的超大数字写在真实
// 字段上，整份输入仍须拒绝。
func TestCLIRealNumericFieldBigNumberStillRejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "currentTerm",
			input: `{"currentTerm": 1e400, "log": [], "requests": []}`,
		},
		{
			name:  "committedIndex",
			input: `{"currentTerm": 1, "committedIndex": 1e400, "log": [], "requests": []}`,
		},
		{
			name: "log entry index",
			input: `{"currentTerm": 1, "log": [{"index": 1e400, "term": 1, "command": "a"}],
			  "requests": []}`,
		},
		{
			name: "request leaderCommit",
			input: `{"currentTerm": 1, "log": [], "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1e400, "entries": []}
			]}`,
		},
		{
			name: "entry term",
			input: `{"currentTerm": 1, "log": [], "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [{"index": 1, "term": 1e400, "command": "a"}]}
			]}`,
		},
		{
			name:  "oversized integer",
			input: `{"currentTerm": 123456789012345678901234567890, "log": [], "requests": []}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runReplicateIO(strings.NewReader(tc.input), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("no result JSON may be produced, got: %s", stdout.String())
			}
			if !strings.HasPrefix(stderr.String(), "replicate:") {
				t.Fatalf("error message missing replicate: prefix: %q", stderr.String())
			}
		})
	}
}

// 未知大数不能遮住真实数值字段上的显式 null：null 检查仍按输入顺序报告
// 第一个真实字段位置，退出码 1、标准输出为空、标准错误带 replicate: 前缀。
func TestCLIUnknownBigNumberDoesNotMaskRealNull(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "big number before root null",
			input: `{"unknown": 1e400, "currentTerm": null}`,
			path:  "currentTerm",
		},
		{
			name: "big number inside unknown nested value before real null",
			input: `{"currentTerm": 1, "log": [], "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "deep": {"x": [1e400, {"term": 1e400}]}, "entries": []}
			], "committedIndex": null}`,
			path: "committedIndex",
		},
		{
			name: "big number inside earlier entry before later entry null",
			input: `{"currentTerm": 1, "log": [], "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [
			     {"index": 1, "term": 1, "command": "a", "x": 1e400},
			     {"index": 2, "term": null, "command": "b"}
			   ]}
			]}`,
			path: "requests[0].entries[1].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}
