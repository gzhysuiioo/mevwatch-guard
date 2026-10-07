package main

import (
	"bytes"
	"strings"
	"testing"
)

// 未知字段里的合法大数（1e400、超出浮点范围的大整数等）不影响输入解析：
// 未知字段不参与跟随者状态计算，结果应与删除这些字段后完全相同。本文件
// 锁定这一行为：大数可以出现在根对象、请求对象、日志条目以及未知字段
// 自己的嵌套对象和数组里；未知对象内部即使出现 currentTerm、term、index
// 等名称，也不能当成真实状态字段检查。

// bigNumberUnknownFieldsInput 是任务主场景：任期 1、空日志、提交位置 0，
// 开启 applyKV，一个任期 1 的请求从日志起点依次复制索引 1 的 set count=7
// 和索引 2 的 incr count=-2，并提交到 2。未知字段（含 1e400 与超出浮点
// 范围的大整数）散布在根对象、请求对象、日志条目及未知字段自身的嵌套
// 结构里，未知对象内部还故意使用 currentTerm、term、index 等同名键。
const bigNumberUnknownFieldsInput = `{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "applyKV": true,
  "trace": {"currentTerm": 1e400, "term": 123456789012345678901234567890, "index": -9e999},
  "extra": [1e400, {"committedIndex": null, "nested": [1e400, {"leaderCommit": 5e500}]}],
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 2,
     "debug": {"term": 1e400, "entries": [{"index": 1e400}]},
     "entries": [
       {"index": 1, "term": 1, "command": "set count=7", "note": 1e400},
       {"index": 2, "term": 1, "command": "incr count=-2",
        "note": {"index": 99999999999999999999999999, "list": [1e-400]}}
     ]}
  ]
}`

// bigNumberUnknownFieldsStripped 是同一份输入删除所有未知字段后的样子。
const bigNumberUnknownFieldsStripped = `{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "applyKV": true,
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 2,
     "entries": [
       {"index": 1, "term": 1, "command": "set count=7"},
       {"index": 2, "term": 1, "command": "incr count=-2"}
     ]}
  ]
}`

// TestCLIUnknownFieldBigNumbersIgnored 端到端锁定任务主场景：附加含 1e400
// 等合法大数的未知字段后请求仍被接受，最终任期 1，日志保留两条命令，提交
// 位置与应用位置都为 2，count 为字符串 "5"，没有应用错误，退出码为 0；
// 输出与删除未知字段后的输入逐字节相同。
func TestCLIUnknownFieldBigNumbersIgnored(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(bigNumberUnknownFieldsInput), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("normal completion must leave stderr empty, got %q", stderr.String())
	}
	body := stdout.String()
	for _, fragment := range []string{
		`"accepted": true`,
		`"finalTerm": 1`,
		`"finalCommittedIndex": 2`,
		`"finalAppliedIndex": 2`,
		`"applyError": null`,
		`"finalApplyError": null`,
		`"count": "5"`,
		`"set count=7"`,
		`"incr count=-2"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
	if strings.Contains(body, "1e400") || strings.Contains(body, "trace") || strings.Contains(body, "note") {
		t.Fatalf("unknown fields must not leak into the output:\n%s", body)
	}

	// 结果必须与删除未知字段后的输入完全一致。
	var stripped bytes.Buffer
	if code := runReplicateIO(strings.NewReader(bigNumberUnknownFieldsStripped), &stripped, &stderr); code != 0 {
		t.Fatalf("stripped input exit code = %d", code)
	}
	if body != stripped.String() {
		t.Fatalf("output must equal the output with unknown fields removed:\n%s\n%s", body, stripped.String())
	}
}

// TestCLIUnknownFieldBigNumbersApplyKVDisabled 关闭键值应用时同样正常复制，
// 保留原有输出形状：没有任何应用字段，命令原样出现在最终日志里。
func TestCLIUnknownFieldBigNumbersApplyKVDisabled(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "unknown": {"big": 1e400},
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 2,
	     "extra": [1e400],
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
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q:\n%s", field, body)
		}
	}
	for _, fragment := range []string{`"accepted": true`, `"finalCommittedIndex": 2`, `"incr count=-2"`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
}

// 同样的超大数字写在已识别的真实数值字段上，仍须按字段类型错误拒绝整份
// 输入：已识别字段的整数类型与范围限制不因本修复而放松。
func TestCLIRealNumericFieldBigNumberStillRejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "currentTerm",
			input: `{"currentTerm": 1e400, "log": [], "requests": []}`,
			path:  "currentTerm",
		},
		{
			name:  "committedIndex big integer",
			input: `{"currentTerm": 1, "committedIndex": 99999999999999999999999999}`,
			path:  "committedIndex",
		},
		{
			name:  "log entry index",
			input: `{"currentTerm": 1, "log": [{"index": 1e400, "term": 1, "command": "a"}]}`,
			path:  "index",
		},
		{
			name: "request leaderCommit",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1e400, "entries": []}
			]}`,
			path: "leaderCommit",
		},
		{
			name: "entry term",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [{"index": 1, "term": 1e400, "command": "a"}]}
			]}`,
			path: "term",
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
				t.Fatalf("no result JSON may be produced on a field type error, got: %s", stdout.String())
			}
			message := stderr.String()
			if !strings.HasPrefix(message, "replicate:") || !strings.Contains(message, tc.path) {
				t.Fatalf("error must carry replicate: prefix and name %q, got: %q", tc.path, message)
			}
		})
	}
}

// 未知大数不能遮住排在其后的真实数值 null：扫描必须越过未知字段里的
// 1e400，仍报告完整字段位置。重复字段里较早出现的真实数值 null 也不能丢。
func TestCLIUnknownBigNumberDoesNotHideRealNull(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "big number before real null at root",
			input: `{"unknown": 1e400, "committedIndex": null}`,
			path:  "committedIndex",
		},
		{
			name:  "big number in nested unknown object before real null",
			input: `{"unknown": {"deep": [1e400, {"term": 9e999}]}, "currentTerm": null}`,
			path:  "currentTerm",
		},
		{
			name: "big number in request unknown field before entry null",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0, "debug": 1e400,
			   "entries": [{"index": null, "term": 1, "command": "a"}]}
			]}`,
			path: "requests[0].entries[0].index",
		},
		{
			name:  "earlier real null in duplicated field survives",
			input: `{"unknown": 1e400, "currentTerm": null, "currentTerm": 1}`,
			path:  "currentTerm",
		},
		{
			name:  "real null in earlier duplicated array survives",
			input: `{"meta": 1e400, "log": [{"index": null, "term": 1, "command": "a"}], "log": []}`,
			path:  "log[0].index",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}

// 未知字段携带大数不改变输入错误的既有判定：语法错误、一份文档后又跟着
// 另一份 JSON，仍按原有输入错误处理。
func TestCLIUnknownBigNumberKeepsInputErrorRules(t *testing.T) {
	cases := []string{
		`{"unknown": 1e400, "currentTerm": }`,
		`{"unknown": 1e400} {"currentTerm": 1}`,
		`{"unknown": 1e400}`,
	}
	for i, input := range cases {
		var stdout, stderr bytes.Buffer
		code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
		// 前两种是输入错误；最后一种只有未知字段，是合法的空初始状态。
		if i < 2 {
			if code != 1 {
				t.Fatalf("input %q: exit code = %d, want 1", input, code)
			}
			if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "replicate:") {
				t.Fatalf("input %q: unexpected stdout/stderr: %q / %q", input, stdout.String(), stderr.String())
			}
		} else if code != 0 {
			t.Fatalf("input %q: exit code = %d, want 0; stderr=%s", input, code, stderr.String())
		}
	}
}
