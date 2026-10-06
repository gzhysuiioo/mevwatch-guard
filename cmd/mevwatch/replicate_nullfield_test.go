package main

import (
	"bytes"
	"strings"
	"testing"
)

// runReplicateExpectInputError 执行一次 replicate，断言整份输入在读取阶段被
// 拒绝：退出码 1、标准输出没有任何结果 JSON、标准错误带 replicate: 前缀且
// 指出字段的完整位置。
func runReplicateExpectInputError(t *testing.T, input, wantPath string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("no result JSON may be produced on a field type error, got: %s", stdout.String())
	}
	message := stderr.String()
	if !strings.HasPrefix(message, "replicate:") {
		t.Fatalf("error message missing replicate: prefix: %q", message)
	}
	if !strings.Contains(message, wantPath) {
		t.Fatalf("error message must name the field location %q, got: %q", wantPath, message)
	}
	return message
}

// 任务主场景：当前任期 2、初始日志含索引 1（任期 1）的条目，committedIndex
// 却显式写成 null。即使随后任期 3 的请求能从日志起点替换这条日志，也必须在
// 读取输入阶段失败——null 不能被解释成“尚未提交”而让初始日志失去提交保护。
func TestCLINullCommittedIndexRejectsWholeInput(t *testing.T) {
	input := `{
	  "currentTerm": 2,
	  "committedIndex": null,
	  "log": [{"index": 1, "term": 1, "command": "set x=1"}],
	  "requests": [
	    {"term": 3, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 3, "command": "set x=2"}]}
	  ]
	}`
	runReplicateExpectInputError(t, input, "committedIndex")
}

// 前面的请求都合法、后面某条请求的 leaderCommit 为 null：同样拒绝整份输入，
// 不输出前面请求的部分结果，也不把它降为一次普通复制拒绝。
func TestCLINullLeaderCommitInLaterRequestRejectsWholeInput(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": [],
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "set a=1"}]},
	    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": null,
	     "entries": [{"index": 2, "term": 1, "command": "set b=2"}]}
	  ]
	}`
	runReplicateExpectInputError(t, input, "requests[1].leaderCommit")
}

// 字段名只改变字母大小写时沿用同样的识别方式，不能绕过数值 null 校验。
func TestCLINullNumericFieldCaseVariantStillRejected(t *testing.T) {
	input := `{
	  "CurrentTerm": 1,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "LeaderCommit": null,
	     "entries": []}
	  ]
	}`
	message := runReplicateExpectInputError(t, input, "requests[0].leaderCommit")
	if strings.Contains(message, "LeaderCommit") && !strings.Contains(message, "leaderCommit") {
		t.Fatalf("location should use the canonical field name, got: %q", message)
	}
}

// 初始状态与其余数值位置：currentTerm、初始日志条目的 index/term、请求的
// term/prevLogIndex/prevLogTerm，以及未提交条目的 index/term——都不能延迟
// 到提交时才判断。
func TestCLINullNumericFieldLocations(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "initial currentTerm",
			input: `{"currentTerm": null, "log": [], "requests": []}`,
			path:  "currentTerm",
		},
		{
			name:  "initial log entry index",
			input: `{"currentTerm": 1, "log": [{"index": null, "term": 1, "command": "a"}]}`,
			path:  "log[0].index",
		},
		{
			name:  "initial log entry term",
			input: `{"currentTerm": 1, "log": [{"index": 1, "term": null, "command": "a"}]}`,
			path:  "log[0].term",
		},
		{
			name: "request term",
			input: `{"currentTerm": 1, "requests": [
			  {"term": null, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0, "entries": []}
			]}`,
			path: "requests[0].term",
		},
		{
			name: "request prevLogIndex",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": null, "prevLogTerm": 0, "leaderCommit": 0, "entries": []}
			]}`,
			path: "requests[0].prevLogIndex",
		},
		{
			name: "request prevLogTerm",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": null, "leaderCommit": 0, "entries": []}
			]}`,
			path: "requests[0].prevLogTerm",
		},
		{
			// 条目尚未提交：null 校验仍在读取输入阶段完成，不延迟到提交时。
			name: "uncommitted entry index",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [{"index": null, "term": 1, "command": "set a=1"}]}
			]}`,
			path: "requests[0].entries[0].index",
		},
		{
			name: "uncommitted entry term",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [{"index": 1, "term": null, "command": "set a=1"}]}
			]}`,
			path: "requests[0].entries[0].term",
		},
		{
			name: "second entry of second request",
			input: `{"currentTerm": 1, "requests": [
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0, "entries": []},
			  {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
			   "entries": [
			     {"index": 1, "term": 1, "command": "a"},
			     {"index": 2, "term": null, "command": "b"}
			   ]}
			]}`,
			path: "requests[1].entries[1].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}

// 显式 null 与省略字段、合法数字 0 要区分开：省略仍采用默认值，{} 仍是合法
// 空初始状态，日志起点的索引 0 与任期 0 保持原有含义；数组字段与未知键里的
// null 沿用已有处理，不受数值校验影响。
func TestCLINullValidationKeepsExistingSemantics(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": null,
	  "unknownKey": null,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
	     "entries": null},
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "set a=1"}]}
	  ]
	}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	body := stdout.String()
	for _, fragment := range []string{`"accepted": true`, `"finalCommittedIndex": 1`, `"set a=1"`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("output missing %s:\n%s", fragment, body)
		}
	}
}

// 本应是数组的 log/requests/entries 被写成对象时，对象内部的字段不能冒充
// 外层已识别字段：扫描必须把整个错误对象消费掉，让类型化解码按既有 JSON
// 类型错误格式指出这个数组字段本身，而不是声称某个数值字段被写成 null。
func TestCLINonObjectArrayFieldKeepsInnerFieldsOutOfScan(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			// requests 内的 currentTerm 不是顶层字段；错误必须指出 requests 本身。
			name:  "requests object inner field is not top-level",
			input: `{"requests":{"currentTerm":null}}`,
			path:  "requests",
		},
		{
			name:  "log object inner field is not an entry field",
			input: `{"log":{"index":null,"term":null}}`,
			path:  "log",
		},
		{
			// entries 内的 term/index 既不是请求自身的字段，也不是合法条目的字段。
			name: "entries object inner fields are not request or entry fields",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":{"term":null,"index":null}}
			]}`,
			path: "entries",
		},
		{
			// 错误对象里的嵌套内容同样不算已识别字段。
			name:  "nested content inside error object is not recognized",
			input: `{"requests":{"nested":{"log":[{"index":null}]}}}`,
			path:  "requests",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message := runReplicateExpectInputError(t, tc.input, tc.path)
			if strings.Contains(message, "got null") {
				t.Fatalf("error object inner fields must not be reported as numeric nulls, got: %q", message)
			}
		})
	}
}

// 错误对象不能遮住其后的真实字段：log 被写成对象时，后面 committedIndex 的
// 数值 null 仍要在读取阶段被报告，而不是只报告 log 的类型错误。多个真实
// 字段都为 null 时按输入顺序报告第一个，错误对象内部的同名字段不参与次序。
func TestCLIErrorObjectDoesNotHideLaterRealNull(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "real null after log object",
			input: `{"log":{},"committedIndex":null}`,
			path:  "committedIndex",
		},
		{
			name:  "real null after requests object",
			input: `{"requests":{"term":null},"currentTerm":null}`,
			path:  "currentTerm",
		},
		{
			name: "real null after entries object",
			input: `{"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":{"term":null}}
			],"committedIndex":null}`,
			path: "committedIndex",
		},
		{
			// 数组字段重复出现时，前一份错误对象不影响后一份数组里的真实 null。
			name:  "duplicate array field: object then array with real null",
			input: `{"log":{},"log":[{"index":null,"term":1,"command":"a"}]}`,
			path:  "log[0].index",
		},
		{
			name:  "first real null in input order wins",
			input: `{"committedIndex":null,"currentTerm":null}`,
			path:  "committedIndex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}
