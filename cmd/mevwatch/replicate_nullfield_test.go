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

// 同名字段在对象中重复出现时，JSON 解码成 map 只保留最后一次出现：先前的
// null 会被后面的数字盖掉。任何一次出现是数值 null 都必须拒绝整份输入，
// 不论 null 在数字之前还是之后，也不论重复字段是否只改变大小写。
func TestCLINullNumericFieldDuplicatedStillRejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			// 任务主场景：null 在前、数字在后。
			name:  "root currentTerm null then number",
			input: `{"currentTerm":null,"currentTerm":1}`,
			path:  "currentTerm",
		},
		{
			name:  "root committedIndex number then null",
			input: `{"committedIndex":0,"committedIndex":null}`,
			path:  "committedIndex",
		},
		{
			name:  "root currentTerm case-only spelling",
			input: `{"Currentterm":null,"currentTerm":1}`,
			path:  "currentTerm",
		},
		{
			name: "request field null before number",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":null,"leaderCommit":0,"entries":[]}
			]}`,
			path: "requests[0].leaderCommit",
		},
		{
			name: "request term number before null",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"term":null,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}
			]}`,
			path: "requests[0].term",
		},
		{
			name: "request numeric field case-only spelling",
			input: `{"currentTerm":1,"requests":[
			  {"Term":1,"PrevLogIndex":0,"PrevLogTerm":0,"LEADERCOMMIT":null,"entries":[]}
			]}`,
			path: "requests[0].leaderCommit",
		},
		{
			name: "entry index null then number",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[{"index":null,"index":1,"term":1,"command":"a"}]}
			]}`,
			path: "requests[0].entries[0].index",
		},
		{
			name: "entry term number then null",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[{"index":1,"term":1,"term":null,"command":"a"}]}
			]}`,
			path: "requests[0].entries[0].term",
		},
		{
			name: "entry field case-only spelling",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[{"Index":1,"TERM":null,"command":"a"}]}
			]}`,
			path: "requests[0].entries[0].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}

// log、requests、entries 数组字段自身重复出现时，每一份数组都要检查：任一
// 份数组里的数值 null 不能被后面（或前面）的数组盖掉。字段名只改变大小写
// 时同样命中；数组下标按该份数组从 0 计数，字段位置使用标准字段名。
func TestCLINullNumericFieldInDuplicatedArraysRejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "duplicate log null hidden in first array",
			input: `{"currentTerm":1,"log":[{"index":null,"term":1}],"log":[],"requests":[]}`,
			path:  "log[0].index",
		},
		{
			name:  "duplicate log null in second array",
			input: `{"currentTerm":1,"log":[],"log":[{"index":1,"term":null}],"requests":[]}`,
			path:  "log[0].term",
		},
		{
			name:  "duplicate log case-only spelling",
			input: `{"currentTerm":1,"Log":[],"loG":[{"index":1,"term":null}],"requests":[]}`,
			path:  "log[0].term",
		},
		{
			name: "duplicate requests null hidden in first array",
			input: `{"currentTerm":1,
			  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[{"index":null,"term":1}]}],
			  "requests":[]}`,
			path: "requests[0].entries[0].index",
		},
		{
			name: "duplicate requests null in second array",
			input: `{"currentTerm":1,"requests":[],
			  "requests":[{"term":null,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]}`,
			path: "requests[0].term",
		},
		{
			name: "duplicate entries null hidden in first array",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[{"index":null,"term":1}],"entries":[]}
			]}`,
			path: "requests[0].entries[0].index",
		},
		{
			name: "duplicate entries null in second array",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[],"entries":[{"index":1,"term":null}]}
			]}`,
			path: "requests[0].entries[0].term",
		},
		{
			name: "duplicate entries case-only spelling",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "Entries":[],"ENTRIES":[{"index":1,"term":null}]}
			]}`,
			path: "requests[0].entries[0].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}

// 即使条目尚未提交、或 applyKV 没有开启，重复字段中的数值 null 仍在读取
// 输入阶段拒绝整份输入。
func TestCLINullInDuplicatedFieldsRejectedBeforeApply(t *testing.T) {
	// applyKV 开启但 leaderCommit 为 0：条目永远不会提交，null 检查也不
	// 延迟到应用阶段。
	input := `{
	  "currentTerm": 1,
	  "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
	     "entries": [{"index": 1, "term": null, "term": 1, "command": "set a=1"}]}
	  ]
	}`
	runReplicateExpectInputError(t, input, "requests[0].entries[0].term")

	// applyKV 省略（关闭）时同样拒绝，不产生任何普通拒绝结果。
	input = `{
	  "currentTerm": 1,
	  "requests": [
	    {"term": 1, "term": null, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
	     "entries": []},
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
	     "entries": []}
	  ]
	}`
	runReplicateExpectInputError(t, input, "requests[0].term")
}

// 不含数值 null 的重复字段不额外禁止：仍按既有 JSON 读取规则（后值覆盖前值）
// 得到初始状态与请求。
func TestCLIDuplicateFieldsWithoutNullKeepLastWinsSemantics(t *testing.T) {
	input := `{"currentTerm":1,"currentTerm":2,"requests":[]}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"finalTerm": 2`) {
		t.Fatalf("duplicate valid field should keep last value, got: %s", stdout.String())
	}
}

// 显式 null 与省略字段、合法数字 0 要区分开：省略仍采用默认值，{} 仍是合法
// 空初始状态，日志起点的索引 0 与任期 0 保持原有含义；数组字段与未知键里的
// null 沿用已有处理，不受数值校验影响。未知对象即使含有 term、index 同名键，
// 也不属于日志数值字段。
func TestCLINullValidationKeepsExistingSemantics(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": null,
	  "unknownKey": null,
	  "meta": {"term": null, "entries": [{"index": null, "term": null}]},
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
	     "entries": null, "extra": {"term": null}},
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "set a=1",
	                  "meta": {"index": null, "term": null}}]}
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
