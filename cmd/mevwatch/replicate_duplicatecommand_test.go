package main

import (
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// 重复 command 字段回归：同一条日志条目对象里 command 允许重复，按输入中的
// 出现顺序取最后一个值，只改变字段名大小写的写法也参与判断。最后值为字符串
// 时按原文保留；最后值为 null 时为空字符串，与单独给出 command:null 或省略
// command 的结果一致；先 null 后字符串时采用后面的字符串。初始 log 与请求
// entries 中的条目都遵守这条规则。

// 任务主场景（关闭键值应用）：同一条目先写 "set count=7" 再写 null，
// finalLog 必须保存最后确定的空命令，仍把它当作普通字符串，输出不带应用字段。
func TestCLIDuplicateCommandStringThenNullLeavesEmpty(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
	   "entries":[{"index":1,"term":1,"command":"set count=7","command":null}]}
	]}`
	out, raw := runReplicateRaw(t, input)
	if len(out.FinalLog) != 1 || out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: ""}) {
		t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
	}
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(raw, field) {
			t.Fatalf("applyKV off: output must not contain %q:\n%s", field, raw)
		}
	}
}

// 同一条目先 null 后字符串时采用后面的字符串；只改大小写的写法也按顺序参与。
func TestCLIDuplicateCommandNullThenStringKeepsLast(t *testing.T) {
	cases := []struct {
		name  string
		pairs string
		want  string
	}{
		{name: "null then string", pairs: `"command":null,"command":"set count=7"`, want: "set count=7"},
		{name: "string then case-variant string", pairs: `"command":"a","Command":"b"`, want: "b"},
		{name: "case-variant string then lowercase", pairs: `"COMMAND":"a","command":"b"`, want: "b"},
		{name: "case variant then null", pairs: `"COMMAND":"a","command":null`, want: ""},
		{name: "null via case variant last", pairs: `"command":"a","Command":null`, want: ""},
		{name: "string null then string again", pairs: `"command":"a","command":null,"command":"c"`, want: "c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[{"index":1,"term":1,` + tc.pairs + `}]}]}`
			out := runReplicateJSON(t, input)
			if len(out.FinalLog) != 1 || out.FinalLog[0].Command != tc.want {
				t.Fatalf("final log = %+v, want command %q", out.FinalLog, tc.want)
			}
		})
	}
}

// 单独 command:null 与省略 command 的结果一致，都是空字符串。
func TestCLISingleOrOmittedCommandIsEmpty(t *testing.T) {
	for _, entry := range []string{
		`{"index":1,"term":1,"command":null}`,
		`{"index":1,"term":1}`,
	} {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,"entries":[` + entry + `]}]}`
		out := runReplicateJSON(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
			t.Fatalf("final log = %+v, want empty command", out.FinalLog)
		}
	}
}

// 初始 log 中的条目同样遵守重复 command 规则：字符串后接 null 最终为空。
func TestCLIDuplicateCommandInInitialLogLastWins(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":0,
	  "log":[{"index":1,"term":1,"command":"set a=1","command":null}],"requests":[]}`
	out := runReplicateJSON(t, input)
	if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
		t.Fatalf("initial log = %+v, want empty command from last null", out.FinalLog)
	}
}

// 任务主场景（开启键值应用）：先提交 set count=3，再提交先写 set count=7、
// 后写 null 的条目。空命令尚未提交时不报错；提交后按既有未知命令错误处理，
// 错误索引指向该条目，应用位置停在它之前，count 必须仍为 "3"，后面的命令不
// 再应用，且复制仍被接受、退出码为 0。
func TestCLIDuplicateCommandNullAfterSetAppliesAsEmptyError(t *testing.T) {
	input := `{
	  "currentTerm": 1, "committedIndex": 0, "log": [], "applyKV": true,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "set count=3"}]},
	    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 2,
	     "entries": [{"index": 2, "term": 1, "command": "set count=7", "command": null}]}
	  ]
	}`
	out := runReplicateJSON(t, input)

	if len(out.Results) != 2 {
		t.Fatalf("results = %+v, want 2 results", out.Results)
	}
	// 应用失败不改变请求是否被接受：第二条仍 accepted。
	if !out.Results[1].Accepted || out.Results[1].Reason != mevwatch.ReasonOK {
		t.Fatalf("second request still accepted: %+v", out.Results[1])
	}
	if out.Results[1].AppliedIndex == nil || *out.Results[1].AppliedIndex != 1 {
		t.Fatalf("appliedIndex = %+v, want 1 (stopped before the empty entry)", out.Results[1].AppliedIndex)
	}
	if out.Results[1].ApplyError == nil || out.Results[1].ApplyError.Index != 2 ||
		out.Results[1].ApplyError.Reason != mevwatch.ApplyReasonUnknownCommand {
		t.Fatalf("applyError = %+v, want index 2 unknown command", out.Results[1].ApplyError)
	}

	if out.FinalCommittedIndex != 2 {
		t.Fatalf("finalCommittedIndex = %d, want 2 (commitment is unaffected by apply failure)", out.FinalCommittedIndex)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %+v, want 1", out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 {
		t.Fatalf("finalApplyError = %+v, want index 2", out.FinalApplyError)
	}
	if got := out.FinalKV["count"]; got != "3" {
		t.Fatalf("count = %q, want %q (the overwritten write must never apply)", got, "3")
	}
}

// 空命令尚未提交时不产生应用错误，也不提前暴露：复制照常接受。
func TestCLIDuplicateCommandEmptyUncommittedNoApplyError(t *testing.T) {
	input := `{"currentTerm":1,"applyKV":true,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
	   "entries":[{"index":1,"term":1,"command":"set count=7","command":null}]}
	]}`
	out := runReplicateJSON(t, input)
	if !out.Results[0].Accepted {
		t.Fatalf("replication must still be accepted: %+v", out.Results[0])
	}
	if out.Results[0].ApplyError != nil {
		t.Fatalf("uncommitted empty command must not surface an apply error: %+v", out.Results[0].ApplyError)
	}
	if out.FinalApplyError != nil || len(out.FinalKV) != 0 {
		t.Fatalf("nothing committed yet: finalApplyError=%+v finalKV=%v", out.FinalApplyError, out.FinalKV)
	}
}

// 初始 log 的空命令在开启 applyKV 且已提交时，按既有未知命令规则在读取后
// （正常输出中）报告应用错误，而不是读取阶段失败。
func TestCLIDuplicateCommandInitialLogEmptyApplyError(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":1,"applyKV":true,
	  "log":[{"index":1,"term":1,"command":"set x=9","command":null}]}`
	out := runReplicateJSON(t, input)
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 0 {
		t.Fatalf("finalAppliedIndex = %+v, want 0", out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 ||
		out.FinalApplyError.Reason != mevwatch.ApplyReasonUnknownCommand {
		t.Fatalf("finalApplyError = %+v, want index 1 unknown command", out.FinalApplyError)
	}
}

// command 写成数字、布尔、对象或数组时仍是输入类型错误；后面的合法字符串不
// 能掩盖这次错误。退出码 1、标准错误保留 replicate: 前缀、标准输出为空。
func TestCLIDuplicateCommandNonStringTypeRejected(t *testing.T) {
	cases := []struct {
		name    string
		command string
		kind    string
	}{
		{name: "number", command: `123`, kind: "number"},
		{name: "bool", command: `true`, kind: "bool"},
		{name: "object", command: `{"x":1}`, kind: "object"},
		{name: "array", command: `["a"]`, kind: "array"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" single", func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"entries":[{"index":1,"term":1,"command":` + tc.command + `}]}]}`
			assertCommandTypeError(t, input, tc.kind)
		})
		t.Run(tc.name+" before later string", func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"entries":[{"index":1,"term":1,"command":` + tc.command + `,"command":"ok"}]}]}`
			assertCommandTypeError(t, input, tc.kind)
		})
		t.Run(tc.name+" before later null", func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"entries":[{"index":1,"term":1,"command":` + tc.command + `,"command":null}]}]}`
			assertCommandTypeError(t, input, tc.kind)
		})
	}
}

// 初始 log 中的非法 command 类型同样在读取阶段拒绝整份输入。
func TestCLIDuplicateCommandNonStringInInitialLogRejected(t *testing.T) {
	input := `{"currentTerm":1,"log":[{"index":1,"term":1,"command":1}]}`
	runReplicateExpectInputError(t, input, "log.command")
}

// assertCommandTypeError 断言整份输入在读取阶段因 command 类型错误被拒绝：
// 退出码 1、stdout 为空、stderr 带 replicate: 前缀并指出 command 字段与实际
// JSON 值类别。
func assertCommandTypeError(t *testing.T, input, kind string) {
	t.Helper()
	message := runReplicateExpectInputError(t, input, "command")
	for _, fragment := range []string{"cannot unmarshal " + kind, "of type string"} {
		if !strings.Contains(message, fragment) {
			t.Fatalf("error message missing %q: %q", fragment, message)
		}
	}
}
