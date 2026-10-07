package main

import (
	"bytes"
	"strings"
	"testing"
)

// 重复 command 回归：公开说明要求同一对象里重复出现的字段由输入中的最后一次
// 出现决定内容，而 encoding/json 把 null 解进 string 字段时保持原值不变，
// {"command":"set count=7","command":null} 曾因此错误地留下前面的写入，开启
// applyKV 提交后还会把 count 写成 "7"。下列用例锁定：command 重复出现按输入
// 顺序取最后一个值（只改变大小写的写法同样命中），最后值为 null 时为空字符串，
// 与单独给出 command:null 或省略 command 的结果一致。

// 任务主场景：先提交 set count=3，再提交先写 set count=7、后写 null 的条目。
// 最后值为 null，命令为空：提交后按未知命令应用错误处理，错误索引指向该条目，
// 应用位置停在它之前，count 必须仍为 "3"，不能出现被覆盖掉的写入；复制与提交
// 不受影响（accepted 仍为 true、退出码 0）。
func TestCLIDuplicateCommandNullLastKeepsEarlierKV(t *testing.T) {
	input := `{"currentTerm":1,"applyKV":true,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
	   "entries":[{"index":1,"term":1,"command":"set count=3"}]},
	  {"term":1,"prevLogIndex":1,"prevLogTerm":1,"leaderCommit":2,
	   "entries":[{"index":2,"term":1,"command":"set count=7","command":null}]}
	]}`
	out, _ := runReplicateRaw(t, input)
	if !out.Results[1].Accepted {
		t.Fatalf("apply failure must not change acceptance: %+v", out.Results[1])
	}
	if out.FinalCommittedIndex != 2 {
		t.Fatalf("finalCommittedIndex = %d, want 2", out.FinalCommittedIndex)
	}
	if len(out.FinalLog) != 2 || out.FinalLog[1].Command != "" {
		t.Fatalf("final log = %+v, want the duplicated command resolved to empty string", out.FinalLog)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %v, want 1 (stops before the empty command)", out.FinalAppliedIndex)
	}
	if out.FinalKV["count"] != "3" {
		t.Fatalf("finalKV = %v, want count still \"3\": the masked write must not appear", out.FinalKV)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 {
		t.Fatalf("finalApplyError = %+v, want the unknown-command error at index 2", out.FinalApplyError)
	}
}

// 关闭 applyKV 时，finalLog 保存最后确定的命令（这里是空字符串），继续把它
// 当作普通字符串，输出不增加任何应用字段。
func TestCLIDuplicateCommandNullLastApplyKVDisabled(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
	   "entries":[{"index":1,"term":1,"command":"set count=7","command":null}]}
	]}`
	out, body := runReplicateRaw(t, input)
	if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
		t.Fatalf("final log = %+v, want the resolved empty command", out.FinalLog)
	}
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q:\n%s", field, body)
		}
	}
}

// 空命令尚未提交时不产生应用错误；单独写 command:null 与省略 command 的结果
// 与重复后取 null 完全一致。
func TestCLIDuplicateCommandNullUncommittedNoApplyError(t *testing.T) {
	input := `{"currentTerm":1,"applyKV":true,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
	   "entries":[{"index":1,"term":1,"command":"set count=7","command":null},
	              {"index":2,"term":1,"command":null},
	              {"index":3,"term":1}]}
	]}`
	out, _ := runReplicateRaw(t, input)
	if out.FinalApplyError != nil {
		t.Fatalf("uncommitted empty commands must not surface an apply error: %+v", out.FinalApplyError)
	}
	for i, entry := range out.FinalLog {
		if entry.Command != "" {
			t.Fatalf("final log entry %d command = %q, want empty string in all three forms", i, entry.Command)
		}
	}
}

// 先给 null 再给字符串时采用后面的字符串；只改变字段名大小写的重复写法
// 同样参与“最后一次出现定值”。
func TestCLIDuplicateCommandStringAfterNullWins(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":2,
	   "entries":[{"index":1,"term":1,"command":null,"command":"set a=1"},
	              {"index":2,"term":1,"command":"set b=2","Command":null}]}
	]}`
	out, _ := runReplicateRaw(t, input)
	if out.FinalLog[0].Command != "set a=1" {
		t.Fatalf("null then string: command = %q, want the later string", out.FinalLog[0].Command)
	}
	if out.FinalLog[1].Command != "" {
		t.Fatalf("case-variant null last: command = %q, want empty string", out.FinalLog[1].Command)
	}
}

// 初始 log 中的条目遵守同一条规则：先写字符串后写 null，最终命令为空字符串。
func TestCLIDuplicateCommandInInitialLog(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":0,
	  "log":[{"index":1,"term":1,"command":"set count=7","command":null}]}`
	out, _ := runReplicateRaw(t, input)
	if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
		t.Fatalf("final log = %+v, want the initial entry's command resolved to empty string", out.FinalLog)
	}
}

// command 写成数字、布尔值、对象或数组时仍是输入类型错误：退出码 1、标准
// 错误保留 replicate: 前缀、标准输出没有结果 JSON；后面的合法字符串不能
// 掩盖这次错误，前面的合法字符串同样不能。
func TestCLIDuplicateCommandNonStringOccurrenceRejected(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{"number", `{"index":1,"term":1,"command":5}`},
		{"boolean", `{"index":1,"term":1,"command":true}`},
		{"object", `{"index":1,"term":1,"command":{}}`},
		{"array", `{"index":1,"term":1,"command":[]}`},
		{"bad then legal string does not mask", `{"index":1,"term":1,"command":5,"command":"set a=1"}`},
		{"legal string then bad", `{"index":1,"term":1,"command":"set a=1","command":5}`},
		{"case-variant bad occurrence", `{"index":1,"term":1,"Command":5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
			   "entries":[` + tc.entry + `]}
			]}`
			var stdout, stderr bytes.Buffer
			code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("no result JSON may be produced on a field type error, got: %s", stdout.String())
			}
			message := stderr.String()
			if !strings.HasPrefix(message, "replicate:") || !strings.Contains(message, "command") {
				t.Fatalf("error must carry replicate: prefix and name command, got: %q", message)
			}
		})
	}
}

// 初始日志条目里的非法 command 类型同样在读取阶段拒绝整份输入。
func TestCLICommandNonStringInInitialLogRejected(t *testing.T) {
	input := `{"currentTerm":1,"log":[{"index":1,"term":1,"command":false}]}`
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "replicate:") {
		t.Fatalf("unexpected stdout/stderr: %q / %q", stdout.String(), stderr.String())
	}
}
