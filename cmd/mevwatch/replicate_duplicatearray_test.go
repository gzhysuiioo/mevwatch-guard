package main

import (
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// 重复数组整体替换回归：同一输入里 log、requests 以及同一请求对象内的
// entries 重复出现时，最后一份数组必须整体替换之前的数组。元素只按最后一份
// 的内容解释——省略的命令为空字符串、省略的数值为 0、省略的条目数组为空，
// 不能从相同位置的旧元素继承任期、索引、提交位置、命令或条目；数组变短时也
// 只保留最后一份实际给出的元素。下列用例锁定这些语义。

// 任务主场景（关闭键值应用）：任期 1、已提交索引 1，先给一条
// index=term=1、command="set a=1" 的日志，再给一条同索引同任期却省略
// command 的日志。最终日志命令必须为空，而不是前一份的 set a=1。
func TestCLIDuplicateLogLaterEntryOmitsCommandLeavesEmpty(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":1,
	  "log":[{"index":1,"term":1,"command":"set a=1"}],
	  "log":[{"index":1,"term":1}]}`
	out := runReplicateJSON(t, input)
	if len(out.FinalLog) != 1 {
		t.Fatalf("final log has %d entries, want 1: %+v", len(out.FinalLog), out.FinalLog)
	}
	got := out.FinalLog[0]
	want := mevwatch.LogEntry{Index: 1, Term: 1, Command: ""}
	if got != want {
		t.Fatalf("final log entry = %+v, want %+v (command must not be borrowed from the first log)", got, want)
	}
}

// 同一场景开启 applyKV：空命令按现有未知命令规则报告索引 1 的应用错误，
// 已应用索引停在 0，键值表为空——被替换掉的 set a=1 不能留下写入。
func TestCLIDuplicateLogLaterEmptyCommandApplyKVReportsError(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":1,"applyKV":true,
	  "log":[{"index":1,"term":1,"command":"set a=1"}],
	  "log":[{"index":1,"term":1}]}`
	out := runReplicateJSON(t, input)
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 0 {
		t.Fatalf("finalAppliedIndex = %+v, want 0", out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 ||
		out.FinalApplyError.Reason != mevwatch.ApplyReasonUnknownCommand {
		t.Fatalf("finalApplyError = %+v, want index 1 unknown command", out.FinalApplyError)
	}
	if len(out.FinalKV) != 0 {
		t.Fatalf("finalKV = %v, want empty table (the replaced write must not apply)", out.FinalKV)
	}
}

// 最后一份日志的条目若省略 index 或 term，按默认 0 解释并以非法初始状态
// 结束，不能借先前条目的合法值通过校验。
func TestCLIDuplicateLogLaterEntryOmitsIndexOrTermIsInvalidInitialState(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{name: "omits index", entry: `{"term":1}`},
		{name: "omits term", entry: `{"index":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"currentTerm":1,"committedIndex":1,
			  "log":[{"index":1,"term":1,"command":"set a=1"}],
			  "log":[` + tc.entry + `]}`
			runReplicateExpectInputError(t, input, "invalid initial state")
		})
	}
}

// 后一份 log 更短时只保留它实际给出的元素，前一份多出的尾部必须丢弃，
// 且保留下来的元素不借用旧内容。
func TestCLIDuplicateLogShorterArrayDropsOldTail(t *testing.T) {
	input := `{"currentTerm":2,
	  "log":[{"index":1,"term":1,"command":"a"},{"index":2,"term":2,"command":"b"}],
	  "log":[{"index":1,"term":1,"command":"Z"}]}`
	out := runReplicateJSON(t, input)
	want := []mevwatch.LogEntry{{Index: 1, Term: 1, Command: "Z"}}
	if len(out.FinalLog) != len(want) || out.FinalLog[0] != want[0] {
		t.Fatalf("final log = %+v, want only the second array's %+v", out.FinalLog, want)
	}
}

// 后一份 log 为 null 时与单份 log:null 一致：日志为空。
func TestCLIDuplicateLogLaterNullEmptiesLog(t *testing.T) {
	input := `{"currentTerm":1,
	  "log":[{"index":1,"term":1,"command":"a"}],"log":null,"requests":[]}`
	out := runReplicateJSON(t, input)
	if len(out.FinalLog) != 0 {
		t.Fatalf("final log = %+v, want empty after the later null occurrence", out.FinalLog)
	}
}

// 同一请求对象内 entries 重复出现：最后一份条目整体替换，后者省略 command
// 时最终日志的命令为空；applyKV 开启时报告索引 1 的未知命令应用错误。
func TestCLIDuplicateEntriesLaterEntryStandsAlone(t *testing.T) {
	t.Run("applyKV off: empty command, not inherited", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"set a=1"}],
		   "entries":[{"index":1,"term":1}]}]}`
		out := runReplicateJSON(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: ""}) {
			t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
		}
	})

	t.Run("applyKV on: replaced write does not apply", func(t *testing.T) {
		input := `{"currentTerm":1,"applyKV":true,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"set a=1"}],
		   "entries":[{"index":1,"term":1}]}]}`
		out := runReplicateJSON(t, input)
		if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 0 {
			t.Fatalf("finalAppliedIndex = %+v, want 0", out.FinalAppliedIndex)
		}
		if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 ||
			out.FinalApplyError.Reason != mevwatch.ApplyReasonUnknownCommand {
			t.Fatalf("finalApplyError = %+v, want index 1 unknown command", out.FinalApplyError)
		}
		if len(out.FinalKV) != 0 {
			t.Fatalf("finalKV = %v, want empty table", out.FinalKV)
		}
	})

	t.Run("later entry omits index: field rule rejection, no inherited index", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
		   "entries":[{"index":1,"term":1,"command":"a"}],
		   "entries":[{"term":1}]}]}`
		out := runReplicateJSON(t, input)
		if len(out.Results) != 1 || out.Results[0].Accepted ||
			out.Results[0].Reason != mevwatch.ReasonEntryIndexGap {
			t.Fatalf("later entries element must be validated on its own, got %+v", out.Results)
		}
	})

	t.Run("later entries array shorter: old tail dropped", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
		   "entries":[{"index":1,"term":1,"command":"a"},{"index":2,"term":1,"command":"b"}],
		   "entries":[{"index":1,"term":1,"command":"Z"}]}]}`
		out := runReplicateJSON(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "Z" {
			t.Fatalf("final log = %+v, want only the later entries array's Z", out.FinalLog)
		}
	})
}

// 根对象 requests 重复出现时最后一份数组整体替换：结果只与最后一份请求一一
// 对应，后一份更短时结果数量也随之变短；后一份里省略标量字段的请求按默认 0
// 独立校验，不能沿用前一份同位置请求的任期等字段。
func TestCLIDuplicateRequestsLastArrayStandsAlone(t *testing.T) {
	t.Run("shorter later array replaces wholesale", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "requests":[
		    {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]},
		    {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[
		    {"term":2,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]}`
		out := runReplicateJSON(t, input)
		if len(out.Results) != 1 {
			t.Fatalf("got %d results, want 1 (only the later requests array): %+v", len(out.Results), out.Results)
		}
		if out.Results[0].Term != 2 || out.FinalTerm != 2 {
			t.Fatalf("result = %+v finalTerm = %d, want the later array's term-2 request",
				out.Results[0], out.FinalTerm)
		}
	})

	t.Run("later request omits scalar fields: zero-valued request, not merged", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[{}]}`
		out := runReplicateJSON(t, input)
		if len(out.Results) != 1 || out.Results[0].Accepted ||
			out.Results[0].Reason != mevwatch.ReasonStaleTerm {
			t.Fatalf("the later request must be judged on its own zero-valued fields, got %+v", out.Results)
		}
	})
}

// 数组字段名只改变大小写时，仍取文本中最后一次出现的数组。
func TestCLIDuplicateArrayCaseVariantLastArrayWins(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  mevwatch.LogEntry
	}{
		{
			name: "LOG after log",
			input: `{"currentTerm":1,
			  "log":[{"index":1,"term":1,"command":"a"}],
			  "LOG":[{"index":1,"term":1,"command":"b"}]}`,
			want: mevwatch.LogEntry{Index: 1, Term: 1, Command: "b"},
		},
		{
			name: "log after LOG",
			input: `{"currentTerm":1,
			  "LOG":[{"index":1,"term":1,"command":"a"}],
			  "log":[{"index":1,"term":1,"command":"b"}]}`,
			want: mevwatch.LogEntry{Index: 1, Term: 1, Command: "b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runReplicateJSON(t, tc.input)
			if len(out.FinalLog) != 1 || out.FinalLog[0] != tc.want {
				t.Fatalf("final log = %+v, want %+v from the last textual occurrence", out.FinalLog, tc.want)
			}
		})
	}
}
