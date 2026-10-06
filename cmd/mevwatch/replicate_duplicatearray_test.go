package main

import (
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// 重复数组字段回归：同一输入中 log、requests 以及同一请求对象内的 entries
// 重复出现时，最后一份数组必须“整体替换”前一份——后一份元素省略的数值按
// 默认值 0、省略的命令按空字符串解释，不能从同位置旧元素借用任期、索引、
// 提交位置、命令或条目；数组变短也只保留后一份实际给出的元素。标准库把第
// 二个数组解进既有切片时会复用旧底层数组，这些用例锁定自定义解码的行为。

// 任务主场景（关闭键值应用）：当前任期 1、已提交索引 1，先给 log 一条
// index=1、term=1、command="set a=1" 的日志，再给同索引同任期却省略 command
// 的一份日志。最终日志的命令必须为空，不能保留前一份的 "set a=1"。
func TestCLIDuplicateLogLastEntryOmitsCommandLeavesEmptyCommand(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":1,
	  "log":[{"index":1,"term":1,"command":"set a=1"}],
	  "log":[{"index":1,"term":1}]}`
	out, body := runReplicateRaw(t, input)
	if out.FinalCommittedIndex != 1 || len(out.FinalLog) != 1 {
		t.Fatalf("unexpected final state: %+v", out)
	}
	entry := out.FinalLog[0]
	if entry.Index != 1 || entry.Term != 1 || entry.Command != "" {
		t.Fatalf("final log entry = %+v, want {1 1 \"\"} (command must not be borrowed)", entry)
	}
	if strings.Contains(body, "set a=1") {
		t.Fatalf("the first array's command must not appear in the output:\n%s", body)
	}
}

// 同一主场景开启 applyKV：空命令按既有未知命令规则报告索引 1 的应用错误，
// 已应用索引停在 0，键值表为空——绝不能应用本应已被替换掉的 set a=1。
func TestCLIDuplicateLogOmittedCommandApplyKVReportsUnknownCommand(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":1,"applyKV":true,
	  "log":[{"index":1,"term":1,"command":"set a=1"}],
	  "log":[{"index":1,"term":1}]}`
	out, body := runReplicateRaw(t, input)
	if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
		t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 ||
		out.FinalApplyError.Reason != mevwatch.ApplyReasonUnknownCommand {
		t.Fatalf("finalApplyError = %+v, want unknown-command error at index 1", out.FinalApplyError)
	}
	if out.FinalAppliedIndex == nil || *out.FinalAppliedIndex != 0 {
		t.Fatalf("finalAppliedIndex = %+v, want 0 (failing entry is index 1)", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 0 {
		t.Fatalf("finalKV = %v, want empty: the replaced write must not be applied", out.FinalKV)
	}
	if strings.Contains(body, "set a=1") {
		t.Fatalf("the replaced command must not appear in the output:\n%s", body)
	}
}

// 后一份日志省略 index 或 term 时按非法初始状态结束（退出码 1、stderr 带
// replicate: 前缀），不能拿前一份同位置元素的合法值补齐让它通过。
func TestCLIDuplicateLogLastEntryOmitsIndexOrTermRejectsInitialState(t *testing.T) {
	cases := []struct {
		name      string
		secondLog string
	}{
		{name: "omit index", secondLog: `[{"term":1}]`},
		{name: "omit term", secondLog: `[{"index":1}]`},
		{name: "omit index and term", secondLog: `[{"command":"set a=1"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"currentTerm":1,"committedIndex":1,
			  "log":[{"index":1,"term":1,"command":"set a=1"}],
			  "log":` + tc.secondLog + `}`
			runReplicateExpectInputError(t, input, "invalid initial state")
		})
	}
}

// 后一份 log 整体变短：只保留后一份实际给出的元素，前一份多出的尾部不能
// 留在底层数组上；committedIndex 也按替换后的短日志长度核对。
func TestCLIDuplicateLogShorterArrayReplacesWholesale(t *testing.T) {
	t.Run("shorter second array keeps only its elements", func(t *testing.T) {
		input := `{"currentTerm":1,"committedIndex":0,
		  "log":[{"index":1,"term":1,"command":"a"},{"index":2,"term":1,"command":"b"}],
		  "log":[{"index":1,"term":1,"command":"c"}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 {
			t.Fatalf("final log = %+v, want only the second array's single element", out.FinalLog)
		}
		if out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "c"}) {
			t.Fatalf("final log[0] = %+v, want {1 1 c}", out.FinalLog[0])
		}
	})

	t.Run("committed index is checked against the shorter replacement", func(t *testing.T) {
		input := `{"currentTerm":1,"committedIndex":2,
		  "log":[{"index":1,"term":1,"command":"a"},{"index":2,"term":1,"command":"b"}],
		  "log":[{"index":1,"term":1,"command":"c"}]}`
		runReplicateExpectInputError(t, input, "invalid initial state")
	})

	t.Run("second array empty drops the whole log", func(t *testing.T) {
		input := `{"currentTerm":1,"committedIndex":0,
		  "log":[{"index":1,"term":1,"command":"a"},{"index":2,"term":1,"command":"b"}],
		  "log":[]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 0 {
			t.Fatalf("final log = %+v, want empty after replacement by []", out.FinalLog)
		}
	})
}

// 后一份元素只在自身写出的字段上取值，不能借用同位置旧元素的任一字段：
// 省略命令得到空串、省略数值得到 0（因此后一份日志非法），字段不会跨元素
// 位置或跨数组残留。
func TestCLIDuplicateLogNoFieldBorrowedAcrossPositions(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":0,
	  "log":[{"index":1,"term":1,"command":"set a=1"},{"index":2,"term":1,"command":"set b=2"}],
	  "log":[{"index":1,"command":""}]}`
	runReplicateExpectInputError(t, input, "invalid initial state")
}

// 同一请求对象内 entries 重复出现：最后一份条目整体替换。
func TestCLIDuplicateEntriesInRequestReplaceWholesale(t *testing.T) {
	t.Run("omitted command becomes empty string", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"set a=1"}],
		   "entries":[{"index":1,"term":1}]}
		]}`
		out, body := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
			t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
		}
		if strings.Contains(body, "set a=1") {
			t.Fatalf("the replaced command must not appear in the output:\n%s", body)
		}
	})

	t.Run("omitted index is the entry's own zero, recorded as a field rejection", func(t *testing.T) {
		// 后一份条目省略 index：按默认值 0 解释，条目索引不从 prevLogIndex+1
		// 连续，整条请求按既有字段规则被拒，状态保持空日志；不能借前一份的
		// index 1 让它被接受。
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"set a=1"}],
		   "entries":[{"term":1}]}
		]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.Results) != 1 {
			t.Fatalf("unexpected results: %+v", out.Results)
		}
		result := out.Results[0]
		if result.Accepted || result.Reason != mevwatch.ReasonEntryIndexGap {
			t.Fatalf("result = %+v, want non-consecutive entry rejection", result)
		}
		if len(out.FinalLog) != 0 {
			t.Fatalf("rejected request must leave the log empty, got %+v", out.FinalLog)
		}
	})

	t.Run("shorter second entries array drops the old tail", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"a"},{"index":2,"term":1,"command":"b"}],
		   "entries":[{"index":1,"term":1,"command":"c"}]}
		]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0] != (mevwatch.LogEntry{Index: 1, Term: 1, Command: "c"}) {
			t.Fatalf("final log = %+v, want only {1 1 c}", out.FinalLog)
		}
	})
}

// requests 数组重复出现：最后一份请求数组整体替换，元素省略的数值与条目
// 数组都按自身默认值解释，不从前一份同位置请求借用。
func TestCLIDuplicateRequestsReplaceWholesale(t *testing.T) {
	t.Run("second array element omits term: zero term, not the old request's", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[{}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.Results) != 1 {
			t.Fatalf("results = %+v, want only the second array's single request", out.Results)
		}
		// 省略 term 得到 0：低于当前任期 1，按既有低任期规则拒绝；这正说明
		// 它没有借用前一份请求的 term 1。
		if out.Results[0].Accepted || out.Results[0].Reason != mevwatch.ReasonStaleTerm {
			t.Fatalf("result = %+v, want stale-term rejection for omitted term 0", out.Results[0])
		}
	})

	t.Run("second requests array shorter keeps only its requests", func(t *testing.T) {
		input := `{"currentTerm":3,
		  "requests":[
		    {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]},
		    {"term":2,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[{"term":3,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.Results) != 1 || out.Results[0].Term != 3 || !out.Results[0].Accepted {
			t.Fatalf("results = %+v, want only the second array's accepted term-3 request", out.Results)
		}
	})
}

// 字段名只改变大小写仍视为同一字段，取文本中最后一次出现的数组。
func TestCLIDuplicateArraysCaseVariantLastArrayWins(t *testing.T) {
	t.Run("LOG then log", func(t *testing.T) {
		input := `{"currentTerm":1,"committedIndex":1,
		  "LOG":[{"index":1,"term":1,"command":"leak"}],
		  "log":[{"index":1,"term":1}]}`
		out, body := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
			t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
		}
		if strings.Contains(body, "leak") {
			t.Fatalf("first LOG array content must not survive:\n%s", body)
		}
	})

	t.Run("REQUESTS then requests", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "REQUESTS":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.Results) != 0 {
			t.Fatalf("results = %+v, want no requests (second array is empty)", out.Results)
		}
	})

	t.Run("ENTRIES then entries inside one request", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "ENTRIES":[{"index":1,"term":1,"command":"leak"}],
		   "entries":[{"index":1,"term":1}]}]}`
		out, body := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "" {
			t.Fatalf("final log = %+v, want one entry with empty command", out.FinalLog)
		}
		if strings.Contains(body, "leak") {
			t.Fatalf("first ENTRIES array content must not survive:\n%s", body)
		}
	})
}

// 数组字段显式为 null 的既有处理保持兼容：null 不解出任何元素，不影响另一次
// 出现给出的数组（先 null 后数组时保留后一份数组；先数组后 null 时 null 同样
// 不补出元素，沿用标准库重复键后者生效的旧行为）。
func TestCLIDuplicateArraysNullKeepsLegacyBehavior(t *testing.T) {
	t.Run("null then array keeps the array", func(t *testing.T) {
		input := `{"currentTerm":1,"committedIndex":1,
		  "log":null,
		  "log":[{"index":1,"term":1,"command":"x"}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "x" {
			t.Fatalf("final log = %+v, want the array given after null", out.FinalLog)
		}
	})

	t.Run("entries null then array keeps the array", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":null,
		   "entries":[{"index":1,"term":1,"command":"y"}]}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "y" {
			t.Fatalf("final log = %+v, want the entries given after null", out.FinalLog)
		}
	})
}

// 没有重复字段的输入、请求被逐条应用的既有行为不受自定义解码影响：一个简单
// 的追加 + 提交流程仍然完整跑通（含 applyKV）。
func TestCLIDuplicateArrayDecoderKeepsOrdinaryInputs(t *testing.T) {
	input := `{"currentTerm":1,"applyKV":true,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
	   "entries":[{"index":1,"term":1,"command":"set a=1"}]}
	]}`
	out, _ := runReplicateRaw(t, input)
	if len(out.Results) != 1 || !out.Results[0].Accepted {
		t.Fatalf("ordinary request must still be accepted: %+v", out.Results)
	}
	if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "set a=1" {
		t.Fatalf("final log = %+v, want the single appended entry", out.FinalLog)
	}
	if len(out.FinalKV) != 1 || out.FinalKV["a"] != "1" {
		t.Fatalf("finalKV = %v, want a=1", out.FinalKV)
	}
}
