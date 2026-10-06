package mevwatch

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// 本文件固定 incr 在一条命令同时存在多个问题时的错误原因选择：命令自身的
// 格式或增量错误优先于键值表中的当前值问题；四类原因（命令格式、增量非法、
// 当前值非法、相加溢出）按此顺序逐级成为失败原因，且各自保留已有的错误
// 文本，不能合并成笼统的数值错误。

// TestKVIncrReasonPriorityParseLevel 固定解析阶段的优先级：键的格式问题
// （空键、键含空白、缺等号）与非法增量同时存在时，报告键的格式问题——键的
// 校验先于增量的解析，与 set 共用同一套键规则。
func TestKVIncrReasonPriorityParseLevel(t *testing.T) {
	cases := []struct {
		command    string
		wantReason string
	}{
		{"incr =oops", ApplyReasonEmptyKey},            // 空键 + 非法增量：报空键
		{"incr =1", ApplyReasonEmptyKey},               // 空键 + 合法增量：仍报空键
		{"incr k k=oops", ApplyReasonKeyHasWhitespace}, // 键含空白 + 非法增量：报键含空白
		{"incr a=b=oops", ApplyReasonIncrBadDelta},     // 第一个等号分隔，额外等号属于增量
		{"incr count", ApplyReasonIncrMissingEquals},   // 缺等号：谈不上增量是否合法
		{"incr count=oops", ApplyReasonIncrBadDelta},   // 键合法后才轮到增量
		{"incr count=1.5", ApplyReasonIncrBadDelta},
	}
	for _, tc := range cases {
		_, reason := parseKVCommand(tc.command)
		if reason != tc.wantReason {
			t.Fatalf("parseKVCommand(%q) reason = %q, want %q", tc.command, reason, tc.wantReason)
		}
	}
}

// TestKVIncrReasonPriorityChain 固定应用阶段的完整优先级链：每条用例让一条
// incr 命令同时暴露多个问题，断言只有按优先级排在最前的原因成为该条命令的
// 失败原因；失败命令不创建键、不覆盖值，应用位置停在它前一条，此前已成功
// 的写入保留。
func TestKVIncrReasonPriorityChain(t *testing.T) {
	maxText := strconv.FormatInt(math.MaxInt64, 10)
	cases := []struct {
		name       string
		setup      string // 先提交的写入，为出错命令准备当前值；"" 表示不写入
		setupKey   string
		setupValue string
		command    string // 同时存在多个问题的出错命令
		wantReason string
	}{
		{"empty key beats bad delta", "", "", "",
			"incr =oops", ApplyReasonEmptyKey},
		{"whitespace key beats bad delta", "", "", "",
			"incr k k=oops", ApplyReasonKeyHasWhitespace},
		{"bad delta beats bad current", "set count=hello", "count", "hello",
			"incr count=oops", ApplyReasonIncrBadDelta},
		{"bad delta beats missing key", "", "", "",
			"incr ghost=oops", ApplyReasonIncrBadDelta},
		{"legal delta exposes bad current", "set count=hello", "count", "hello",
			"incr count=2", ApplyReasonIncrBadCurrent},
		{"legal delta and current expose overflow", "set count=" + maxText, "count", maxText,
			"incr count=1", ApplyReasonIncrOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var entries []LogEntry
			if tc.setup != "" {
				entries = append(entries, entry(1, 1, tc.setup))
			}
			entries = append(entries, entry(len(entries)+1, 1, tc.command))
			failIndex := len(entries)
			out := runKV(t, InitialState{CurrentTerm: 1},
				AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0,
					LeaderCommit: failIndex, Entries: entries},
			)
			result := out.Results[0]
			if !result.Accepted || result.Reason != ReasonOK {
				t.Fatalf("replication must stay accepted: %+v", result)
			}
			if got := appliedIndexOf(t, result); got != failIndex-1 {
				t.Fatalf("appliedIndex = %d, want %d (stuck before failing entry)", got, failIndex-1)
			}
			if result.ApplyError == nil || result.ApplyError.Index != failIndex ||
				result.ApplyError.Reason != tc.wantReason {
				t.Fatalf("applyError = %+v, want index %d %q", result.ApplyError, failIndex, tc.wantReason)
			}
			// 失败命令不改变键值表：事先写入的当前值原样保留，未写入时不创建键。
			wantKV := map[string]string{}
			if tc.setup != "" {
				wantKV[tc.setupKey] = tc.setupValue
			}
			if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, wantKV) {
				t.Fatalf("finalKV = %v, want %v (failing command must not change the table)", kv, wantKV)
			}
			if out.FinalApplyError == nil || out.FinalApplyError.Index != failIndex ||
				out.FinalApplyError.Reason != tc.wantReason {
				t.Fatalf("finalApplyError = %+v, want index %d %q",
					out.FinalApplyError, failIndex, tc.wantReason)
			}
		})
	}
}

// TestKVIncrBadDeltaKeepsCurrentValue 固定任务示例：先写入 count=hello，再应用
// incr count=oops——增量与当前值都不是有符号 64 位十进制整数时报告增量非法，
// hello 原样保留；同样的当前值遇到合法增量 incr count=2 时才报告当前值非法。
// 两种原因不能互相替代，也不能合并。
func TestKVIncrBadDeltaKeepsCurrentValue(t *testing.T) {
	cases := []struct {
		name       string
		command    string
		wantReason string
	}{
		{"bad delta with bad current", "incr count=oops", ApplyReasonIncrBadDelta},
		{"legal delta with bad current", "incr count=2", ApplyReasonIncrBadCurrent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runKV(t, InitialState{CurrentTerm: 1},
				AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
					Entries: []LogEntry{
						entry(1, 1, "set count=hello"),
						entry(2, 1, tc.command),
					}},
			)
			result := out.Results[0]
			if got := appliedIndexOf(t, result); got != 1 {
				t.Fatalf("appliedIndex = %d, want 1", got)
			}
			if result.ApplyError == nil || result.ApplyError.Index != 2 ||
				result.ApplyError.Reason != tc.wantReason {
				t.Fatalf("applyError = %+v, want index 2 %q", result.ApplyError, tc.wantReason)
			}
			if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "hello"}) {
				t.Fatalf("finalKV = %v, want count=hello preserved", kv)
			}
		})
	}
}

// TestKVIncrMultiProblemCommitBoundary 固定错误判定发生的时机：同时存在多个
// 问题的 incr 仅被复制而尚未提交时，键值表与应用错误都不能提前变化；提交
// 推进到它时才按优先级报告原因。错误中的索引对应失败的日志位置，而不是
// 复制请求的序号。
func TestKVIncrMultiProblemCommitBoundary(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 请求一：追加三条（idx3 的增量与当前值都有问题），但只提交到 2。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set count=hello"),
				entry(2, 1, "set ok=1"),
				entry(3, 1, "incr count=oops"),
			}},
		// 请求二：心跳把提交推进到 3，idx3 的多问题命令此时才判定。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 3},
	)
	first := out.Results[0]
	if !first.Accepted || first.Reason != ReasonOK {
		t.Fatalf("first request must be accepted: %+v", first)
	}
	if got := appliedIndexOf(t, first); got != 2 {
		t.Fatalf("first appliedIndex = %d, want 2", got)
	}
	if first.ApplyError != nil {
		t.Fatalf("uncommitted multi-problem incr reported early: %+v", first.ApplyError)
	}

	second := out.Results[1]
	if !second.Accepted || second.Reason != ReasonOK {
		t.Fatalf("second request must be accepted: %+v", second)
	}
	if second.CommittedIndex != 3 {
		t.Fatalf("second committedIndex = %d, want 3", second.CommittedIndex)
	}
	if got := appliedIndexOf(t, second); got != 2 {
		t.Fatalf("second appliedIndex = %d, want 2 (stuck before failing entry)", got)
	}
	// 失败的是日志索引 3，而它是第二条请求的结果：索引必须对应日志位置。
	if second.ApplyError == nil || second.ApplyError.Index != 3 ||
		second.ApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("second applyError = %+v, want index 3 %q",
			second.ApplyError, ApplyReasonIncrBadDelta)
	}

	// 此前成功的写入保留，失败命令不覆盖 hello。
	kv := finalKVOf(t, out)
	want := map[string]string{"count": "hello", "ok": "1"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 2 {
		t.Fatalf("finalAppliedIndex = %d, want 2", *out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 3 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("finalApplyError = %+v, want index 3 %q",
			out.FinalApplyError, ApplyReasonIncrBadDelta)
	}
}

// TestKVIncrMultiProblemInitialCommittedPrefix 固定初始日志已提交部分遵守同样
// 的原因选择规则：没有任何后续复制请求，最终输出仍反映实际应用结果——增量
// 与当前值都有问题时报告增量非法，未提交的后续合法命令不生效。
func TestKVIncrMultiProblemInitialCommittedPrefix(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set count=hello"),
		entry(2, 1, "incr count=oops"), // 已提交：增量非法优先于当前值非法
		entry(3, 1, "incr count=5"),    // 未提交：不能生效
	}}
	out := runKV(t, initial)
	if len(out.Results) != 0 {
		t.Fatalf("unexpected results: %+v", out.Results)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "hello"}) {
		t.Fatalf("finalKV = %v, want only count=hello", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("finalApplyError = %+v, want index 2 %q",
			out.FinalApplyError, ApplyReasonIncrBadDelta)
	}
}

// TestKVIncrMultiProblemStuckKeepsFirstReason 固定应用停住之后的行为：后续
// 日志即使写入一个合法当前值（set count=5）或带有另一种错误（未知命令），
// 也不能执行这些命令或替换第一次错误。后续合法复制仍按原有规则接收日志并
// 推进提交，逐条结果与最终结果保留原来的应用位置与原因，复制接受状态不能
// 变成应用失败的替代信号。
func TestKVIncrMultiProblemStuckKeepsFirstReason(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 请求一：提交 idx1/idx2，idx2 增量非法（当前值 hello 也不合法），应用停在 1。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set count=hello"),
				entry(2, 1, "incr count=oops"),
			}},
		// 请求二：合法复制照常接受并提交到 4；idx3 本可把当前值改合法，
		// idx4 是另一种错误——两者都不得执行，第一次错误不得被替换。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(3, 2, "set count=5"),
				entry(4, 2, "bogus command"),
			}},
	)
	for i, result := range out.Results {
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("result %d must stay accepted: %+v", i, result)
		}
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want 1 (stuck)", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 ||
			result.ApplyError.Reason != ApplyReasonIncrBadDelta {
			t.Fatalf("result %d applyError = %+v, want the original index 2 %q",
				i, result.ApplyError, ApplyReasonIncrBadDelta)
		}
	}
	// 复制层面照常推进：任期、提交位置与日志都反映第二条请求。
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 4 || len(out.FinalLog) != 4 {
		t.Fatalf("replication must keep advancing: term=%d ci=%d log=%+v",
			out.FinalTerm, out.FinalCommittedIndex, out.FinalLog)
	}
	// 应用层面停住：set count=5 未生效，hello 保留，第一个错误原样保留。
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "hello"}) {
		t.Fatalf("finalKV = %v, want only count=hello (later entries must not apply)", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("finalApplyError = %+v, want the original index 2 %q",
			out.FinalApplyError, ApplyReasonIncrBadDelta)
	}
}

// TestKVIncrMultiProblemDisabledStaysPlainString 固定未开启 applyKV 时的行为：
// 同时存在多个问题的 incr 继续作为普通字符串复制，不增加应用字段，命令在
// 日志中按原文保留。
func TestKVIncrMultiProblemDisabledStaysPlainString(t *testing.T) {
	out, err := Replicate(InitialState{CurrentTerm: 1}, []AppendRequest{
		{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set count=hello"),
				entry(2, 1, "incr count=oops"),
			}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Results[0].Accepted || out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("replication should succeed without applyKV: %+v", out)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q: %s", field, body)
		}
	}
	if !strings.Contains(body, "incr count=oops") {
		t.Fatalf("multi-problem incr command must stay in the log verbatim: %s", body)
	}
}
