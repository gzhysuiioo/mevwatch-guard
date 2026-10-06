package mevwatch

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// 一条 incr 命令同时存在多个问题时的错误原因选择：命令自身的格式或增量错误
// 优先于键值表中的当前值问题；只有命令本身合法，当前值非法才成为失败原因；
// 当前值与增量都合法、相加超出范围时才报告溢出。本文件固定这套优先级与
// “提交并轮到它应用时才判断”的边界，不改任何现有行为。

// TestKVIncrReasonPriorityParse 解析层面的优先级：键的格式错误先于增量错误
// 报告——键为空且增量也不是整数时说明键为空，而不是增量非法。
func TestKVIncrReasonPriorityParse(t *testing.T) {
	cases := []struct {
		command    string
		wantReason string
	}{
		{"incr =oops", ApplyReasonEmptyKey},          // 空键 + 非整数增量：键为空
		{"incr =1.5", ApplyReasonEmptyKey},           // 空键 + 小数增量：仍是键为空
		{"incr  =oops", ApplyReasonKeyHasWhitespace}, // 空白键 + 非整数增量：键含空白
		{"incr k b=oops", ApplyReasonKeyHasWhitespace},
		{"incr k", ApplyReasonIncrMissingEquals}, // 缺等号时根本轮不到增量判断
		{"incr k=oops", ApplyReasonIncrBadDelta}, // 键合法才轮到增量
	}
	for _, tc := range cases {
		_, reason := parseKVCommand(tc.command)
		if reason != tc.wantReason {
			t.Fatalf("parseKVCommand(%q) reason = %q, want %q", tc.command, reason, tc.wantReason)
		}
	}
}

// TestKVIncrBadDeltaWinsOverBadCurrent 任务示例：先写入 count=hello，再应用
// incr count=oops——增量与当前值都不是有符号 64 位十进制整数时，报告增量非法
// 而不是当前值非法，hello 保留；同样的当前值遇到合法增量时，才报告当前值非法。
// 每个子场景独立运行，因为应用出错后状态停住，不能共用一次调用。
func TestKVIncrBadDeltaWinsOverBadCurrent(t *testing.T) {
	cases := []struct {
		name       string
		incr       string
		wantReason string
	}{
		{"bad delta beats bad current", "incr count=oops", ApplyReasonIncrBadDelta},
		{"decimal delta beats bad current", "incr count=1.5", ApplyReasonIncrBadDelta},
		{"out-of-range delta beats bad current", "incr count=9223372036854775808", ApplyReasonIncrBadDelta},
		{"empty delta beats bad current", "incr count=", ApplyReasonIncrBadDelta},
		{"legal delta exposes bad current", "incr count=5", ApplyReasonIncrBadCurrent},
		{"zero delta exposes bad current", "incr count=0", ApplyReasonIncrBadCurrent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runKV(t, InitialState{CurrentTerm: 1},
				AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
					Entries: []LogEntry{
						entry(1, 1, "set count=hello"), // 非整数当前值
						entry(2, 1, tc.incr),
					}},
			)
			result := out.Results[0]
			if !result.Accepted || result.Reason != ReasonOK {
				t.Fatalf("replication must stay accepted: %+v", result)
			}
			if got := appliedIndexOf(t, result); got != 1 {
				t.Fatalf("appliedIndex = %d, want 1 (stuck before failing entry)", got)
			}
			if result.ApplyError == nil || result.ApplyError.Index != 2 ||
				result.ApplyError.Reason != tc.wantReason {
				t.Fatalf("applyError = %+v, want index 2 %q", result.ApplyError, tc.wantReason)
			}
			// 失败命令不覆盖值：count 仍是 hello。
			if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "hello"}) {
				t.Fatalf("finalKV = %v, want count=hello preserved", kv)
			}
			if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
				out.FinalApplyError.Reason != tc.wantReason {
				t.Fatalf("finalApplyError = %+v, want index 2 %q", out.FinalApplyError, tc.wantReason)
			}
		})
	}
}

// TestKVIncrEmptyKeyWinsOverBadDelta 应用层面固定同一优先级：键为空且增量也
// 不是整数时，应用错误说明键为空；即使键值表里存在同名坏值也不会轮到当前值
// 判断（空键命令根本不查表）。
func TestKVIncrEmptyKeyWinsOverBadDelta(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set ok=1"),
				entry(2, 1, "incr =oops"), // 空键 + 非整数增量：原因是键为空
			}},
	)
	if got := appliedIndexOf(t, out.Results[0]); got != 1 {
		t.Fatalf("appliedIndex = %d, want 1", got)
	}
	err := out.Results[0].ApplyError
	if err == nil || err.Index != 2 || err.Reason != ApplyReasonEmptyKey {
		t.Fatalf("applyError = %+v, want index 2 empty key", err)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"ok": "1"}) {
		t.Fatalf("finalKV = %v, want only ok=1", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Reason != ApplyReasonEmptyKey {
		t.Fatalf("finalApplyError = %+v, want empty key", out.FinalApplyError)
	}
}

// TestKVIncrOverflowOnlyWhenDeltaAndCurrentValid 溢出是最后一级判断：当前值
// 已达上限但增量非法时报告增量非法而非溢出；当前值非法且增量会让“和”越界的
// 说法不成立——当前值非法先报告。只有两者都合法且相加越界才是溢出。
func TestKVIncrOverflowOnlyWhenDeltaAndCurrentValid(t *testing.T) {
	max := strconv.FormatInt(math.MaxInt64, 10)
	cases := []struct {
		name       string
		setup      string
		incr       string
		wantReason string
	}{
		{"max current with bad delta", "set count=" + max, "incr count=oops", ApplyReasonIncrBadDelta},
		{"bad current with huge-looking delta", "set count=hello", "incr count=9223372036854775808", ApplyReasonIncrBadDelta},
		{"bad current with legal delta", "set count=hello", "incr count=1", ApplyReasonIncrBadCurrent},
		{"max current plus one overflows", "set count=" + max, "incr count=1", ApplyReasonIncrOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runKV(t, InitialState{CurrentTerm: 1},
				AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
					Entries: []LogEntry{entry(1, 1, tc.setup), entry(2, 1, tc.incr)}},
			)
			err := out.Results[0].ApplyError
			if err == nil || err.Index != 2 || err.Reason != tc.wantReason {
				t.Fatalf("applyError = %+v, want index 2 %q", err, tc.wantReason)
			}
			if got := appliedIndexOf(t, out.Results[0]); got != 1 {
				t.Fatalf("appliedIndex = %d, want 1", got)
			}
		})
	}
}

// TestKVIncrReasonChosenAtCommitTime 判断必须发生在该日志条目已经提交、并且
// 轮到它应用时：仅复制未提交的多问题命令，键值表与应用错误都不能提前变化；
// 提交推进到它时，之前成功的累加保留，失败命令不创建键、不覆盖值，应用位置
// 停在它前一条。错误索引对应失败的日志位置，而不是复制请求的序号。
func TestKVIncrReasonChosenAtCommitTime(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 请求一：追加三条，只提交第一条。idx2 是“键为空 + 增量非法”的多问题
		// 命令，idx3 是新键上的非法增量——都未提交，既不能提前报错，也不能
		// 提前创建键。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{
				entry(1, 1, "incr count=5"),
				entry(2, 1, "incr =oops"),
				entry(3, 1, "incr ghost=oops"),
			}},
		// 请求二：心跳把提交推进到 2，多问题命令此时才报“键为空”。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 2},
		// 请求三：提交继续推进到 3，但应用已停住，idx3 不再判断。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 3},
	)
	if len(out.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(out.Results))
	}
	// 请求一：复制接受，提交到 1，只应用 idx1；未提交的多问题命令不可见。
	first := out.Results[0]
	if !first.Accepted || first.Reason != ReasonOK {
		t.Fatalf("first request must be accepted: %+v", first)
	}
	if first.CommittedIndex != 1 {
		t.Fatalf("first committedIndex = %d, want 1", first.CommittedIndex)
	}
	if got := appliedIndexOf(t, first); got != 1 {
		t.Fatalf("first appliedIndex = %d, want 1", got)
	}
	if first.ApplyError != nil {
		t.Fatalf("uncommitted multi-problem command reported early: %+v", first.ApplyError)
	}
	// 请求二、三：错误索引是日志位置 2（不是请求序号），原因固定为键为空；
	// 应用位置停在出错前一条，不再前进。
	for i := 1; i < 3; i++ {
		result := out.Results[i]
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("result %d must stay accepted: %+v", i, result)
		}
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want 1 (stuck)", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 ||
			result.ApplyError.Reason != ApplyReasonEmptyKey {
			t.Fatalf("result %d applyError = %+v, want index 2 empty key", i, result.ApplyError)
		}
	}
	if out.Results[2].CommittedIndex != 3 {
		t.Fatalf("commit must keep advancing after application stuck: %d, want 3",
			out.Results[2].CommittedIndex)
	}
	// 之前成功的累加保留；失败命令不创建键（ghost 不存在）、不覆盖值。
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"count": "5"}) {
		t.Fatalf("finalKV = %v, want only count=5 (failing commands create nothing)", kv)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonEmptyKey {
		t.Fatalf("finalApplyError = %+v, want index 2 empty key", out.FinalApplyError)
	}
}

// TestKVIncrInitialCommittedPrefixReasonPriority 初始日志的已提交部分遵守同样
// 的原因选择规则：没有任何后续复制请求，最终输出仍反映实际应用结果——非法
// 增量先于非法当前值报告，应用停在出错条目前。
func TestKVIncrInitialCommittedPrefixReasonPriority(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 3, Log: []LogEntry{
		entry(1, 1, "set count=hello"), // 非整数当前值
		entry(2, 1, "incr count=oops"), // 增量也非法：报增量非法
		entry(3, 2, "set later=x"),     // 出错之后不再应用
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
		t.Fatalf("finalApplyError = %+v, want index 2 bad delta", out.FinalApplyError)
	}
}

// TestKVIncrStuckIgnoresLaterFixAndOtherErrors 应用停住后，即使后面的日志写入
// 一个合法当前值，或带有另一种错误，也不能执行这些命令或替换第一次错误。
// 后续合法复制仍按原有规则接收日志并推进提交，逐条结果与最终结果保留原来的
// 应用位置与原因；复制接受状态不能变成应用失败的替代信号。
func TestKVIncrStuckIgnoresLaterFixAndOtherErrors(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 请求一：idx1 写入非整数当前值，idx2 增量非法——提交到 2，应用停在 1。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set count=hello"),
				entry(2, 1, "incr count=oops"),
			}},
		// 请求二：idx3 把 count 改成合法的 "7"，idx4 是合法增量——若被执行会
		// 消除当前值问题；idx5 是另一种错误（未知命令）。全部提交，但都不能
		// 执行，也不能替换 idx2 的第一次错误。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 5,
			Entries: []LogEntry{
				entry(3, 2, "set count=7"),
				entry(4, 2, "incr count=1"),
				entry(5, 2, "bogus command"),
			}},
	)
	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(out.Results))
	}
	// 复制层面：两条请求都按原有规则接受，提交推进到 5——接受状态不代表
	// 应用成功。
	for i, result := range out.Results {
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("result %d must stay accepted: %+v", i, result)
		}
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want 1 (stuck)", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 ||
			result.ApplyError.Reason != ApplyReasonIncrBadDelta {
			t.Fatalf("result %d applyError = %+v, want the original index 2 bad delta",
				i, result.ApplyError)
		}
	}
	second := out.Results[1]
	if second.Term != 2 || second.CommittedIndex != 5 {
		t.Fatalf("replication must keep advancing: term %d ci %d, want term 2 ci 5",
			second.Term, second.CommittedIndex)
	}
	// 最终状态：日志完整保留五条；合法当前值与合法增量都未生效，count 仍是
	// hello；第一次错误原样保留，不被 idx5 的另一种错误替换。
	if len(out.FinalLog) != 5 {
		t.Fatalf("final log = %d entries, want 5", len(out.FinalLog))
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 5 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 5",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "hello"}) {
		t.Fatalf("finalKV = %v, want only count=hello (later fix must not run)", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("finalApplyError = %+v, want the original index 2 bad delta", out.FinalApplyError)
	}
}

// TestKVIncrMultiProblemDisabledStaysPlainString applyKV 未开启时，多问题的
// incr 命令继续作为普通字符串复制：不解释键、增量或当前值，不增加应用字段，
// 复制与提交照常推进。
func TestKVIncrMultiProblemDisabledStaysPlainString(t *testing.T) {
	out, err := Replicate(InitialState{CurrentTerm: 1}, []AppendRequest{
		{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "incr =oops"), // 空键 + 非法增量
				entry(2, 1, "incr k=1.5"), // 非法增量
			}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Results[0].Accepted || out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
		t.Fatalf("replication state wrong: %+v", out)
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
	if !strings.Contains(body, "incr =oops") || !strings.Contains(body, "incr k=1.5") {
		t.Fatalf("multi-problem incr commands must stay in the log verbatim: %s", body)
	}
}
