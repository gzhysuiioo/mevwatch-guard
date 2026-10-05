package mevwatch

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// incr 命令的解析：合法形式（负号、前导零、边界值）与各类非法增量。
func TestKVIncrParseCommands(t *testing.T) {
	cases := []struct {
		command    string
		wantOp     kvOperation
		wantReason string
	}{
		{"incr k=1", kvOperation{isIncr: true, key: "k", delta: 1}, ""},
		{"incr k=-2", kvOperation{isIncr: true, key: "k", delta: -2}, ""},
		{"incr k=0", kvOperation{isIncr: true, key: "k", delta: 0}, ""},
		{"incr k=-0", kvOperation{isIncr: true, key: "k", delta: 0}, ""},  // 负零合法
		{"incr k=007", kvOperation{isIncr: true, key: "k", delta: 7}, ""}, // 前导零合法
		{"incr k=-007", kvOperation{isIncr: true, key: "k", delta: -7}, ""},
		{"incr 键=3", kvOperation{isIncr: true, key: "键", delta: 3}, ""},
		{"incr k=" + strconv.FormatInt(math.MaxInt64, 10), kvOperation{isIncr: true, key: "k", delta: math.MaxInt64}, ""},
		{"incr k=" + strconv.FormatInt(math.MinInt64, 10), kvOperation{isIncr: true, key: "k", delta: math.MinInt64}, ""},
		{"incr", kvOperation{}, ApplyReasonUnknownCommand},     // 没有空格与键
		{"INCR k=1", kvOperation{}, ApplyReasonUnknownCommand}, // 区分大小写
		{"Incr k=1", kvOperation{}, ApplyReasonUnknownCommand},
		{"incr k", kvOperation{}, ApplyReasonIncrMissingEquals}, // 缺等号
		{"incr =1", kvOperation{}, ApplyReasonEmptyKey},         // 空键
		{"incr  k=1", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"incr k b=1", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"incr\tk=1", kvOperation{}, ApplyReasonUnknownCommand}, // 制表符不是普通空格
		{"incr k=", kvOperation{}, ApplyReasonIncrBadDelta},     // 空增量不是整数
		{"incr k=+1", kvOperation{}, ApplyReasonIncrBadDelta},   // 不接受正号
		{"incr k=-", kvOperation{}, ApplyReasonIncrBadDelta},    // 只有负号
		{"incr k= 1", kvOperation{}, ApplyReasonIncrBadDelta},   // 空白不裁剪
		{"incr k=1 ", kvOperation{}, ApplyReasonIncrBadDelta},
		{"incr k=1.0", kvOperation{}, ApplyReasonIncrBadDelta},                  // 小数
		{"incr k=1e3", kvOperation{}, ApplyReasonIncrBadDelta},                  // 指数
		{"incr k=١", kvOperation{}, ApplyReasonIncrBadDelta},                    // 非 ASCII 数字
		{"incr k=1=2", kvOperation{}, ApplyReasonIncrBadDelta},                  // 额外等号属于增量
		{"incr k=9223372036854775808", kvOperation{}, ApplyReasonIncrBadDelta},  // 超出上限
		{"incr k=-9223372036854775809", kvOperation{}, ApplyReasonIncrBadDelta}, // 超出下限
	}
	for _, tc := range cases {
		op, reason := parseKVCommand(tc.command)
		if reason != tc.wantReason {
			t.Fatalf("parseKVCommand(%q) reason = %q, want %q", tc.command, reason, tc.wantReason)
		}
		if tc.wantReason == "" && op != tc.wantOp {
			t.Fatalf("parseKVCommand(%q) = %+v, want %+v", tc.command, op, tc.wantOp)
		}
	}
}

// 基本语义：键不存在按 0 创建；set 之后累加；delete 之后重新从 0 计；
// 结果为规范十进制字符串。
func TestKVIncrBasicSemantics(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 6,
			Entries: []LogEntry{
				entry(1, 1, "incr hits=1"),    // 键不存在：按 0 创建
				entry(2, 1, "set count=7"),    // 先前写入决定当前值
				entry(3, 1, "incr count=-2"),  // 7 + (-2) = 5
				entry(4, 1, "delete count"),   // 删除后
				entry(5, 1, "incr count=10"),  // 重新从 0 计：10
				entry(6, 1, "incr hits=-007"), // 1 + (-7) = -6，前导零合法
			}},
	)
	if got := appliedIndexOf(t, out.Results[0]); got != 6 {
		t.Fatalf("appliedIndex = %d, want 6", got)
	}
	if out.Results[0].ApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", out.Results[0].ApplyError)
	}
	kv := finalKVOf(t, out)
	want := map[string]string{"hits": "-6", "count": "10"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
}

// 任务示例：set count=7 后应用 incr count=-2，最终 count 为 "5"。
func TestKVIncrTaskExample(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{entry(1, 1, "set count=7"), entry(2, 1, "incr count=-2")}},
	)
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"count": "5"}) {
		t.Fatalf("finalKV = %v, want count=5", kv)
	}
}

// 规范形式：成功后的值不带前导零，零统一为 "0"；delta 为 0 同样写回规范
// 形式并推进应用位置。
func TestKVIncrCanonicalForm(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 5,
			Entries: []LogEntry{
				entry(1, 1, "set a=007"),  // set 按原文保存
				entry(2, 1, "incr a=0"),   // delta 0：写回规范形式 "7"
				entry(3, 1, "incr b=000"), // 不存在的键加 0：创建为 "0"
				entry(4, 1, "set c=-0"),   // 负零当前值
				entry(5, 1, "incr c=0"),   // 规范化为 "0"
			}},
	)
	if got := appliedIndexOf(t, out.Results[0]); got != 5 {
		t.Fatalf("appliedIndex = %d, want 5 (zero delta still advances)", got)
	}
	kv := finalKVOf(t, out)
	want := map[string]string{"a": "7", "b": "0", "c": "0"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
}

// 边界值：int64 上限与下限都能正确表示与累加。
func TestKVIncrInt64Boundaries(t *testing.T) {
	max := strconv.FormatInt(math.MaxInt64, 10)
	min := strconv.FormatInt(math.MinInt64, 10)
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(1, 1, "incr max="+max),  // 0 + MaxInt64
				entry(2, 1, "incr min="+min),  // 0 + MinInt64
				entry(3, 1, "incr max=-"+max), // MaxInt64 - MaxInt64 = 0
				entry(4, 1, "incr min=1"),     // MinInt64 + 1
			}},
	)
	if out.Results[0].ApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", out.Results[0].ApplyError)
	}
	kv := finalKVOf(t, out)
	want := map[string]string{
		"max": "0",
		"min": strconv.FormatInt(math.MinInt64+1, 10),
	}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
}

// 当前值不是整数：本条命令不改变键值表，应用停在该条目之前，此前结果保留。
func TestKVIncrBadCurrentValue(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(1, 1, "set k=hello"), // 非整数当前值
				entry(2, 1, "set ok=1"),
				entry(3, 1, "incr k=1"),
			}},
	)
	if got := appliedIndexOf(t, out.Results[0]); got != 2 {
		t.Fatalf("appliedIndex = %d, want 2 (stuck before failing entry)", got)
	}
	err := out.Results[0].ApplyError
	if err == nil || err.Index != 3 || err.Reason != ApplyReasonIncrBadCurrent {
		t.Fatalf("applyError = %+v, want index 3 bad current value", err)
	}
	kv := finalKVOf(t, out)
	want := map[string]string{"k": "hello", "ok": "1"} // k 保持原值
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v (failing incr must not change the table)", kv, want)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 3 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadCurrent {
		t.Fatalf("finalApplyError = %+v, want index 3 bad current value", out.FinalApplyError)
	}
}

// 增量非法：含空增量、正号、小数、超范围等，应用停在出错条目前。
func TestKVIncrBadDeltaStopsApplication(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(1, 1, "incr k=5"),
				entry(2, 1, "incr k=1.5"), // 小数增量非法
				entry(3, 1, "incr k=100"), // 出错之后不再应用
			}},
	)
	if got := appliedIndexOf(t, out.Results[0]); got != 1 {
		t.Fatalf("appliedIndex = %d, want 1", got)
	}
	err := out.Results[0].ApplyError
	if err == nil || err.Index != 2 || err.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("applyError = %+v, want index 2 bad delta", err)
	}
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"k": "5"}) {
		t.Fatalf("finalKV = %v, want only k=5", kv)
	}
}

// 相加溢出：当前值与增量各自合法，但和超出 int64 范围。
func TestKVIncrOverflow(t *testing.T) {
	max := strconv.FormatInt(math.MaxInt64, 10)
	cases := []struct {
		name     string
		commands []string
	}{
		{"positive overflow", []string{"set k=" + max, "incr k=1"}},
		{"negative overflow", []string{"set k=" + strconv.FormatInt(math.MinInt64, 10), "incr k=-1"}},
		{"two incr overflow", []string{"incr k=" + max, "incr k=" + max}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]LogEntry, len(tc.commands))
			for i, command := range tc.commands {
				entries[i] = entry(i+1, 1, command)
			}
			out := runKV(t, InitialState{CurrentTerm: 1},
				AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0,
					LeaderCommit: len(entries), Entries: entries},
			)
			if got := appliedIndexOf(t, out.Results[0]); got != len(entries)-1 {
				t.Fatalf("appliedIndex = %d, want %d", got, len(entries)-1)
			}
			err := out.Results[0].ApplyError
			if err == nil || err.Index != len(entries) || err.Reason != ApplyReasonIncrOverflow {
				t.Fatalf("applyError = %+v, want index %d overflow", err, len(entries))
			}
		})
	}
}

// 三类 incr 失败的原因必须能互相区分。
func TestKVIncrErrorReasonsAreDistinct(t *testing.T) {
	reasons := []string{ApplyReasonIncrBadCurrent, ApplyReasonIncrBadDelta, ApplyReasonIncrOverflow}
	seen := map[string]bool{}
	for _, reason := range reasons {
		if seen[reason] {
			t.Fatalf("duplicate incr error reason %q", reason)
		}
		seen[reason] = true
	}
}

// 未提交的 incr 不能提前改值或暴露数值错误；重复复制与心跳不重复累加。
func TestKVIncrCommitBoundaries(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 追加两条 incr 但都不提交：键值表仍为空，非法增量也不暴露。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "incr k=5"), entry(2, 1, "incr k=oops")}},
		// 重复复制同一条日志（完全相同，保留），提交位置不变：不累加。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "incr k=5"), entry(2, 1, "incr k=oops")}},
		// 心跳提交到 1：只累加一次。
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 1},
		// 提交位置未前进的心跳：不重复累加。
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 1},
		// 提交到 2：非法增量此时才报错，应用停在 1。
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 2},
	)
	wantApplied := []int{0, 0, 1, 1, 1}
	for i, result := range out.Results {
		if !result.Accepted {
			t.Fatalf("result %d rejected: %s", i, result.Reason)
		}
		if got := appliedIndexOf(t, result); got != wantApplied[i] {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, got, wantApplied[i])
		}
	}
	for i := 0; i < 4; i++ {
		if out.Results[i].ApplyError != nil {
			t.Fatalf("result %d unexpected apply error: %+v", i, out.Results[i].ApplyError)
		}
	}
	last := out.Results[4]
	if last.ApplyError == nil || last.ApplyError.Index != 2 ||
		last.ApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("result 4 applyError = %+v, want index 2 bad delta", last.ApplyError)
	}
	// incr k=5 恰好应用一次。
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"k": "5"}) {
		t.Fatalf("finalKV = %v, want k=5 (applied exactly once)", kv)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
}

// 初始已提交前缀中的 incr 照常生效。
func TestKVIncrInitialCommittedPrefix(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 3, Log: []LogEntry{
		entry(1, 1, "incr k=10"),
		entry(2, 2, "incr k=-3"),
		entry(3, 2, "set other=x"),
	}}
	out := runKV(t, initial)
	kv := finalKVOf(t, out)
	want := map[string]string{"k": "7", "other": "x"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 3 {
		t.Fatalf("finalAppliedIndex = %d, want 3", *out.FinalAppliedIndex)
	}
}

// incr 失败后应用停住：后续请求复制与提交照常推进，但不再应用任何条目。
func TestKVIncrErrorStopsLaterApplication(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{entry(1, 1, "incr k=1"), entry(2, 1, "incr k=abc")}},
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(3, 2, "incr k=100")}},
	)
	if !out.Results[1].Accepted || out.Results[1].CommittedIndex != 3 {
		t.Fatalf("replication must keep advancing: %+v", out.Results[1])
	}
	for i, result := range out.Results {
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want 1 (stuck)", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 {
			t.Fatalf("result %d applyError = %+v, want index 2", i, result.ApplyError)
		}
	}
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"k": "1"}) {
		t.Fatalf("finalKV = %v, want only k=1", kv)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 3 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 3", out.FinalTerm, out.FinalCommittedIndex)
	}
}

// applyKV 省略或为 false 时，incr 只是普通日志字符串，不增加应用字段。
func TestKVIncrDisabledStaysPlainString(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "incr k=1"),
	}}
	out, err := Replicate(initial, []AppendRequest{
		{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 1, "incr k=oops")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.FinalCommittedIndex != 2 || len(out.FinalLog) != 2 {
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
	if !strings.Contains(body, "incr k=oops") {
		t.Fatalf("incr command must stay in the log verbatim: %s", body)
	}
}
