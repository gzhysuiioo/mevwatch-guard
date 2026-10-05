package mevwatch

import (
	"math"
	"reflect"
	"testing"
)

func TestKVParseIncrCommands(t *testing.T) {
	cases := []struct {
		command    string
		wantOp     kvOperation
		wantReason string
	}{
		// incr 的增量合法性在应用时结合当前值判定：解析阶段只拆键与增量原文，
		// 空增量、缺等号也能解析成功，不产生格式错误。
		{"incr x=1", kvOperation{isIncr: true, key: "x", value: "1"}, ""},
		{"incr x=-2", kvOperation{isIncr: true, key: "x", value: "-2"}, ""},
		{"incr x=007", kvOperation{isIncr: true, key: "x", value: "007"}, ""},
		{"incr x=", kvOperation{isIncr: true, key: "x", value: ""}, ""},
		{"incr x", kvOperation{isIncr: true, key: "x", value: ""}, ""},
		{"incr 键=1", kvOperation{isIncr: true, key: "键", value: "1"}, ""},
		{"incr x=1 =2", kvOperation{isIncr: true, key: "x", value: "1 =2"}, ""}, // 第一个等号分隔
		{"incr =1", kvOperation{}, ApplyReasonEmptyKey},
		{"incr  x=1", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"incr x y=1", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"incr x =1", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"incr a=b=1", kvOperation{isIncr: true, key: "a", value: "b=1"}, ""}, // 额外等号留在增量里，应用时判非法
		{"INCR x=1", kvOperation{}, ApplyReasonUnknownCommand},                // 区分大小写
		{"incrx=1", kvOperation{}, ApplyReasonUnknownCommand},
		{" incr x=1", kvOperation{}, ApplyReasonUnknownCommand},
		{"incr\tx=1", kvOperation{}, ApplyReasonUnknownCommand},
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

func TestParseSignedInt64(t *testing.T) {
	valid := map[string]int64{
		"0":                    0,
		"-0":                   0,
		"00":                   0,
		"00012":                12,
		"-00012":               -12,
		"7":                    7,
		"-2":                   -2,
		"9223372036854775807":  math.MaxInt64,
		"-9223372036854775808": math.MinInt64,
	}
	for literal, want := range valid {
		got, ok := parseSignedInt64(literal)
		if !ok || got != want {
			t.Fatalf("parseSignedInt64(%q) = %d, %v; want %d, true", literal, got, ok, want)
		}
	}
	invalid := []string{
		"", "-", "+", "+1", " 1", "1 ", "\t1", "1\n",
		"1.0", "1e3", ".5", "0x10", "1_000", "--1", "1-",
		"9223372036854775808",      // MaxInt64 + 1
		"-9223372036854775809",     // MinInt64 - 1
		"999999999999999999999999", // 远超范围
		"＋1", "１２", "−5", "١٢",     // 全角加号/数字、Unicode 减号、阿拉伯-印度数字
	}
	for _, literal := range invalid {
		if _, ok := parseSignedInt64(literal); ok {
			t.Fatalf("parseSignedInt64(%q) succeeded, want error", literal)
		}
	}
}

// TestKVIncrBasic 覆盖题目给出的主示例与基本累加语义。
func TestKVIncrBasic(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(1, 1, "set count=7"),
				entry(2, 1, "incr count=-2"), // 题目示例：7 + (-2) = 5
				entry(3, 1, "incr fresh=4"),  // 不存在的键按 0 计算并创建
				entry(4, 1, "incr debt=-9"),  // 不存在的键累加负数
			}},
	)
	want := map[string]string{"count": "5", "fresh": "4", "debt": "-9"}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 4 || out.FinalApplyError != nil {
		t.Fatalf("apply state = %d %+v, want 4/nil", *out.FinalAppliedIndex, out.FinalApplyError)
	}
}

// TestKVIncrChainsWithPriorWritesAndDeletes 同一日志中先前已生效的写入、删除与
// 增量共同决定当前值；结果以规范十进制保存。
func TestKVIncrChainsWithPriorWritesAndDeletes(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 9,
			Entries: []LogEntry{
				entry(1, 1, "incr k=5"),    // 缺失 → 0+5
				entry(2, 1, "incr k=-3"),   // 5-3=2
				entry(3, 1, "set k=0010"),  // set 按原文覆盖为 "0010"
				entry(4, 1, "incr k=0"),    // 增量为 0 也规范化为 "10" 并推进
				entry(5, 1, "delete k"),    // 删除
				entry(6, 1, "incr k=-0"),   // 重新按 0 计算，规范为 "0"
				entry(7, 1, "set z=-0"),    // 非规范值
				entry(8, 1, "incr z=0000"), // 规范为 "0"
				entry(9, 1, "incr z=-0007"),
			}},
	)
	want := map[string]string{"k": "0", "z": "-7"}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 9 || out.FinalApplyError != nil {
		t.Fatalf("apply state = %d %+v, want 9/nil", *out.FinalAppliedIndex, out.FinalApplyError)
	}
}

// TestKVIncrBoundaries 64 位边界上的合法累加。
func TestKVIncrBoundaries(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 8,
			Entries: []LogEntry{
				entry(1, 1, "set max=9223372036854775807"),
				entry(2, 1, "incr max=0"), // 边界值 +0 合法，输出规范化文本
				entry(3, 1, "set min=-9223372036854775808"),
				entry(4, 1, "incr min=-0"),
				entry(5, 1, "incr up=9223372036854775807"),    // 0 + 最大值
				entry(6, 1, "incr down=-9223372036854775808"), // 0 + 最小值
				entry(7, 1, "set near=-9223372036854775807"),
				entry(8, 1, "incr near=-1"), // 恰好到达最小值
			}},
	)
	want := map[string]string{
		"max": "9223372036854775807", "min": "-9223372036854775808",
		"up": "9223372036854775807", "down": "-9223372036854775808",
		"near": "-9223372036854775808",
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
}

// TestKVIncrCurrentValueInvalid 当前值不是合法整数时失败，且不改动键值表。
func TestKVIncrCurrentValueInvalid(t *testing.T) {
	// 空字符串、小数、指数、全角数字等各种非整数当前值都按同一原因失败。
	for _, bad := range []string{"abc", "", "1.0", "1e3", " 1", "１２", "+1", "-"} {
		t.Run("current="+bad, func(t *testing.T) {
			initial := InitialState{CurrentTerm: 1, CommittedIndex: 2, Log: []LogEntry{
				entry(1, 1, "set keep="+bad), // 非整数当前值
				entry(2, 1, "set after=2"),
			}}
			out := runKV(t, initial,
				// idx3 对非整数当前值累加：失败，停在 2，表保持原样；idx4 不应用。
				AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 4,
					Entries: []LogEntry{
						entry(3, 1, "incr keep=5"),
						entry(4, 1, "set later=9"),
					}},
			)
			r := out.Results[0]
			if got := appliedIndexOf(t, r); got != 2 {
				t.Fatalf("appliedIndex = %d, want 2 (stuck before failing incr)", got)
			}
			if r.ApplyError == nil || r.ApplyError.Index != 3 ||
				r.ApplyError.Reason != ApplyReasonIncrCurrentInvalid {
				t.Fatalf("applyError = %+v, want index 3 current-invalid", r.ApplyError)
			}
			if *out.FinalAppliedIndex != 2 {
				t.Fatalf("finalAppliedIndex = %d, want 2", *out.FinalAppliedIndex)
			}
			want := map[string]string{"keep": bad, "after": "2"}
			if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, want) {
				t.Fatalf("finalKV = %v, want unchanged %v", kv, want)
			}
			if e := out.FinalApplyError; e == nil || e.Index != 3 ||
				e.Reason != ApplyReasonIncrCurrentInvalid {
				t.Fatalf("finalApplyError = %+v, want index 3 current-invalid", e)
			}
		})
	}
}

// TestKVIncrDeltaInvalid 增量文本不是合法整数时失败，且不创建键、不改值。
func TestKVIncrDeltaInvalid(t *testing.T) {
	badDeltas := []string{
		"", "+", "+1", " 1", "1 ", "1.0", "1e3", "0x10",
		"9223372036854775808", "-9223372036854775809", "１２",
	}
	for _, delta := range badDeltas {
		initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
			entry(1, 1, "set k=5"),
		}}
		command := "incr k=" + delta
		out := runKV(t, initial,
			AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
				Entries: []LogEntry{entry(2, 1, command)}},
		)
		if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
			out.FinalApplyError.Reason != ApplyReasonIncrDeltaInvalid {
			t.Fatalf("delta %q: finalApplyError = %+v, want index 2 delta-invalid",
				delta, out.FinalApplyError)
		}
		if *out.FinalAppliedIndex != 1 {
			t.Fatalf("delta %q: finalAppliedIndex = %d, want 1", delta, *out.FinalAppliedIndex)
		}
		if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"k": "5"}) {
			t.Fatalf("delta %q: finalKV = %v, want k unchanged", delta, kv)
		}
	}

	// 缺等号与空增量：不能创建缺失的键。
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "incr ghost"),
				entry(2, 1, "set later=1"),
			}},
	)
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 1 ||
		out.FinalApplyError.Reason != ApplyReasonIncrDeltaInvalid {
		t.Fatalf("finalApplyError = %+v, want index 1 delta-invalid", out.FinalApplyError)
	}
	if kv := finalKVOf(t, out); len(kv) != 0 {
		t.Fatalf("missing key must not be created on failure: %v", kv)
	}
}

// TestKVIncrOverflow 相加超出范围时失败，当前值与增量各自合法也不改表。
func TestKVIncrOverflow(t *testing.T) {
	cases := []struct {
		name    string
		current string
		delta   string
	}{
		{"max plus 1", "9223372036854775807", "1"},
		{"min minus 1", "-9223372036854775808", "-1"},
		{"two large positives", "9223372036854775800", "100"},
		{"two large negatives", "-9223372036854775800", "-100"},
		{"positive max delta overflow", "5", "9223372036854775807"},
		{"negative min delta overflow", "-5", "-9223372036854775808"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
				entry(1, 1, "set k="+tc.current),
			}}
			out := runKV(t, initial,
				AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
					Entries: []LogEntry{entry(2, 1, "incr k="+tc.delta)}},
			)
			if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
				out.FinalApplyError.Reason != ApplyReasonIncrOverflow {
				t.Fatalf("finalApplyError = %+v, want index 2 overflow", out.FinalApplyError)
			}
			if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"k": tc.current}) {
				t.Fatalf("finalKV = %v, want current value %q preserved", kv, tc.current)
			}
			if *out.FinalAppliedIndex != 1 {
				t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
			}
		})
	}
}

// TestKVIncrErrorReasonPrecedence 多个问题并存时按“当前值 → 增量 → 溢出”判定。
func TestKVIncrErrorReasonPrecedence(t *testing.T) {
	// 当前值非法且增量非法：报当前值非法。
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set k=abc"),
				entry(2, 1, "incr k=not-a-number"),
			}},
	)
	if e := out.FinalApplyError; e == nil || e.Index != 2 ||
		e.Reason != ApplyReasonIncrCurrentInvalid {
		t.Fatalf("want current-invalid precedence, got %+v", e)
	}

	// 当前值合法、增量非法且若按数字相加本会溢出：报增量非法，而非溢出。
	out = runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{
				entry(1, 1, "set k=9223372036854775807"),
				entry(2, 1, "incr k=99999999999999999999"),
			}},
	)
	if e := out.FinalApplyError; e == nil || e.Index != 2 ||
		e.Reason != ApplyReasonIncrDeltaInvalid {
		t.Fatalf("want delta-invalid precedence, got %+v", e)
	}
}

// TestKVIncrCommitBoundaries 未提交不累加、不报错；重复复制与提交位置不前进的
// 心跳不能再次累加；初始已提交前缀照常生效。
func TestKVIncrCommitBoundaries(t *testing.T) {
	// 未提交的非法增量不能提前暴露错误；提交同一条日志时才应用（恰好一次）。
	bad := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "incr x=bad")}},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "incr x=bad")}},
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1},
	)
	if got := appliedIndexOf(t, bad.Results[0]); got != 0 {
		t.Fatalf("uncommitted incr applied early: appliedIndex = %d, want 0", got)
	}
	if bad.Results[0].ApplyError != nil {
		t.Fatalf("uncommitted bad incr exposed early: %+v", bad.Results[0].ApplyError)
	}
	if got := appliedIndexOf(t, bad.Results[1]); got != 0 {
		t.Fatalf("after commit appliedIndex = %d, want 0 (failed at index 1)", got)
	}
	if e := bad.Results[1].ApplyError; e == nil || e.Index != 1 ||
		e.Reason != ApplyReasonIncrDeltaInvalid {
		t.Fatalf("result 1 applyError = %+v, want index 1 delta-invalid", e)
	}
	// 提交位置不前进的心跳不能再次累加，错误仍是同一个。
	if e := bad.Results[2].ApplyError; e == nil || e.Index != 1 {
		t.Fatalf("heartbeat re-applied: %+v", e)
	}
	if kv := finalKVOf(t, bad); len(kv) != 0 {
		t.Fatalf("failed incr must not create the key: %v", kv)
	}

	legal := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "incr n=1")}},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "incr n=1")}},
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1},
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1},
		// 追加第二条增量并提交，确认应用位置还能继续推进。
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 1, "incr n=2")}},
	)
	wantApplied := []int{0, 1, 1, 1, 2}
	for i, result := range legal.Results {
		if got := appliedIndexOf(t, result); got != wantApplied[i] {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, got, wantApplied[i])
		}
		if result.ApplyError != nil {
			t.Fatalf("result %d unexpected error: %+v", i, result.ApplyError)
		}
	}
	if kv := finalKVOf(t, legal); !reflect.DeepEqual(kv, map[string]string{"n": "3"}) {
		t.Fatalf("finalKV = %v, want n=3 (each incr applied once)", kv)
	}

	// 未提交后缀被新领导者替换后，旧 incr 不留痕迹。
	replaced := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "incr n=bad")}},
		AppendRequest{Term: 2, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 2, "incr n=41")}},
	)
	if replaced.Results[0].ApplyError != nil {
		t.Fatalf("uncommitted bad incr exposed early: %+v", replaced.Results[0].ApplyError)
	}
	if kv := finalKVOf(t, replaced); !reflect.DeepEqual(kv, map[string]string{"n": "41"}) {
		t.Fatalf("finalKV = %v, want n=41 from replacement only", kv)
	}

	// 初始已提交前缀中的 incr 在没有请求时同样生效。
	initial := runKV(t, InitialState{CurrentTerm: 2, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 2, "incr c=10"), entry(2, 2, "incr c=-4"), entry(3, 2, "incr c=999"),
	}})
	if kv := finalKVOf(t, initial); !reflect.DeepEqual(kv, map[string]string{"c": "6"}) {
		t.Fatalf("initial committed prefix kv = %v, want c=6", kv)
	}
	if *initial.FinalAppliedIndex != 2 || initial.FinalApplyError != nil {
		t.Fatalf("initial apply state = %d %+v, want 2/nil",
			*initial.FinalAppliedIndex, initial.FinalApplyError)
	}
}

// TestKVIncrErrorInInitialCommittedPrefix 初始已提交前缀中的非法增量按既有规则
// 停在失败条目之前。
func TestKVIncrErrorInInitialCommittedPrefix(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 3, Log: []LogEntry{
		entry(1, 1, "set a=1"),
		entry(2, 1, "incr a=2"),
		entry(3, 1, "incr a=99999999999999999999"), // 增量非法
	}}
	out := runKV(t, initial)
	if *out.FinalAppliedIndex != 2 {
		t.Fatalf("finalAppliedIndex = %d, want 2", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"a": "3"}) {
		t.Fatalf("finalKV = %v, want a=3", kv)
	}
	if e := out.FinalApplyError; e == nil || e.Index != 3 ||
		e.Reason != ApplyReasonIncrDeltaInvalid {
		t.Fatalf("finalApplyError = %+v, want index 3 delta-invalid", e)
	}
}

// TestKVIncrFailureKeepsReplicationBehavior 增量失败后复制、任期、提交位置继续
// 按原规则推进，输出仍是正常结果（应用错误与复制成败相互独立）。
func TestKVIncrFailureKeepsReplicationBehavior(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set n=9223372036854775807"),
	}},
		// idx2 溢出失败、idx3 正常：复制都接受，应用停在 1。
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(2, 1, "incr n=1"),
				entry(3, 1, "set other=x"),
			}},
		// 更高任期、继续推进提交：应用状态保持停住，错误仍是首个。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 3},
	)
	for i, result := range out.Results {
		if !result.Accepted {
			t.Fatalf("result %d replication rejected: %s", i, result.Reason)
		}
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want stuck at 1", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 ||
			result.ApplyError.Reason != ApplyReasonIncrOverflow {
			t.Fatalf("result %d applyError = %+v, want index 2 overflow", i, result.ApplyError)
		}
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 3 || len(out.FinalLog) != 3 {
		t.Fatalf("replication state should advance: %+v", out)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"n": "9223372036854775807"}) {
		t.Fatalf("finalKV = %v, want only original n", kv)
	}
}

// TestKVIncrDisabledStaysPlainString applyKV 关闭时 incr 只是普通字符串，
// 输出中不出现任何应用字段。
func TestKVIncrDisabledStaysPlainString(t *testing.T) {
	input := InitialState{CurrentTerm: 1}
	requests := []AppendRequest{
		{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2, Entries: []LogEntry{
			entry(1, 1, "incr n=5"),
			entry(2, 1, "incr n=not-a-number"),
		}},
	}
	out, err := Replicate(input, requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.FinalLog) != 2 || out.FinalLog[0].Command != "incr n=5" {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
	if out.FinalAppliedIndex != nil || out.FinalKV != nil || out.FinalApplyError != nil {
		t.Fatalf("apply state leaked with applyKV off: %+v", out)
	}
}
