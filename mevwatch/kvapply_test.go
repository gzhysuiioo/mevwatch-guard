package mevwatch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func runKV(t *testing.T, initial InitialState, requests ...AppendRequest) ReplicateOutput {
	t.Helper()
	out, err := ReplicateWithOptions(initial, requests, ReplicateOptions{ApplyKV: true})
	if err != nil {
		t.Fatalf("ReplicateWithOptions returned error: %v", err)
	}
	return out
}

func appliedIndexOf(t *testing.T, result AppendResult) int {
	t.Helper()
	if result.AppliedIndex == nil {
		t.Fatalf("appliedIndex missing in %+v", result)
	}
	return *result.AppliedIndex
}

func finalKVOf(t *testing.T, out ReplicateOutput) map[string]string {
	t.Helper()
	if out.FinalAppliedIndex == nil || out.FinalKV == nil {
		t.Fatalf("final apply fields missing in %+v", out)
	}
	return out.FinalKV
}

func TestKVParseCommands(t *testing.T) {
	cases := []struct {
		command    string
		wantOp     kvOperation
		wantReason string
	}{
		{"set x=1", kvOperation{key: "x", value: "1"}, ""},
		{"set x=", kvOperation{key: "x", value: ""}, ""},           // 空值
		{"set k=a b c", kvOperation{key: "k", value: "a b c"}, ""}, // 值含空格
		{"set k=a=b=c", kvOperation{key: "k", value: "a=b=c"}, ""}, // 值含额外等号
		{"set k=你好 世界", kvOperation{key: "k", value: "你好 世界"}, ""}, // 中文值
		{"set k=1 ", kvOperation{key: "k", value: "1 "}, ""},       // 尾部空白保留在值里
		{"delete x", kvOperation{isDelete: true, key: "x"}, ""},
		{"delete 键", kvOperation{isDelete: true, key: "键"}, ""},
		{"set", kvOperation{}, ApplyReasonUnknownCommand}, // 没有空格与键
		{"delete", kvOperation{}, ApplyReasonUnknownCommand},
		{"set x", kvOperation{}, ApplyReasonSetMissingEquals},     // 缺等号
		{"set =1", kvOperation{}, ApplyReasonEmptyKey},            // 空键
		{"set  x=1", kvOperation{}, ApplyReasonKeyHasWhitespace},  // 两个空格：键以空格开头
		{"set x y=1", kvOperation{}, ApplyReasonKeyHasWhitespace}, // 键含空白
		{"set\tx=1", kvOperation{}, ApplyReasonUnknownCommand},    // 制表符不是普通空格
		{"delete x y", kvOperation{}, ApplyReasonKeyHasWhitespace},
		{"delete x ", kvOperation{}, ApplyReasonKeyHasWhitespace}, // 尾部空白不裁剪
		{"delete a=b", kvOperation{}, ApplyReasonKeyHasEquals},    // 键含等号
		{" set x=1", kvOperation{}, ApplyReasonUnknownCommand},    // 前导空白不裁剪
		{"SET x=1", kvOperation{}, ApplyReasonUnknownCommand},     // 区分大小写
		{"get x", kvOperation{}, ApplyReasonUnknownCommand},
		{"", kvOperation{}, ApplyReasonUnknownCommand},
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

func TestKVInitialCommittedPrefixWithoutRequests(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set x=1"), entry(2, 2, "set y=你好"), entry(3, 2, "set z=9"),
	}}
	out := runKV(t, initial)
	kv := finalKVOf(t, out)
	want := map[string]string{"x": "1", "y": "你好"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 2 {
		t.Fatalf("finalAppliedIndex = %d, want 2", *out.FinalAppliedIndex)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", out.FinalApplyError)
	}
	if len(out.Results) != 0 {
		t.Fatalf("unexpected results: %+v", out.Results)
	}
}

func TestKVAppliesOnlyNewlyCommitted(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 追加三条但一条都不提交：不应用。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "set a=1"), entry(2, 1, "set b=2"), entry(3, 1, "delete a")}},
		// 心跳推进提交到 2：应用前两条。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 2},
		// 重复的心跳：提交位置不变，不重复应用。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 2},
		// 提交最后一条 delete。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 3},
	)
	wantApplied := []int{0, 2, 2, 3}
	for i, result := range out.Results {
		if !result.Accepted {
			t.Fatalf("result %d rejected: %s", i, result.Reason)
		}
		if got := appliedIndexOf(t, result); got != wantApplied[i] {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, got, wantApplied[i])
		}
		if result.ApplyError != nil {
			t.Fatalf("result %d unexpected apply error: %+v", i, result.ApplyError)
		}
	}
	// 同一个键的多次操作按日志次序生效：set a=1 之后 delete a。
	kv := finalKVOf(t, out)
	want := map[string]string{"b": "2"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if *out.FinalAppliedIndex != 3 {
		t.Fatalf("finalAppliedIndex = %d, want 3", *out.FinalAppliedIndex)
	}
}

func TestKVDeleteMissingKeySucceeds(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "delete ghost")}},
	)
	if !out.Results[0].Accepted || out.Results[0].ApplyError != nil {
		t.Fatalf("deleting a missing key should succeed: %+v", out.Results[0])
	}
	if got := appliedIndexOf(t, out.Results[0]); got != 1 {
		t.Fatalf("appliedIndex = %d, want 1", got)
	}
	if kv := finalKVOf(t, out); len(kv) != 0 {
		t.Fatalf("finalKV = %v, want empty", kv)
	}
}

func TestKVFormatErrorStopsApplication(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set ok=1"),
	}}
	out := runKV(t, initial,
		// 追加 idx2（格式错误）与 idx3，并提交到 3：应用停在 idx1。
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(2, 1, "set bad"), entry(3, 1, "set later=3")}},
		// 复制与提交仍可继续推进，但应用状态保持停住。
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 4,
			Entries: []LogEntry{entry(4, 2, "set more=4")}},
	)
	if !out.Results[0].Accepted || !out.Results[1].Accepted {
		t.Fatalf("replication should still be accepted: %+v", out.Results)
	}
	for i, result := range out.Results {
		if got := appliedIndexOf(t, result); got != 1 {
			t.Fatalf("result %d appliedIndex = %d, want 1 (stuck)", i, got)
		}
		if result.ApplyError == nil || result.ApplyError.Index != 2 ||
			result.ApplyError.Reason != ApplyReasonSetMissingEquals {
			t.Fatalf("result %d applyError = %+v, want index 2 missing '='", i, result.ApplyError)
		}
	}
	// 日志、任期与提交位置继续变化。
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 4 || len(out.FinalLog) != 4 {
		t.Fatalf("replication state should advance: term=%d ci=%d log=%+v",
			out.FinalTerm, out.FinalCommittedIndex, out.FinalLog)
	}
	// 应用状态停住：idx2 及之后（包括格式正确的 idx3/idx4）都不执行。
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	kv := finalKVOf(t, out)
	want := map[string]string{"ok": "1"}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 {
		t.Fatalf("finalApplyError = %+v, want index 2", out.FinalApplyError)
	}
}

func TestKVErrorInInitialCommittedPrefix(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 3, Log: []LogEntry{
		entry(1, 1, "set a=1"), entry(2, 1, "bogus"), entry(3, 1, "set b=2"),
	}}
	out := runKV(t, initial)
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"a": "1"}) {
		t.Fatalf("finalKV = %v, want only first entry applied", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonUnknownCommand {
		t.Fatalf("finalApplyError = %+v, want index 2 unknown command", out.FinalApplyError)
	}
}

func TestKVUncommittedBadEntryAndReplacedSuffix(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		// 追加一条格式错误的未提交条目：不能提前报错。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "not a kv command")}},
		// 新领导者替换未提交后缀：被丢弃命令的效果不得出现在键值表中。
		AppendRequest{Term: 2, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 2, "set x=1")}},
	)
	for i, result := range out.Results {
		if !result.Accepted {
			t.Fatalf("result %d rejected: %s", i, result.Reason)
		}
		if result.ApplyError != nil {
			t.Fatalf("result %d unexpected apply error: %+v", i, result.ApplyError)
		}
	}
	if got := appliedIndexOf(t, out.Results[0]); got != 0 {
		t.Fatalf("uncommitted entry applied: appliedIndex = %d, want 0", got)
	}
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"x": "1"}) {
		t.Fatalf("finalKV = %v, want only replacement entry", kv)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
}

func TestKVApplyFailureKeepsReplicationVerdict(t *testing.T) {
	// 应用失败不得把已接受的复制改为拒绝，也不得改变原有拒绝原因。
	out := runKV(t, InitialState{CurrentTerm: 3, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set a=1"), entry(2, 2, "bad command"), entry(3, 2, "set b=2"),
	}},
		// 提交 idx2（格式错误）：复制成功，应用失败。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 2},
		// 低任期请求：仍按原规则拒绝，应用状态保持停住。
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 3},
	)
	if !out.Results[0].Accepted || out.Results[0].Reason != ReasonOK {
		t.Fatalf("accepted replication must stay accepted: %+v", out.Results[0])
	}
	if out.Results[0].CommittedIndex != 2 {
		t.Fatalf("commit must not be rolled back: %+v", out.Results[0])
	}
	if out.Results[1].Accepted || out.Results[1].Reason != ReasonStaleTerm {
		t.Fatalf("rejection reason changed: %+v", out.Results[1])
	}
	for i, result := range out.Results {
		if result.ApplyError == nil || result.ApplyError.Index != 2 {
			t.Fatalf("result %d applyError = %+v, want index 2", i, result.ApplyError)
		}
	}
}

func TestKVValueVerbatimAndKeyOverwrite(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(1, 1, "set k="),
				entry(2, 1, "set k=a=b c"),
				entry(3, 1, "set 键=值 "),
				entry(4, 1, "set k=最终"),
			}},
	)
	kv := finalKVOf(t, out)
	want := map[string]string{"k": "最终", "键": "值 "}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("finalKV = %v, want %v", kv, want)
	}
}

func TestKVDisabledKeepsOutputShape(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}}
	requests := []AppendRequest{
		{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1},
	}
	out, err := Replicate(initial, requests)
	if err != nil {
		t.Fatal(err)
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
}

func TestKVEnabledEmptyTableSerializesAsEmptyObject(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0},
	)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if !strings.Contains(body, `"finalKV":{}`) {
		t.Fatalf("empty table must serialize as {}: %s", body)
	}
	if !strings.Contains(body, `"finalAppliedIndex":0`) {
		t.Fatalf("finalAppliedIndex 0 must be present: %s", body)
	}
	if !strings.Contains(body, `"appliedIndex":0`) {
		t.Fatalf("per-request appliedIndex 0 must be present: %s", body)
	}
	// 无错误时错误字段输出 null 而不是消失。
	if !strings.Contains(body, `"applyError":null`) || !strings.Contains(body, `"finalApplyError":null`) {
		t.Fatalf("empty apply errors must serialize as null: %s", body)
	}
}

func TestKVDeterministic(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set a=1"),
	}}
	requests := []AppendRequest{
		{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(2, 1, "set b=2"), entry(3, 1, "delete a")}},
	}
	first := runKV(t, initial, requests...)
	second := runKV(t, initial, requests...)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic output:\n%+v\n%+v", first, second)
	}
	encoded1, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	encoded2, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded1) != string(encoded2) {
		t.Fatalf("non-deterministic JSON:\n%s\n%s", encoded1, encoded2)
	}
}

// roundTrip 把输出编码为 JSON 再解码、再编码，模拟调用方保存或转交结果。
func roundTrip(t *testing.T, out ReplicateOutput) (ReplicateOutput, string) {
	t.Helper()
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReplicateOutput
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded, string(reencoded)
}

func TestKVRoundTripPreservesApplyFields(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0},
	)
	_, body := roundTrip(t, out)
	// 应用位置 0、无错误 null、空键值表 {} 在读取再输出后都必须保留。
	for _, fragment := range []string{
		`"appliedIndex":0`, `"applyError":null`,
		`"finalAppliedIndex":0`, `"finalKV":{}`, `"finalApplyError":null`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("round-tripped output lost %q: %s", fragment, body)
		}
	}
}

func TestKVRoundTripPreservesValuesAndError(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set ok=1"),
	}}
	out := runKV(t, initial,
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(2, 1, "set bad"), entry(3, 1, "set later=3")}},
	)
	decoded, _ := roundTrip(t, out)
	// 错误索引与原因、错误前已应用的键值内容、停住的应用位置原样保留。
	if decoded.FinalApplyError == nil || decoded.FinalApplyError.Index != 2 ||
		decoded.FinalApplyError.Reason != ApplyReasonSetMissingEquals {
		t.Fatalf("finalApplyError = %+v, want index 2 missing '='", decoded.FinalApplyError)
	}
	if decoded.FinalAppliedIndex == nil || *decoded.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %v, want 1", decoded.FinalAppliedIndex)
	}
	if !reflect.DeepEqual(decoded.FinalKV, map[string]string{"ok": "1"}) {
		t.Fatalf("finalKV = %v, want only entries applied before the error", decoded.FinalKV)
	}
	if decoded.Results[0].ApplyError == nil || decoded.Results[0].ApplyError.Index != 2 {
		t.Fatalf("per-request applyError = %+v, want index 2", decoded.Results[0].ApplyError)
	}
	if decoded.Results[0].AppliedIndex == nil || *decoded.Results[0].AppliedIndex != 1 {
		t.Fatalf("per-request appliedIndex = %v, want 1", decoded.Results[0].AppliedIndex)
	}
}

func TestKVRoundTripWithoutRequestsKeepsFinalApplyState(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set x=1"), entry(2, 2, "set y=2"),
	}}
	_, body := roundTrip(t, runKV(t, initial))
	for _, fragment := range []string{
		`"finalAppliedIndex":2`, `"finalKV":{"x":"1","y":"2"}`, `"finalApplyError":null`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("round-tripped output lost %q: %s", fragment, body)
		}
	}
}

func TestKVRoundTripDisabledAddsNoApplyFields(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}}, AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1})
	_, body := roundTrip(t, out)
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: round-tripped output must not contain %q: %s", field, body)
		}
	}
}

func TestKVRoundTripReuseObjectLeavesNoResidue(t *testing.T) {
	// 同一个结果对象先读启用应用的结果，再读未启用的：后一次输出不得残留
	// 前一次的键值表、错误或应用位置。
	enabled := runKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}})
	disabled := run(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}})
	enabledJSON, err := json.Marshal(enabled)
	if err != nil {
		t.Fatal(err)
	}
	disabledJSON, err := json.Marshal(disabled)
	if err != nil {
		t.Fatal(err)
	}
	var out ReplicateOutput
	if err := json.Unmarshal(enabledJSON, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(disabledJSON, &out); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(string(body), field) {
			t.Fatalf("stale apply field %q after reusing object: %s", field, body)
		}
	}
	if out.FinalKV != nil || out.FinalAppliedIndex != nil || out.FinalApplyError != nil {
		t.Fatalf("stale apply state in %+v", out)
	}
}

func TestKVAppendResultRoundTripStandalone(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0})
	encoded, err := json.Marshal(out.Results[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded AppendResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	body := string(reencoded)
	if !strings.Contains(body, `"appliedIndex":0`) || !strings.Contains(body, `"applyError":null`) {
		t.Fatalf("standalone result round trip lost apply fields: %s", body)
	}
}

func TestKVRoundTripRejectsBadFieldTypes(t *testing.T) {
	for _, data := range []string{
		`{"results":[],"finalTerm":0,"finalCommittedIndex":0,"finalLog":[],"finalAppliedIndex":"0"}`,
		`{"results":[],"finalTerm":0,"finalCommittedIndex":0,"finalLog":[],"finalKV":[]}`,
		`{"results":[],"finalTerm":0,"finalCommittedIndex":0,"finalLog":[],"finalApplyError":{"index":"2","reason":"x"}}`,
		`{"results":[{"accepted":true,"reason":"ok","term":1,"committedIndex":0,"appliedIndex":"0"}],"finalTerm":1,"finalCommittedIndex":0,"finalLog":[]}`,
	} {
		var out ReplicateOutput
		if err := json.Unmarshal([]byte(data), &out); err == nil {
			t.Fatalf("expected decode error for %s", data)
		}
	}
}

// decodeMap 把 JSON 解码为通用对象，便于只按“键是否出现”断言输出形状
// （不能用字符串包含判断：appliedIndex 是 finalAppliedIndex 的子串）。
func decodeMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return m
}

func mustHaveKeys(t *testing.T, m map[string]any, where string, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			t.Fatalf("%s: expected key %q present in %v", where, key, m)
		}
	}
}

func mustLackKeys(t *testing.T, m map[string]any, where string, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := m[key]; ok {
			t.Fatalf("%s: expected key %q absent in %v", where, key, m)
		}
	}
}

func resultMaps(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["results"].([]any)
	if !ok {
		t.Fatalf("results is not an array in %v", m)
	}
	results := make([]map[string]any, len(raw))
	for i, item := range raw {
		results[i], ok = item.(map[string]any)
		if !ok {
			t.Fatalf("result %d is not an object: %v", i, item)
		}
	}
	return results
}

// TestKVRoundTripPartialPerRequestFields 覆盖逐条请求一层只出现部分应用字段
// 的约定：appliedIndex 与 applyError 同组，出现任意一个再次输出就要带齐；
// 缺索引补 0、无错误补 null；字段出现与值为空是两回事（只有 null 错误也算
// 记录了应用状态）；已提供的非零索引与错误中的索引、原因原样保留。
func TestKVRoundTripPartialPerRequestFields(t *testing.T) {
	cases := []struct {
		name      string
		extra     string
		wantIndex float64
		wantError any // nil 表示输出必须为 null；否则为期望的错误对象
	}{
		{"only zero applied index", `"appliedIndex":0`, 0, nil},
		{"only nonzero applied index", `"appliedIndex":5`, 5, nil},
		{"only null apply error", `"applyError":null`, 0, nil},
		{"only apply error object",
			`"applyError":{"index":3,"reason":"boom"}`, 0,
			map[string]any{"index": float64(3), "reason": "boom"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := `{"accepted":true,"reason":"ok","term":2,"committedIndex":1,` + tc.extra + `}`
			var result AppendResult
			if err := json.Unmarshal([]byte(data), &result); err != nil {
				t.Fatal(err)
			}
			reencoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			m := decodeMap(t, reencoded)
			mustHaveKeys(t, m, "per-request result", "appliedIndex", "applyError")
			if m["appliedIndex"] != tc.wantIndex {
				t.Fatalf("appliedIndex = %v, want %v: %v", m["appliedIndex"], tc.wantIndex, m)
			}
			if tc.wantError == nil {
				if m["applyError"] != nil {
					t.Fatalf("applyError = %v, want null: %v", m["applyError"], m)
				}
			} else if !reflect.DeepEqual(m["applyError"], tc.wantError) {
				t.Fatalf("applyError = %v, want %v", m["applyError"], tc.wantError)
			}
			// 复制答复的既有字段不被部分应用字段干扰。
			if m["accepted"] != true || m["reason"] != "ok" ||
				m["term"] != float64(2) || m["committedIndex"] != float64(1) {
				t.Fatalf("replication fields changed: %v", m)
			}
		})
	}
}

// TestKVRoundTripPartialFinalFields 覆盖最终结果一层的部分字段约定：
// finalAppliedIndex、finalKV、finalApplyError 同组；缺索引补 0、缺键值表补
// 空对象 {}、无错误补 null；只带空键值表也要保留索引与错误字段；非零索引、
// 键值内容、错误索引与原因原样保留。
func TestKVRoundTripPartialFinalFields(t *testing.T) {
	cases := []struct {
		name      string
		extra     string
		wantIndex float64
		wantKV    any // nil 表示必须输出空对象 {}
		wantError any // nil 表示必须输出 null
	}{
		{"only zero final applied index", `"finalAppliedIndex":0`, 0, map[string]any{}, nil},
		{"only nonzero final applied index", `"finalAppliedIndex":7`, 7, map[string]any{}, nil},
		{"only empty final kv", `"finalKV":{}`, 0, map[string]any{}, nil},
		{"only nonempty final kv",
			`"finalKV":{"a":"1","b":"x=y"}`, 0,
			map[string]any{"a": "1", "b": "x=y"}, nil},
		{"only null final apply error", `"finalApplyError":null`, 0, map[string]any{}, nil},
		{"only final apply error object",
			`"finalApplyError":{"index":2,"reason":"` + ApplyReasonSetMissingEquals + `"}`, 0,
			map[string]any{},
			map[string]any{"index": float64(2), "reason": ApplyReasonSetMissingEquals}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := `{"results":[],"finalTerm":2,"finalCommittedIndex":1,` +
				`"finalLog":[{"index":1,"term":1,"command":"set a=1"}],` + tc.extra + `}`
			var out ReplicateOutput
			if err := json.Unmarshal([]byte(data), &out); err != nil {
				t.Fatal(err)
			}
			reencoded, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			m := decodeMap(t, reencoded)
			mustHaveKeys(t, m, "final output", "finalAppliedIndex", "finalKV", "finalApplyError")
			if m["finalAppliedIndex"] != tc.wantIndex {
				t.Fatalf("finalAppliedIndex = %v, want %v: %v", m["finalAppliedIndex"], tc.wantIndex, m)
			}
			if !reflect.DeepEqual(m["finalKV"], tc.wantKV) {
				t.Fatalf("finalKV = %v, want %v", m["finalKV"], tc.wantKV)
			}
			if tc.wantError == nil {
				if m["finalApplyError"] != nil {
					t.Fatalf("finalApplyError = %v, want null: %v", m["finalApplyError"], m)
				}
			} else if !reflect.DeepEqual(m["finalApplyError"], tc.wantError) {
				t.Fatalf("finalApplyError = %v, want %v", m["finalApplyError"], tc.wantError)
			}
			// 任期、提交位置与日志内容保持原样。
			if m["finalTerm"] != float64(2) || m["finalCommittedIndex"] != float64(1) {
				t.Fatalf("final replication fields changed: %v", m)
			}
			log := m["finalLog"].([]any)
			if !reflect.DeepEqual(log[0], map[string]any{"index": float64(1), "term": float64(1), "command": "set a=1"}) {
				t.Fatalf("finalLog changed: %v", log)
			}
		})
	}
}

// TestKVRoundTripApplyLevelsIndependent 两层应用字段各自按本层是否出现判断：
// 最终结果记录了应用状态，不能让没有应用字段的请求答复凭空多出应用信息；某条
// 请求带有应用字段，也不能让最终结果或其他请求多出字段。同一输出中混合两种
// 请求答复时，读取再输出必须保留各自区别。
func TestKVRoundTripApplyLevelsIndependent(t *testing.T) {
	perRequestKeys := []string{"appliedIndex", "applyError"}
	finalKeys := []string{"finalAppliedIndex", "finalKV", "finalApplyError"}
	cases := []struct {
		name string
		data string
	}{
		{
			"final level applied, requests mixed plain and applied",
			`{"results":[` +
				`{"accepted":true,"reason":"ok","term":3,"committedIndex":0},` +
				`{"accepted":false,"reason":"stale term: leader term is lower than current term","term":3,"committedIndex":0,"appliedIndex":2,"applyError":{"index":3,"reason":"boom"}}` +
				`],"finalTerm":3,"finalCommittedIndex":0,"finalLog":[],` +
				`"finalAppliedIndex":2,"finalKV":{"k":"v"},"finalApplyError":{"index":3,"reason":"boom"}}`,
		},
		{
			"final level absent, requests mixed applied and plain",
			`{"results":[` +
				`{"accepted":true,"reason":"ok","term":1,"committedIndex":0,"appliedIndex":0,"applyError":null},` +
				`{"accepted":true,"reason":"ok","term":1,"committedIndex":0}` +
				`],"finalTerm":1,"finalCommittedIndex":0,"finalLog":[]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out ReplicateOutput
			if err := json.Unmarshal([]byte(tc.data), &out); err != nil {
				t.Fatal(err)
			}
			reencoded, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			m := decodeMap(t, reencoded)
			results := resultMaps(t, m)
			if len(results) != 2 {
				t.Fatalf("expected 2 results, got %d", len(results))
			}
			if strings.Contains(tc.data, `"finalAppliedIndex":2`) {
				// 第一种情形：最终层有应用字段；请求 0 无、请求 1 有。
				mustLackKeys(t, results[0], "plain request", perRequestKeys...)
				mustHaveKeys(t, results[1], "applied request", perRequestKeys...)
				if results[1]["appliedIndex"] != float64(2) {
					t.Fatalf("request appliedIndex changed: %v", results[1])
				}
				if !reflect.DeepEqual(results[1]["applyError"],
					map[string]any{"index": float64(3), "reason": "boom"}) {
					t.Fatalf("request applyError changed: %v", results[1])
				}
				mustHaveKeys(t, m, "final output", finalKeys...)
				if !reflect.DeepEqual(m["finalKV"], map[string]any{"k": "v"}) {
					t.Fatalf("finalKV changed: %v", m["finalKV"])
				}
			} else {
				// 第二种情形：最终层无应用字段；请求 0 有、请求 1 无。
				mustHaveKeys(t, results[0], "applied request", perRequestKeys...)
				if results[0]["appliedIndex"] != float64(0) || results[0]["applyError"] != nil {
					t.Fatalf("applied request values changed: %v", results[0])
				}
				mustLackKeys(t, results[1], "plain request", perRequestKeys...)
				mustLackKeys(t, m, "final output", finalKeys...)
			}
		})
	}
}

// TestKVRoundTripLegacyResultWithoutApplyFields 完全没有应用字段的旧结果保持
// 原有输出形状；接受状态、拒绝原因、任期、提交位置与日志内容原样保留。
func TestKVRoundTripLegacyResultWithoutApplyFields(t *testing.T) {
	data := []byte(`{"results":[{"accepted":false,` +
		`"reason":"stale term: leader term is lower than current term",` +
		`"term":5,"committedIndex":1}],` +
		`"finalTerm":5,"finalCommittedIndex":1,` +
		`"finalLog":[{"index":1,"term":5,"command":"a"}]}`)
	var out ReplicateOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	want := decodeMap(t, data)
	got := decodeMap(t, reencoded)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy result changed shape:\nwant %v\n got %v", want, got)
	}
	results := resultMaps(t, got)
	mustLackKeys(t, results[0], "legacy request", "appliedIndex", "applyError")
	mustLackKeys(t, got, "legacy final output",
		"finalAppliedIndex", "finalKV", "finalApplyError")
}

// TestKVRoundTripFailedReuseKeepsPreviousResult 复用已有结果对象再次读入时，
// 类型非法的 JSON 必须明确报错，且原有结果完整保留——即使错误藏在某条请求
// 答复内，随后输出也不能混入这次读入的任何部分内容。
// TestKVRejectedReplicationKeepsApplyBoundary 回归保障：启用 applyKV 后复制请求
// 被拒绝时的状态边界——较高任期或较大 leaderCommit 都不能把未确认的命令写进
// 键值表。场景含一个已提交前缀与未提交尾部：
//   - 初始任期 2，idx1/idx2 任期均为 2，set balance=100 已提交而 set
//     balance=200 未提交：键值表只有 balance=100，应用位置停在 1；
//   - 任期 5 的请求把 idx2 任期错称为 3 并要求提交更后位置：因前缀不匹配被拒，
//     任期升到 5，但日志、提交位置、应用位置与键值表保持原值，无应用错误；
//   - 任期 9 但条目索引不连续的请求属于字段非法：整条拒绝且连任期都不得改变，
//     不能与上一种拒绝混为同样的状态变化；
//   - 之后任期 5、正确匹配 idx2 的合法请求追加 idx3 并提交到 3：按日志次序
//     应用尚未应用的命令，balance=200、receipt=ok，提交与应用位置均为 3。
func TestKVRejectedReplicationKeepsApplyBoundary(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 2, "set balance=100"),
		entry(2, 2, "set balance=200"), // 未提交尾部：任何拒绝都不能让它被应用
	}}
	wantOriginalLog := []LogEntry{
		entry(1, 2, "set balance=100"),
		entry(2, 2, "set balance=200"),
	}

	// 没有请求时：只应用初始已提交前缀，字符串值原样保留。
	start := runKV(t, initial)
	if *start.FinalAppliedIndex != 1 {
		t.Fatalf("initial appliedIndex = %d, want 1", *start.FinalAppliedIndex)
	}
	if !reflect.DeepEqual(finalKVOf(t, start), map[string]string{"balance": "100"}) {
		t.Fatalf("initial kv = %v, want only balance=100", start.FinalKV)
	}
	if start.FinalApplyError != nil {
		t.Fatalf("unexpected initial apply error: %+v", start.FinalApplyError)
	}

	// 请求一：高任期 + 前缀任期不匹配 + 更大的 leaderCommit，其余字段全部合法。
	mismatch := AppendRequest{Term: 5, PrevLogIndex: 2, PrevLogTerm: 3, LeaderCommit: 4,
		Entries: []LogEntry{entry(3, 5, "set later=x")}}
	// 请求二：任期 9，但条目索引没有从 prevLogIndex+1 开始——字段非法。
	gap := AppendRequest{Term: 9, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 5,
		Entries: []LogEntry{entry(4, 9, "set gap=y")}} // 期望索引 3
	// 请求三：任期 5、正确匹配 idx2（任期 2）的合法追加。
	legal := AppendRequest{Term: 5, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3,
		Entries: []LogEntry{entry(3, 5, "set receipt=ok")}}

	// 若输入停在第一次拒绝处：任期升到 5，其余一切不动，未确认命令不入表。
	stopped := runKV(t, initial, mismatch)
	r := stopped.Results[0]
	if r.Accepted || r.Reason != ReasonPrevLogMismatch {
		t.Fatalf("first request should be rejected for prefix mismatch: %+v", r)
	}
	if r.Term != 5 {
		t.Fatalf("higher term should survive rejection: term = %d, want 5", r.Term)
	}
	if r.CommittedIndex != 1 {
		t.Fatalf("commit advanced on rejection: %d, want 1", r.CommittedIndex)
	}
	if got := appliedIndexOf(t, r); got != 1 {
		t.Fatalf("applied index advanced on rejection: %d, want 1", got)
	}
	if r.ApplyError != nil {
		t.Fatalf("rejection must not produce an apply error: %+v", r.ApplyError)
	}
	if stopped.FinalTerm != 5 || stopped.FinalCommittedIndex != 1 {
		t.Fatalf("final state after stop: term=%d ci=%d, want 5/1",
			stopped.FinalTerm, stopped.FinalCommittedIndex)
	}
	if !reflect.DeepEqual(stopped.FinalLog, wantOriginalLog) {
		t.Fatalf("log changed after rejection: %+v", stopped.FinalLog)
	}
	if *stopped.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *stopped.FinalAppliedIndex)
	}
	if !reflect.DeepEqual(finalKVOf(t, stopped), map[string]string{"balance": "100"}) {
		t.Fatalf("kv changed after rejection: %v, want only balance=100", stopped.FinalKV)
	}
	if stopped.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", stopped.FinalApplyError)
	}

	// 完整过程：两种拒绝之后合法请求仍能追加并提交。
	out := runKV(t, initial, mismatch, gap, legal)
	wantResults := []struct {
		accepted bool
		reason   string
		term     int
		commit   int
		applied  int
	}{
		{false, ReasonPrevLogMismatch, 5, 1, 1}, // 任期更新保留，其余不动
		{false, ReasonEntryIndexGap, 5, 1, 1},   // 字段非法：连任期都停在 5
		{true, ReasonOK, 5, 3, 3},               // 追加 idx3，提交并应用到 3
	}
	if len(out.Results) != len(wantResults) {
		t.Fatalf("got %d results, want %d", len(out.Results), len(wantResults))
	}
	for i, want := range wantResults {
		got := out.Results[i]
		if got.Accepted != want.accepted || got.Reason != want.reason {
			t.Fatalf("result %d = accepted=%v reason=%q, want accepted=%v reason=%q",
				i, got.Accepted, got.Reason, want.accepted, want.reason)
		}
		if got.Term != want.term || got.CommittedIndex != want.commit {
			t.Fatalf("result %d state = term %d ci %d, want term %d ci %d",
				i, got.Term, got.CommittedIndex, want.term, want.commit)
		}
		if applied := appliedIndexOf(t, got); applied != want.applied {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, applied, want.applied)
		}
		if got.ApplyError != nil {
			t.Fatalf("result %d unexpected apply error: %+v", i, got.ApplyError)
		}
	}

	// 最终状态：任期 5、提交 3；日志为原两条加 idx3，未提交尾部命令原样保留。
	wantLog := []LogEntry{
		entry(1, 2, "set balance=100"),
		entry(2, 2, "set balance=200"),
		entry(3, 5, "set receipt=ok"),
	}
	if out.FinalTerm != 5 || out.FinalCommittedIndex != 3 {
		t.Fatalf("final replication state = term %d ci %d, want term 5 ci 3",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if *out.FinalAppliedIndex != 3 {
		t.Fatalf("final appliedIndex = %d, want 3", *out.FinalAppliedIndex)
	}
	// 按原日志顺序应用：idx2 把 balance 改成 200，idx3 写入 receipt。
	wantKV := map[string]string{"balance": "200", "receipt": "ok"}
	if !reflect.DeepEqual(finalKVOf(t, out), wantKV) {
		t.Fatalf("final kv = %v, want %v", out.FinalKV, wantKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

// replaceScenarioInitial 构造两条替换规则回归测试共用的初始状态：任期 4，
// 日志 idx1..idx4 任期为 1、2、4、4；只有 idx1（set balance=100）已提交，
// 后三条（set balance=200、delete balance、set legacy=old）均未提交。
func replaceScenarioInitial() InitialState {
	return InitialState{CurrentTerm: 4, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set balance=100"),
		entry(2, 2, "set balance=200"),
		entry(3, 4, "delete balance"),
		entry(4, 4, "set legacy=old"),
	}}
}

// TestKVTermConflictReplacesUncommittedSuffix 回归保障：新条目在某个未提交位置
// 出现任期冲突后，该位置及其后的旧日志被整体替换——被丢弃后缀里的后续位置即使
// 与新条目同任期、命令不同，也不再触发同任期命令冲突拒绝。本场景中 idx2 任期
// 3 对旧任期 4 构成任期冲突，idx3 与旧 idx3 同为任期 4 但命令不同：请求必须
// 被接受，已提交前缀完整保留，原 idx4 删除，提交与应用位置推进到 3，键值表只
// 反映新日志的命令（旧后缀的 delete/set legacy 不得生效）。
func TestKVTermConflictReplacesUncommittedSuffix(t *testing.T) {
	initial := replaceScenarioInitial()
	out := runKV(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(2, 3, "set balance=300"),
				entry(3, 4, "set receipt=ok"),
			}},
	)

	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("request should be accepted: %+v", result)
	}
	if result.Term != 4 || result.CommittedIndex != 3 {
		t.Fatalf("result state = term %d ci %d, want term 4 ci 3", result.Term, result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 3 {
		t.Fatalf("result appliedIndex = %d, want 3", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", result.ApplyError)
	}

	// 已提交前缀保留，idx2 起整段替换为新条目，原 idx4 被删除：最终只剩三条。
	wantLog := []LogEntry{
		entry(1, 1, "set balance=100"),
		entry(2, 3, "set balance=300"),
		entry(3, 4, "set receipt=ok"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 4 || out.FinalCommittedIndex != 3 {
		t.Fatalf("final state = term %d ci %d, want term 4 ci 3", out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 3 {
		t.Fatalf("final appliedIndex = %d, want 3", *out.FinalAppliedIndex)
	}
	// 键值表只来自新日志：balance=300、receipt=ok；旧后缀的 delete balance
	// 与 set legacy=old 不得留下任何痕迹，也不能产生应用错误。
	wantKV := map[string]string{"balance": "300", "receipt": "ok"}
	if !reflect.DeepEqual(finalKVOf(t, out), wantKV) {
		t.Fatalf("final kv = %v, want %v", out.FinalKV, wantKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

// TestKVSameTermConflictOnKeptPrefixRejects 回归保障相反情形：同一个初始状态下，
// idx2 新条目沿用旧任期 2 但命令不同——冲突位于仍需保留的旧日志位置（其前没有
// 任期冲突触发截断），必须按同任期命令冲突拒绝整条请求：日志保持原有四条，
// 提交与应用位置停在 1，键值表只有 balance=100。
func TestKVSameTermConflictOnKeptPrefixRejects(t *testing.T) {
	initial := replaceScenarioInitial()
	out := runKV(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(2, 2, "set balance=300"), // 同任期同索引、命令不同
				entry(3, 4, "set receipt=ok"),
			}},
	)

	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonCommandConflictSameTerm {
		t.Fatalf("request should be rejected for same-term command conflict: %+v", result)
	}
	if result.Term != 4 || result.CommittedIndex != 1 {
		t.Fatalf("result state = term %d ci %d, want term 4 ci 1", result.Term, result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 1 {
		t.Fatalf("result appliedIndex = %d, want 1", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("rejection must not produce an apply error: %+v", result.ApplyError)
	}

	// 整条拒绝：日志、提交位置、应用位置与键值表全部保持原样。
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed after rejection: %+v", out.FinalLog)
	}
	if out.FinalTerm != 4 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final state = term %d ci %d, want term 4 ci 1", out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if !reflect.DeepEqual(finalKVOf(t, out), map[string]string{"balance": "100"}) {
		t.Fatalf("final kv = %v, want only balance=100", out.FinalKV)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

func TestKVRoundTripFailedReuseKeepsPreviousResult(t *testing.T) {
	original := runKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}},
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(2, 1, "set bad"), entry(3, 1, "set k=v")}},
	)
	originalJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	badInputs := []string{
		// 错误位于某条请求答复内：应用索引写成字符串。
		`{"results":[{"accepted":true,"reason":"ok","term":9,"committedIndex":9,"appliedIndex":"3"}],"finalTerm":9,"finalCommittedIndex":9,"finalLog":[]}`,
		// 最终层：应用索引写成字符串。
		`{"results":[],"finalTerm":9,"finalCommittedIndex":9,"finalLog":[],"finalAppliedIndex":"9"}`,
		// 最终层：键值表写成数组。
		`{"results":[],"finalTerm":9,"finalCommittedIndex":9,"finalLog":[],"finalKV":["nope"]}`,
	}
	for _, bad := range badInputs {
		var out ReplicateOutput
		if err := json.Unmarshal(originalJSON, &out); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(bad), &out); err == nil {
			t.Fatalf("expected decode error for %s", bad)
		}
		reencoded, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(reencoded) != string(originalJSON) {
			t.Fatalf("previous result not preserved after failed decode of %s:\nwant %s\n got %s",
				bad, originalJSON, reencoded)
		}
	}
}
