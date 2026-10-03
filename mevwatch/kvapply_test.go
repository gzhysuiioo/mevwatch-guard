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
