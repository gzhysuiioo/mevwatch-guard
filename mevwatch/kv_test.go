package mevwatch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func kvRun(t *testing.T, initial InitialState, requests ...AppendRequest) ReplicateOutput {
	t.Helper()
	initial.ApplyKV = true
	out, err := Replicate(initial, requests)
	if err != nil {
		t.Fatalf("Replicate returned error: %v", err)
	}
	return out
}

// set/delete 基本语义：值按原文保留（空、含空格、中文、额外等号），
// 删除不存在的键算成功。
func TestApplyKVSetDeleteAndVerbatimValues(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 7,
			Entries: []LogEntry{
				entry(1, 1, "set x=1"),
				entry(2, 1, "set y=hello world"),
				entry(3, 1, "set z=中文值"),
				entry(4, 1, "set w=a=b=c"),
				entry(5, 1, "set empty="),
				entry(6, 1, "delete x"),
				entry(7, 1, "delete ghost"),
			}},
	)
	want := map[string]string{
		"y":     "hello world",
		"z":     "中文值",
		"w":     "a=b=c",
		"empty": "",
	}
	if !reflect.DeepEqual(out.FinalKV, want) {
		t.Fatalf("finalKV = %+v, want %+v", out.FinalKV, want)
	}
	if out.FinalAppliedIndex != 7 {
		t.Fatalf("finalAppliedIndex = %d, want 7", out.FinalAppliedIndex)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", out.FinalApplyError)
	}
	if len(out.Results) != 1 {
		t.Fatalf("results = %+v, want one per-request result", out.Results)
	}
	result := out.Results[0]
	if result.ApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", result.ApplyError)
	}
	if result.AppliedIndex != 7 {
		t.Fatalf("appliedIndex = %d, want 7", result.AppliedIndex)
	}
}

// 初始日志中已提交的前缀在任何请求之前按索引顺序应用。
func TestApplyKVInitialCommittedPrefix(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1, CommittedIndex: 2,
		Log: []LogEntry{
			entry(1, 1, "set a=1"),
			entry(2, 1, "set b=2"),
			entry(3, 1, "set c=3"), // 未提交
		}},
		// 空心跳把提交推进到 3。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 3},
	)
	want := map[string]string{"a": "1", "b": "2", "c": "3"}
	if !reflect.DeepEqual(out.FinalKV, want) {
		t.Fatalf("finalKV = %+v, want %+v", out.FinalKV, want)
	}
	if out.FinalAppliedIndex != 3 {
		t.Fatalf("finalAppliedIndex = %d, want 3", out.FinalAppliedIndex)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", out.FinalApplyError)
	}
}

// 无请求时也要反映初始已提交前缀的应用结果。
func TestApplyKVNoRequestsReflectsPrefix(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 1, "set a=1")}})
	if len(out.Results) != 0 {
		t.Fatalf("results = %+v, want empty", out.Results)
	}
	if out.FinalAppliedIndex != 1 || out.FinalApplyError != nil {
		t.Fatalf("finalAppliedIndex=%d finalApplyError=%+v", out.FinalAppliedIndex, out.FinalApplyError)
	}
	if !reflect.DeepEqual(out.FinalKV, map[string]string{"a": "1"}) {
		t.Fatalf("finalKV = %+v", out.FinalKV)
	}

	// 初始提交前缀为空：已应用索引从 0 开始，表为 {}。
	out = kvRun(t, InitialState{CurrentTerm: 1})
	if out.FinalAppliedIndex != 0 {
		t.Fatalf("finalAppliedIndex = %d, want 0", out.FinalAppliedIndex)
	}
	if len(out.FinalKV) != 0 {
		t.Fatalf("finalKV = %+v, want empty", out.FinalKV)
	}
}

// 已提交命令格式错误：保留此前成功结果，应用停在出错条目之前，
// 出错条目及其后所有条目均不执行；复制请求仍按原规则处理。
func TestApplyKVMalformedCommittedHalts(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 3,
		Log: []LogEntry{
			entry(1, 1, "set a=1"),
			entry(2, 1, "not-a-command"),
			entry(3, 1, "set c=3"),
		}}
	out := kvRun(t, initial,
		// 请求仍被接受，日志继续追加并提交，但应用状态停住。
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 4,
			Entries: []LogEntry{entry(4, 1, "set d=4")}},
	)
	want := map[string]string{"a": "1"}
	if !reflect.DeepEqual(out.FinalKV, want) {
		t.Fatalf("finalKV = %+v, want %+v", out.FinalKV, want)
	}
	if out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 {
		t.Fatalf("finalApplyError = %+v, want index 2", out.FinalApplyError)
	}
	if out.FinalApplyError.Reason == "" {
		t.Fatalf("apply error reason should describe the format problem")
	}
	if !out.Results[0].Accepted {
		t.Fatalf("replication should still succeed: %s", out.Results[0].Reason)
	}
	if out.Results[0].AppliedIndex != 1 || out.Results[0].ApplyError == nil ||
		out.Results[0].ApplyError.Index != 2 {
		t.Fatalf("per-request apply state = %+v", out.Results[0])
	}
	if out.FinalCommittedIndex != 4 || len(out.FinalLog) != 4 {
		t.Fatalf("replication state should advance: ci=%d log=%+v", out.FinalCommittedIndex, out.FinalLog)
	}
}

// 未提交条目的格式错误不能提前报错；提交推进到它时才出错。
func TestApplyKVUncommittedMalformedDeferred(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "set a=1"), entry(2, 1, "bad")}},
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 2},
	)
	if out.Results[0].ApplyError != nil {
		t.Fatalf("uncommitted error reported early: %+v", out.Results[0].ApplyError)
	}
	if out.Results[0].AppliedIndex != 1 {
		t.Fatalf("appliedIndex = %d, want 1", out.Results[0].AppliedIndex)
	}
	if out.Results[1].ApplyError == nil || out.Results[1].ApplyError.Index != 2 {
		t.Fatalf("expected error at index 2, got %+v", out.Results[1].ApplyError)
	}
	if out.Results[1].AppliedIndex != 1 {
		t.Fatalf("appliedIndex = %d, want 1", out.Results[1].AppliedIndex)
	}
	if !reflect.DeepEqual(out.FinalKV, map[string]string{"a": "1"}) {
		t.Fatalf("finalKV = %+v", out.FinalKV)
	}
}

// 提交位置不变、空心跳及重复复制都不能重复应用已有位置。
func TestApplyKVIdempotentReplication(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "set x=1")}},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "set x=1")}}, // 重复复制
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1}, // 空心跳
	)
	for i, result := range out.Results {
		if result.ApplyError != nil {
			t.Fatalf("result %d: unexpected error: %+v", i, result.ApplyError)
		}
		if result.AppliedIndex != 1 {
			t.Fatalf("result %d: appliedIndex = %d, want 1", i, result.AppliedIndex)
		}
	}
	if !reflect.DeepEqual(out.FinalKV, map[string]string{"x": "1"}) {
		t.Fatalf("finalKV = %+v", out.FinalKV)
	}
}

// 未提交后缀被替换时，键值表不能出现被丢弃命令的效果。
func TestApplyKVTruncationDiscardsEffects(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "set a=1"), entry(2, 1, "set doomed=1")}},
		// 用更高任期的条目替换未提交后缀：idx2 任期不同，截断后重写。
		AppendRequest{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 2, "set b=2")}},
	)
	want := map[string]string{"a": "1", "b": "2"}
	if !reflect.DeepEqual(out.FinalKV, want) {
		t.Fatalf("finalKV = %+v, want %+v", out.FinalKV, want)
	}
	if out.FinalAppliedIndex != 2 {
		t.Fatalf("finalAppliedIndex = %d, want 2", out.FinalAppliedIndex)
	}
}

// 同一个键的多次操作按日志次序生效。
func TestApplyKVRepeatedOpsOrder(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(1, 1, "set x=1"),
				entry(2, 1, "delete x"),
				entry(3, 1, "set x=3"),
				entry(4, 1, "set x=4"),
			}},
	)
	if !reflect.DeepEqual(out.FinalKV, map[string]string{"x": "4"}) {
		t.Fatalf("finalKV = %+v", out.FinalKV)
	}
}

// 各种格式错误：出错索引与具体原因都要给出。
func TestApplyKVMalformedCommands(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"empty", ""},
		{"uppercase set", "SET x=1"},
		{"uppercase delete", "DELETE x"},
		{"set no key", "set"},
		{"set no space", "setx=1"},
		{"set tab separator", "set\tx=1"},
		{"set two spaces", "set  x=1"},
		{"set empty key with equals", "set =1"},
		{"set no equals", "set x"},
		{"set space in key", "set x y=1"},
		{"set space before equals", "set x =1"},
		{"set leading whitespace", " set x=1"},
		{"delete no key", "delete"},
		{"delete no space", "deletex"},
		{"delete two spaces", "delete  x"},
		{"delete trailing whitespace", "delete x "},
		{"delete equals in key", "delete x=y"},
		{"delete space in key", "delete x y"},
		{"delete leading whitespace", " delete x"},
		{"unknown command", "get x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := kvRun(t, InitialState{CurrentTerm: 1, CommittedIndex: 1,
				Log: []LogEntry{entry(1, 1, tc.command)}})
			if out.FinalApplyError == nil {
				t.Fatalf("command %q: expected apply error, got nil", tc.command)
			}
			if out.FinalApplyError.Index != 1 {
				t.Fatalf("error index = %d, want 1", out.FinalApplyError.Index)
			}
			if out.FinalApplyError.Reason == "" ||
				!strings.Contains(out.FinalApplyError.Reason, "malformed command") {
				t.Fatalf("error reason = %q, want malformed command description", out.FinalApplyError.Reason)
			}
			if out.FinalAppliedIndex != 0 {
				t.Fatalf("appliedIndex = %d, want 0", out.FinalAppliedIndex)
			}
		})
	}
}

// 格式错误后应用状态保持停住：后续请求即使提交推进也不再应用。
func TestApplyKVStaysHaltedAfterError(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
			Entries: []LogEntry{entry(1, 1, "set a=1"), entry(2, 1, "bad")}},
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(3, 1, "set c=3")}},
	)
	if out.FinalAppliedIndex != 1 {
		t.Fatalf("finalAppliedIndex = %d, want 1", out.FinalAppliedIndex)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 {
		t.Fatalf("finalApplyError = %+v", out.FinalApplyError)
	}
	if !reflect.DeepEqual(out.FinalKV, map[string]string{"a": "1"}) {
		t.Fatalf("finalKV = %+v", out.FinalKV)
	}
	for i, result := range out.Results {
		if result.AppliedIndex != 1 {
			t.Fatalf("result %d: appliedIndex = %d, want 1", i, result.AppliedIndex)
		}
	}
}

// 未启用 applyKV 时：输出不含键值字段，命令可以是任意字符串，行为与旧版一致。
func TestApplyKVDisabledByDefault(t *testing.T) {
	out, err := Replicate(InitialState{CurrentTerm: 1},
		[]AppendRequest{{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "anything goes"), entry(2, 1, "")}}},
	)
	if err != nil {
		t.Fatalf("Replicate returned error: %v", err)
	}
	if out.FinalAppliedIndex != 0 || out.FinalKV != nil || out.FinalApplyError != nil {
		t.Fatalf("kv fields present when disabled: %+v", out)
	}
	for i, result := range out.Results {
		if result.AppliedIndex != 0 || result.ApplyError != nil {
			t.Fatalf("result %d: kv fields present when disabled: %+v", i, result)
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, field := range []string{"appliedIndex", "applyError", "finalKV", "finalAppliedIndex", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("output contains %q when applyKV disabled: %s", field, body)
		}
	}
}

// 启用时 JSON 形状：applyError 为 null、finalKV 为 {}。
func TestApplyKVJSONShape(t *testing.T) {
	out := kvRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0},
	)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if !strings.Contains(body, `"finalKV":{}`) {
		t.Fatalf("empty finalKV should marshal as {}, got: %s", body)
	}
	if !strings.Contains(body, `"finalApplyError":null`) {
		t.Fatalf("null finalApplyError expected, got: %s", body)
	}
	if !strings.Contains(body, `"applyError":null`) {
		t.Fatalf("null applyError expected, got: %s", body)
	}
	if !strings.Contains(body, `"appliedIndex":0`) {
		t.Fatalf("appliedIndex from 0 expected, got: %s", body)
	}
}

// 相同输入得到相同数据与逐次结果。
func TestApplyKVDeterministic(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 1, "set a=1")}}
	requests := []AppendRequest{
		{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 1, "set b=2")}},
		{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(3, 1, "bad")}},
	}
	first := kvRun(t, initial, requests...)
	second := kvRun(t, initial, requests...)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic output:\n%+v\n%+v", first, second)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReplicateOutput
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.kvEnabled = true // 反序列化不会恢复未导出的 JSON 开关
	for i := range decoded.Results {
		decoded.Results[i].kvEnabled = true
	}
	if !reflect.DeepEqual(decoded, first) {
		t.Fatalf("JSON round trip mismatch:\n%+v\n%+v", decoded, first)
	}
}
