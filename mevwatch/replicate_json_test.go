package mevwatch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// canonicalJSON 把 JSON 解码为通用结构再编码，消除空白与字段排列差异，
// 只比较字段是否出现、null/空对象区别与字段值。
func canonicalJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid JSON %v: %s", err, string(raw))
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encode canonical JSON: %v", err)
	}
	return string(out)
}

func roundTripJSON(t *testing.T, out ReplicateOutput) string {
	t.Helper()
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ReplicateOutput
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, string(encoded))
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if got, want := canonicalJSON(t, reencoded), canonicalJSON(t, encoded); got != want {
		t.Fatalf("decode then encode lost information:\n got: %s\nwant: %s", got, want)
	}
	return string(reencoded)
}

func TestJSONRoundTripEnabledKeepsZeroNullAndEmptyTable(t *testing.T) {
	// 第一条请求什么都不提交：appliedIndex 为 0、applyError 为 null、
	// finalKV 为空表——这些信息在读取再输出后都不能消失。
	out := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 1,
			Entries: []LogEntry{entry(1, 1, "set a=1")}},
	)
	body := roundTripJSON(t, out)
	if !strings.Contains(body, `"appliedIndex":0`) {
		t.Fatalf("per-request appliedIndex 0 missing: %s", body)
	}
	if !strings.Contains(body, `"finalAppliedIndex":1`) {
		t.Fatalf("finalAppliedIndex missing: %s", body)
	}
	if !strings.Contains(body, `"finalKV":{}`) && strings.Contains(body, `"finalKV":null`) {
		t.Fatalf("empty finalKV must stay {}, not null: %s", body)
	}
	if !strings.Contains(body, `"finalKV":{"a":"1"}`) {
		t.Fatalf("finalKV content missing: %s", body)
	}
	if !strings.Contains(body, `"applyError":null`) || !strings.Contains(body, `"finalApplyError":null`) {
		t.Fatalf("null error fields must be preserved: %s", body)
	}
}

func TestJSONRoundTripEnabledMatchesStruct(t *testing.T) {
	out := runKV(t, InitialState{CurrentTerm: 2, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set x=1"), entry(2, 2, "set y=2"),
	}},
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 2},
	)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReplicateOutput
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, out) {
		t.Fatalf("round trip changed struct:\n%+v\n%+v", decoded, out)
	}
}

func TestJSONRoundTripNoRequestsKeepsFinalApplyState(t *testing.T) {
	// 没有复制请求时，初始已提交前缀的应用结果（含最终位置、键值表、错误）
	// 仍然要随 JSON 保留。
	out := runKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set ok=1"), entry(2, 1, "set bad"),
	}})
	body := roundTripJSON(t, out)
	for _, fragment := range []string{
		`"results":[]`,
		`"finalAppliedIndex":1`,
		`"finalKV":{"ok":"1"}`,
		`"finalApplyError":{"index":2,"reason":` + quoteJSON(ApplyReasonSetMissingEquals) + `}`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("missing %s in %s", fragment, body)
		}
	}
}

func TestJSONRoundTripFormatErrorStatePreserved(t *testing.T) {
	initial := InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set ok=1"),
	}}
	out := runKV(t, initial,
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{entry(2, 1, "set bad"), entry(3, 1, "set later=3")}},
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 4,
			Entries: []LogEntry{entry(4, 2, "set more=4")}},
	)
	body := roundTripJSON(t, out)
	// 错误索引与原因、错误前已应用的键值、停住的应用位置原样保留：不能把错误
	// 改成成功，也不能把未应用内容补进键值表。
	for _, fragment := range []string{
		`"appliedIndex":1`,
		`"finalAppliedIndex":1`,
		`"applyError":{"index":2,"reason":` + quoteJSON(ApplyReasonSetMissingEquals) + `}`,
		`"finalApplyError":{"index":2,"reason":` + quoteJSON(ApplyReasonSetMissingEquals) + `}`,
		`"finalKV":{"ok":"1"}`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("missing %s in %s", fragment, body)
		}
	}
	if strings.Contains(body, `"later"`) || strings.Contains(body, `"more"`) {
		t.Fatalf("unapplied entries leaked into finalKV: %s", body)
	}
}

func TestJSONRoundTripDisabledShapeGainsNoFields(t *testing.T) {
	out, err := Replicate(InitialState{CurrentTerm: 1},
		[]AppendRequest{{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0}})
	if err != nil {
		t.Fatal(err)
	}
	body := roundTripJSON(t, out)
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("disabled result gained apply field %q after round trip: %s", field, body)
		}
	}
}

func TestJSONRoundTripOutputReuseHasNoResidue(t *testing.T) {
	enabled, err := json.Marshal(mustRunKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"), entry(2, 1, "set broken"),
	}},
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 2},
	))
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := json.Marshal(mustRun(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0}))
	if err != nil {
		t.Fatal(err)
	}

	// 同一个结果对象先读启用应用的结果，再读未启用的结果：不能残留键值表、
	// 错误或应用位置。
	var out ReplicateOutput
	if err := json.Unmarshal(enabled, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(disabled, &out); err != nil {
		t.Fatal(err)
	}
	body := mustMarshal(t, out)
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("residue apply field %q after decoding disabled output: %s", field, body)
		}
	}
	if out.FinalKV != nil || out.FinalApplyError != nil || out.FinalAppliedIndex != nil {
		t.Fatalf("residue apply state in struct: %+v", out)
	}
	for i, result := range out.Results {
		if result.AppliedIndex != nil || result.ApplyError != nil {
			t.Fatalf("result %d residue apply state: %+v", i, result)
		}
	}

	// 反过来：先读未启用、再读启用，字段必须准确出现且值正确。
	if err := json.Unmarshal(disabled, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(enabled, &out); err != nil {
		t.Fatal(err)
	}
	body = mustMarshal(t, out)
	for _, fragment := range []string{
		`"appliedIndex":1`,
		`"finalAppliedIndex":1`,
		`"finalKV":{"x":"1"}`,
		`"finalApplyError":{"index":2`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("enabled re-decode missing %s in %s", fragment, body)
		}
	}
}

func TestJSONRoundTripSingleResult(t *testing.T) {
	// 每条请求的结果单独读写时也保持含义：启用形状保留 0 与 null。
	enabled := AppendResult{
		Accepted: true, Reason: ReasonOK, Term: 1, CommittedIndex: 0,
		AppliedIndex: intPtr(0), ApplyError: nil, applyFields: true,
	}
	body := roundTripSingle(t, enabled)
	for _, fragment := range []string{`"appliedIndex":0`, `"applyError":null`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("single enabled result missing %s: %s", fragment, body)
		}
	}

	withError := AppendResult{
		Accepted: true, Reason: ReasonOK, Term: 1, CommittedIndex: 2,
		AppliedIndex: intPtr(1),
		ApplyError:   &ApplyError{Index: 2, Reason: ApplyReasonUnknownCommand},
		applyFields:  true,
	}
	body = roundTripSingle(t, withError)
	if !strings.Contains(body, `"appliedIndex":1`) ||
		!strings.Contains(body, `"applyError":{"index":2,"reason":`+quoteJSON(ApplyReasonUnknownCommand)+`}`) {
		t.Fatalf("single result error state not preserved: %s", body)
	}

	// 未启用形状单独读写后不增加应用字段。
	disabled := AppendResult{Accepted: false, Reason: ReasonStaleTerm, Term: 5, CommittedIndex: 1}
	body = roundTripSingle(t, disabled)
	if strings.Contains(body, "appliedIndex") || strings.Contains(body, "applyError") {
		t.Fatalf("single disabled result gained apply fields: %s", body)
	}
}

func TestJSONRoundTripSingleResultReuseHasNoResidue(t *testing.T) {
	var r AppendResult
	enabled := mustMarshal(t, AppendResult{
		Accepted: true, Reason: ReasonOK, Term: 1, CommittedIndex: 2,
		AppliedIndex: intPtr(1), ApplyError: &ApplyError{Index: 2, Reason: ApplyReasonUnknownCommand},
		applyFields: true,
	})
	disabled := mustMarshal(t, AppendResult{Accepted: false, Reason: ReasonStaleTerm, Term: 5, CommittedIndex: 1})

	if err := json.Unmarshal([]byte(enabled), &r); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(disabled), &r); err != nil {
		t.Fatal(err)
	}
	body := mustMarshal(t, r)
	if strings.Contains(body, "appliedIndex") || strings.Contains(body, "applyError") {
		t.Fatalf("single result carries residue apply fields: %s", body)
	}
	if r.AppliedIndex != nil || r.ApplyError != nil {
		t.Fatalf("single result carries residue apply state: %+v", r)
	}
}

func TestJSONDecodeTypeErrors(t *testing.T) {
	// 字段类型错误的 JSON 必须返回解码错误，不能用零值掩盖。
	badOutputs := []string{
		`{"finalAppliedIndex":"0"}`,
		`{"finalKV":[]}`,
		`{"finalApplyError":1}`,
		`{"results":[{"appliedIndex":"0"}]}`,
		`{"results":[{"applyError":1}]}`,
		`{"results":"x"}`,
		`{"finalLog":"x"}`,
	}
	for _, input := range badOutputs {
		var out ReplicateOutput
		if err := json.Unmarshal([]byte(input), &out); err == nil {
			t.Fatalf("expected decode error for %s, got %+v", input, out)
		}
	}
	badResults := []string{
		`{"appliedIndex":"0"}`,
		`{"appliedIndex":true}`,
		`{"applyError":1}`,
		`{"accepted":"yes"}`,
		`{"term":"1"}`,
	}
	for _, input := range badResults {
		var r AppendResult
		if err := json.Unmarshal([]byte(input), &r); err == nil {
			t.Fatalf("expected decode error for single result %s, got %+v", input, r)
		}
	}
}

func TestJSONDecodeExplicitNullsKeepFields(t *testing.T) {
	// 显式 null 表示“字段存在但暂无内容”：重新输出时按启用形状补回 0/{}。
	var out ReplicateOutput
	input := `{
	  "results": [{"accepted": true, "reason": "ok", "term": 1, "committedIndex": 0,
	               "appliedIndex": 0, "applyError": null}],
	  "finalTerm": 1, "finalCommittedIndex": 0, "finalLog": [],
	  "finalAppliedIndex": 0, "finalKV": {}, "finalApplyError": null
	}`
	if err := json.Unmarshal([]byte(input), &out); err != nil {
		t.Fatal(err)
	}
	body := mustMarshal(t, out)
	for _, fragment := range []string{
		`"appliedIndex":0`, `"applyError":null`,
		`"finalAppliedIndex":0`, `"finalKV":{}`, `"finalApplyError":null`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("missing %s in %s", fragment, body)
		}
	}
}

func mustRunKV(t *testing.T, initial InitialState, requests ...AppendRequest) ReplicateOutput {
	t.Helper()
	out, err := ReplicateWithOptions(initial, requests, ReplicateOptions{ApplyKV: true})
	if err != nil {
		t.Fatalf("ReplicateWithOptions: %v", err)
	}
	return out
}

func mustRun(t *testing.T, initial InitialState, requests ...AppendRequest) ReplicateOutput {
	t.Helper()
	out, err := Replicate(initial, requests)
	if err != nil {
		t.Fatalf("Replicate: %v", err)
	}
	return out
}

func roundTripSingle(t *testing.T, r AppendResult) string {
	t.Helper()
	encoded := mustMarshal(t, r)
	var decoded AppendResult
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatalf("unmarshal single result: %v", err)
	}
	if !reflect.DeepEqual(decoded, r) {
		t.Fatalf("single result round trip mismatch:\n%+v\n%+v", decoded, r)
	}
	return mustMarshal(t, decoded)
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

func intPtr(v int) *int { return &v }

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
