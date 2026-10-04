// 结果 JSON 读入再输出的回归测试：调用方保存结果后可能只保留部分应用字段
// 再转交其他程序。同一层出现任一应用字段即按启用键值应用处理，再次输出带齐
// 该层应用信息；字段是否出现与值是否为空分开处理；逐条请求结果与最终结果两
// 层各自独立判断；读入失败时复用的结果对象保持原样。
package mevwatch

import (
	"encoding/json"
	"strings"
	"testing"
)

// reencode 把 data 读入 ReplicateOutput 再输出，模拟调用方保存（可能裁过
// 字段的）结果后转交给其他程序读取。
func reencode(t *testing.T, data string) (ReplicateOutput, string) {
	t.Helper()
	var out ReplicateOutput
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return out, string(encoded)
}

func TestApplyFieldsPartialPerRequestResult(t *testing.T) {
	cases := []struct {
		name     string
		result   string
		contains []string
	}{
		// 只带 applyError: null 也是“记录了应用状态”，不是未启用：索引补 0。
		{"only applyError null",
			`{"accepted":true,"reason":"ok","term":1,"committedIndex":0,"applyError":null}`,
			[]string{`"appliedIndex":0`, `"applyError":null`}},
		// 只带 appliedIndex 时错误字段补 null。
		{"only appliedIndex",
			`{"accepted":true,"reason":"ok","term":1,"committedIndex":0,"appliedIndex":0}`,
			[]string{`"appliedIndex":0`, `"applyError":null`}},
		// 已提供的非零索引与错误内容保持原值。
		{"non-zero values kept",
			`{"accepted":true,"reason":"ok","term":1,"committedIndex":3,"appliedIndex":3,"applyError":{"index":2,"reason":"bad command"}}`,
			[]string{`"appliedIndex":3`, `"applyError":{"index":2,"reason":"bad command"}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var result AppendResult
			if err := json.Unmarshal([]byte(tc.result), &result); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, fragment := range tc.contains {
				if !strings.Contains(string(encoded), fragment) {
					t.Fatalf("re-encoded result lost %q: %s", fragment, encoded)
				}
			}
		})
	}
}

func TestApplyFieldsPartialFinalGroup(t *testing.T) {
	const base = `"results":[],"finalTerm":1,"finalCommittedIndex":0,"finalLog":[]`
	cases := []struct {
		name     string
		data     string
		contains []string
	}{
		// 只带空键值表也是“记录了应用状态”：索引补 0、错误补 null。
		{"only empty finalKV",
			`{` + base + `,"finalKV":{}}`,
			[]string{`"finalAppliedIndex":0`, `"finalKV":{}`, `"finalApplyError":null`}},
		// 只带最终应用索引：键值表补 {}、错误补 null，索引保持原值。
		{"only finalAppliedIndex",
			`{` + base + `,"finalAppliedIndex":2}`,
			[]string{`"finalAppliedIndex":2`, `"finalKV":{}`, `"finalApplyError":null`}},
		// 只带错误：索引补 0、键值表补 {}，错误内容保持原值。
		{"only finalApplyError",
			`{` + base + `,"finalApplyError":{"index":2,"reason":"bad command"}}`,
			[]string{`"finalAppliedIndex":0`, `"finalKV":{}`, `"finalApplyError":{"index":2,"reason":"bad command"}`}},
		// 非零索引与键值内容保持原值。
		{"values kept",
			`{` + base + `,"finalAppliedIndex":3,"finalKV":{"x":"1"},"finalApplyError":null}`,
			[]string{`"finalAppliedIndex":3`, `"finalKV":{"x":"1"}`, `"finalApplyError":null`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, body := reencode(t, tc.data)
			for _, fragment := range tc.contains {
				if !strings.Contains(body, fragment) {
					t.Fatalf("re-encoded output lost %q: %s", fragment, body)
				}
			}
		})
	}
}

func TestApplyFieldsFinalDoesNotLeakIntoResults(t *testing.T) {
	// 最终结果记录了应用状态，不带应用字段的请求答复不得因此补上。
	_, body := reencode(t, `{"results":[{"accepted":true,"reason":"ok","term":1,"committedIndex":1}],`+
		`"finalTerm":1,"finalCommittedIndex":1,"finalLog":[{"index":1,"term":1,"command":"set x=1"}],`+
		`"finalAppliedIndex":1,"finalKV":{"x":"1"},"finalApplyError":null}`)
	if !strings.Contains(body, `"finalAppliedIndex":1`) {
		t.Fatalf("final apply fields lost: %s", body)
	}
	// "appliedIndex" 带前导引号与小写 a，不会误匹配 finalAppliedIndex。
	if strings.Contains(body, `"appliedIndex"`) || strings.Contains(body, `"applyError"`) {
		t.Fatalf("result without apply fields gained them: %s", body)
	}
}

func TestApplyFieldsResultDoesNotLeakIntoFinal(t *testing.T) {
	// 某条请求带有应用字段，不带应用字段的最终结果不得因此补上。
	_, body := reencode(t, `{"results":[{"accepted":true,"reason":"ok","term":1,"committedIndex":1,"appliedIndex":1,"applyError":null}],`+
		`"finalTerm":1,"finalCommittedIndex":1,"finalLog":[{"index":1,"term":1,"command":"set x=1"}]}`)
	if !strings.Contains(body, `"appliedIndex":1`) || !strings.Contains(body, `"applyError":null`) {
		t.Fatalf("per-request apply fields lost: %s", body)
	}
	for _, field := range []string{`"finalAppliedIndex"`, `"finalKV"`, `"finalApplyError"`} {
		if strings.Contains(body, field) {
			t.Fatalf("final output gained %s from a request result: %s", field, body)
		}
	}
}

func TestApplyFieldsMixedResultsKeepDistinction(t *testing.T) {
	// 同一份结果中，一条答复带应用字段、另一条不带，且最终结果带应用字段：
	// 读取后再输出仍保留各自区别，其余字段原样保留。
	out, body := reencode(t, `{"results":[`+
		`{"accepted":true,"reason":"ok","term":1,"committedIndex":1,"appliedIndex":1,"applyError":null},`+
		`{"accepted":false,"reason":"stale term: leader term is lower than current term","term":2,"committedIndex":1}`+
		`],"finalTerm":2,"finalCommittedIndex":1,"finalLog":[{"index":1,"term":1,"command":"set x=1"}],`+
		`"finalAppliedIndex":1,"finalKV":{"x":"1"},"finalApplyError":null}`)
	if !out.Results[0].applyFields {
		t.Fatalf("result 0 apply fields not detected: %+v", out.Results[0])
	}
	if out.Results[1].applyFields {
		t.Fatalf("result 1 should have no apply fields: %+v", out.Results[1])
	}
	if !out.applyFields {
		t.Fatalf("final apply fields not detected: %+v", out)
	}
	// 接受状态、拒绝原因、任期、提交位置与日志内容原样保留。
	if !out.Results[0].Accepted || out.Results[0].Reason != ReasonOK ||
		out.Results[0].Term != 1 || out.Results[0].CommittedIndex != 1 {
		t.Fatalf("result 0 changed: %+v", out.Results[0])
	}
	if out.Results[1].Accepted || out.Results[1].Reason != ReasonStaleTerm ||
		out.Results[1].Term != 2 || out.Results[1].CommittedIndex != 1 {
		t.Fatalf("result 1 changed: %+v", out.Results[1])
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 ||
		len(out.FinalLog) != 1 || out.FinalLog[0] != entry(1, 1, "set x=1") {
		t.Fatalf("final state changed: %+v", out)
	}
	// 输出层面：带应用字段的答复带齐该组，不带的答复保持原形状。
	if !strings.Contains(body, `"appliedIndex":1,"applyError":null`) {
		t.Fatalf("result 0 apply fields lost: %s", body)
	}
	if !strings.Contains(body, `"reason":"stale term: leader term is lower than current term","term":2,"committedIndex":1}`) {
		t.Fatalf("result 1 should stay free of apply fields: %s", body)
	}
	if !strings.Contains(body, `"finalAppliedIndex":1`) || !strings.Contains(body, `"finalKV":{"x":"1"}`) {
		t.Fatalf("final apply fields lost: %s", body)
	}
}

func TestApplyFieldsUnmarshalErrorKeepsReusedObject(t *testing.T) {
	// 对象原先已有有效的启用应用的结果；后一次读入失败时原有结果完整保留，
	// 随后输出不混入这次读入的部分内容。
	enabled := runKV(t, InitialState{CurrentTerm: 1, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set x=1"),
	}}, AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1})
	enabledJSON, err := json.Marshal(enabled)
	if err != nil {
		t.Fatal(err)
	}
	var out ReplicateOutput
	if err := json.Unmarshal(enabledJSON, &out); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	badPayloads := map[string]string{
		// 应用索引写成字符串。
		"final applied index as string": `{"results":[],"finalTerm":0,"finalCommittedIndex":0,"finalLog":[],"finalAppliedIndex":"0"}`,
		// 键值表写成数组。
		"final kv as array": `{"results":[],"finalTerm":0,"finalCommittedIndex":0,"finalLog":[],"finalKV":[]}`,
		// 错误藏在某条请求答复内。
		"bad field inside a result": `{"results":[{"accepted":true,"reason":"ok","term":1,"committedIndex":1,"appliedIndex":"1"}],"finalTerm":1,"finalCommittedIndex":1,"finalLog":[]}`,
	}
	for name, data := range badPayloads {
		if err := json.Unmarshal([]byte(data), &out); err == nil {
			t.Fatalf("%s: expected decode error for %s", name, data)
		}
		after, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Fatalf("%s: failed read polluted the reused object:\nbefore %s\nafter  %s", name, before, after)
		}
	}
}

func TestApplyFieldsAppendResultUnmarshalErrorKeepsReusedObject(t *testing.T) {
	// 单条请求答复的复用对象同样：读入失败不留下部分应用状态。
	enabled := runKV(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0})
	enabledJSON, err := json.Marshal(enabled.Results[0])
	if err != nil {
		t.Fatal(err)
	}
	var result AppendResult
	if err := json.Unmarshal(enabledJSON, &result); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"accepted":true,"reason":"ok","term":1,"committedIndex":0,"appliedIndex":"0"}`), &result); err == nil {
		t.Fatalf("expected decode error for appliedIndex as string")
	}
	after, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("failed read polluted the reused result:\nbefore %s\nafter  %s", before, after)
	}
}
