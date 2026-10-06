package main

import (
	"bytes"
	"strings"
	"testing"
)

// 本应为数组的 log、requests、entries 被写成对象时，扫描器以前只消费起始
// '{' 就返回：对象内部的键被外层循环当成外层字段（产生错误的数值 null 定位），
// 对象之后真正的字段又永远扫不到（真实数值 null 被类型错误遮住）。下列用例
// 锁定“对象整体只是一个值”的语义：内部字段（含嵌套内容）不参与识别，也不
// 影响后续真实字段的检查顺序。

// runReplicateExpectTypeError 断言输入在读取阶段被拒绝（退出码 1、标准输出为
// 空），且标准错误同时包含所有 want 片段、不包含任一 forbid 片段。用于区分
// “原有的 JSON 类型错误”与“数值字段为 null”两种不同的读取阶段错误。
func runReplicateExpectTypeError(t *testing.T, input string, want, forbid []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReplicateIO(strings.NewReader(input), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("no result JSON may be produced on an input error, got: %s", stdout.String())
	}
	message := stderr.String()
	if !strings.HasPrefix(message, "replicate:") {
		t.Fatalf("error message missing replicate: prefix: %q", message)
	}
	for _, fragment := range want {
		if !strings.Contains(message, fragment) {
			t.Fatalf("error message must contain %q, got: %q", fragment, message)
		}
	}
	for _, fragment := range forbid {
		if strings.Contains(message, fragment) {
			t.Fatalf("error message must not contain %q, got: %q", fragment, message)
		}
	}
	return message
}

// 任务主场景：{"requests":{"currentTerm":null}} 必须作为 requests 的类型
// 错误拒绝，沿用原有 JSON 类型错误格式指出 requests，绝不能声称顶层
// currentTerm 被写成 null。
func TestCLIRequestsObjectReportsRequestsTypeError(t *testing.T) {
	input := `{"requests":{"currentTerm":null}}`
	runReplicateExpectTypeError(t, input,
		[]string{
			"parse input JSON",
			"cannot unmarshal object into Go struct field",
			"replicateInput.requests",
			"[]mevwatch.AppendRequest",
		},
		[]string{"invalid field type", "currentTerm"},
	)
}

// entries 被写成对象时，其中的 term、index 等同名字段既不能冒充请求自身的
// 字段，也不能冒充合法日志条目的字段。
func TestCLIEntriesObjectReportsEntriesTypeError(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "inner term looks like request field",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"entries":{"term":null},"leaderCommit":0}
			]}`,
		},
		{
			name: "inner index/term look like entry fields",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"entries":{"index":null,"term":null,"command":"x"}}
			]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectTypeError(t, tc.input,
				[]string{
					"cannot unmarshal object into Go struct field",
					"requests.entries",
					"[]mevwatch.LogEntry",
				},
				[]string{"invalid field type"},
			)
		})
	}
}

// 初始 log 被写成对象时，内部的 index/term 同样不算已识别字段。
func TestCLILogObjectReportsLogTypeError(t *testing.T) {
	input := `{"currentTerm":1,"log":{"index":null,"term":null}}`
	runReplicateExpectTypeError(t, input,
		[]string{
			"cannot unmarshal object into Go struct field",
			"replicateInput.log",
			"[]mevwatch.LogEntry",
		},
		[]string{"invalid field type"},
	)
}

// 空对象没有任何内部字段可误报，仍按原有的类型错误拒绝。
func TestCLIEmptyArrayFieldObjectStillTypeError(t *testing.T) {
	for _, input := range []string{
		`{"requests":{}}`,
		`{"currentTerm":1,"log":{}}`,
		`{"currentTerm":1,"requests":[{"entries":{}}]}`,
	} {
		runReplicateExpectTypeError(t, input,
			[]string{"cannot unmarshal object into Go struct field"},
			[]string{"invalid field type"},
		)
	}
}

// 对象内部的嵌套内容也不算已识别字段：深层数组/对象里的同名 null 不能产生
// 数值 null 错误，整份输入仍只按数组字段的类型错误拒绝。
func TestCLIArrayFieldObjectNestedContentsNotRecognized(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"entries":{"a":[{"index":null}],"nested":{"term":null}},"leaderCommit":0}
	]}`
	runReplicateExpectTypeError(t, input,
		[]string{"cannot unmarshal object into Go struct field", "requests.entries"},
		[]string{"invalid field type"},
	)
}

// 任务主场景：{"log":{},"committedIndex":null} 必须先报告真实结构位置上的
// committedIndex 数值 null，而不是被 log 的类型错误遮住。
func TestCLILogObjectDoesNotMaskLaterRealNull(t *testing.T) {
	input := `{"log":{},"committedIndex":null}`
	runReplicateExpectInputError(t, input, "committedIndex")
}

// 请求里的 entries 写成对象也不能遮住该请求对象中其后真实的 leaderCommit
// 数值 null。
func TestCLIEntriesObjectDoesNotMaskLaterRealNull(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"entries":{},"leaderCommit":null}
	]}`
	runReplicateExpectInputError(t, input, "requests[0].leaderCommit")
}

// log 写成对象后，扫描仍继续到达其后真正的 requests 数组并检出其中的 null。
func TestCLILogObjectDoesNotMaskLaterRequestsNull(t *testing.T) {
	input := `{"currentTerm":1,"log":{},
	  "requests":[{"term":null,"entries":[]}]}`
	runReplicateExpectInputError(t, input, "requests[0].term")
}

// requests 写成对象时，其内部同名字段不参与“按输入顺序的第一个真实 null”
// 排序：对象之后根状态的 currentTerm 为 null 才是要报告的位置。
func TestCLIRequestsObjectInnerFieldNotInNullOrdering(t *testing.T) {
	input := `{"requests":{"leaderCommit":null,"term":null},"currentTerm":null}`
	message := runReplicateExpectInputError(t, input, "currentTerm")
	if strings.Contains(message, "requests") {
		t.Fatalf("inner fields of the requests object must not be reported, got: %q", message)
	}
}

// 同一真实结构层级上多个数值字段都为 null 时，报告按输入顺序出现的第一个；
// 错误对象内部的同名字段不参与次序。
func TestCLIRealNullsReportedInInputOrder(t *testing.T) {
	// log 对象里的“committedIndex/currentTerm”不算；真实字段中先出现
	// committedIndex，必须报告它而不是后面的 currentTerm。
	input := `{"log":{"committedIndex":null,"currentTerm":null},
	  "committedIndex":null,"currentTerm":null}`
	runReplicateExpectInputError(t, input, "committedIndex")
}

// 无论 applyKV 是否开启，错误对象与真实数值 null 的判定都相同：真实 null
// 仍在读取阶段拒绝整份输入，标准输出没有结果 JSON。
func TestCLIWrongArrayObjectJudgmentIndependentOfApplyKV(t *testing.T) {
	t.Run("real null with applyKV enabled", func(t *testing.T) {
		input := `{"log":{},"committedIndex":null,"applyKV":true}`
		runReplicateExpectInputError(t, input, "committedIndex")
	})
	t.Run("object type error with applyKV enabled", func(t *testing.T) {
		input := `{"applyKV":true,"requests":{"currentTerm":null}}`
		runReplicateExpectTypeError(t, input,
			[]string{"cannot unmarshal object into Go struct field", "replicateInput.requests"},
			[]string{"invalid field type"},
		)
	})
}

// 数组字段自身为 null（而非对象）继续沿用既有处理，不会被这次修复波及。
func TestCLINullArrayFieldStillAccepted(t *testing.T) {
	input := `{
	  "currentTerm": 1,
	  "committedIndex": 0,
	  "log": null,
	  "requests": [
	    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 1,
	     "entries": [{"index": 1, "term": 1, "command": "set a=1"}]}
	  ]
	}`
	out, _ := runReplicateRaw(t, input)
	if !out.Results[0].Accepted || out.FinalCommittedIndex != 1 {
		t.Fatalf("null array fields must keep existing semantics: %+v", out)
	}
}
