package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// 重复键回归：encoding/json 解进 map 时重复键只保留最后一次出现，基于 map 的
// 检查会漏掉写在数字前面的 null，也会让后出现的 log/requests/entries 数组
// 盖掉前一份数组。下列用例锁定“重复字段的每一次出现都要检查”，无论 null 在前
// 还是在后、数组重复多少份、拼写是否只改变大小写。

// 主场景：{"currentTerm":null,"currentTerm":1} 不能按任期 1 正常处理，写在
// 数字前面的 null 同样在读取输入阶段拒绝整份输入。
func TestCLIDuplicateFieldNullBeforeNumberRejected(t *testing.T) {
	input := `{"currentTerm":null,"currentTerm":1,"requests":[]}`
	runReplicateExpectInputError(t, input, "currentTerm")
}

// null 写在数字后面时原本就能检出，重复键修复不能改变这一侧。
func TestCLIDuplicateFieldNullAfterNumberRejected(t *testing.T) {
	input := `{"currentTerm":1,"currentTerm":null,"requests":[]}`
	runReplicateExpectInputError(t, input, "currentTerm")
}

// 初始状态的另一个数值字段 committedIndex 同样如此，且 null 在前。
func TestCLIDuplicateCommittedIndexNullFirstRejected(t *testing.T) {
	input := `{"currentTerm":1,"committedIndex":null,"committedIndex":0}`
	runReplicateExpectInputError(t, input, "committedIndex")
}

// 两次出现拼写只改变大小写：{"CurrentTerm":null,"currentTerm":1} 必须命中，
// 错误位置仍使用标准字段名。
func TestCLIDuplicateFieldCaseVariantNullRejected(t *testing.T) {
	input := `{"CurrentTerm":null,"currentTerm":1}`
	message := runReplicateExpectInputError(t, input, "currentTerm")
	if strings.Contains(message, "CurrentTerm") {
		t.Fatalf("location must use the canonical field name, got: %q", message)
	}
}

// 请求内数值字段重复出现、null 在前：不能落成一次普通请求拒绝。
func TestCLIDuplicateRequestFieldNullFirstRejected(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":null,"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}
	]}`
	runReplicateExpectInputError(t, input, "requests[0].term")
}

// 请求内数值字段重复出现、null 在后，且第二次拼写只改变大小写。
func TestCLIDuplicateRequestFieldCaseVariantNullAfterRejected(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"TERM":null,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}
	]}`
	runReplicateExpectInputError(t, input, "requests[0].term")
}

// 条目数值字段重复出现：null 在数字之前与之后各一例。
func TestCLIDuplicateEntryFieldNullEitherOrderRejected(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		path  string
	}{
		{
			name:  "index null before number",
			entry: `{"index":null,"index":1,"term":1,"command":"a"}`,
			path:  "requests[0].entries[0].index",
		},
		{
			name:  "term null after number, case variant",
			entry: `{"index":1,"term":1,"Term":null,"command":"a"}`,
			path:  "requests[0].entries[0].term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"currentTerm":1,"requests":[
			  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
			   "entries":[` + tc.entry + `]}
			]}`
			runReplicateExpectInputError(t, input, tc.path)
		})
	}
}

// requests 数组自身重复出现：第一份数组里的 null 不能被后一份干净数组盖掉。
func TestCLIDuplicateRequestsArrayFirstHasNullRejected(t *testing.T) {
	input := `{"currentTerm":1,
	  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":null,"entries":[]}],
	  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]
	}`
	runReplicateExpectInputError(t, input, "requests[0].leaderCommit")
}

// 第一份 requests 干净、第二份里带 null：下标仍按所在数组从 0 计数。
func TestCLIDuplicateRequestsArraySecondHasNullRejected(t *testing.T) {
	input := `{"currentTerm":1,
	  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
	  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]},
	              {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":null,"entries":[]}]
	}`
	runReplicateExpectInputError(t, input, "requests[1].leaderCommit")
}

// log 数组自身重复出现，第一份初始日志条目的 null 不能被后一份盖掉。
func TestCLIDuplicateLogArrayFirstHasNullRejected(t *testing.T) {
	input := `{"currentTerm":1,
	  "log":[{"index":null,"term":1,"command":"a"}],
	  "log":[]
	}`
	runReplicateExpectInputError(t, input, "log[0].index")
}

// entries 数组在同一请求里重复出现：第一份条目里的 null 不能被空的第二份盖掉。
func TestCLIDuplicateEntriesArrayFirstHasNullRejected(t *testing.T) {
	input := `{"currentTerm":1,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
	   "entries":[{"index":1,"term":null,"command":"a"}],
	   "entries":[]}
	]}`
	runReplicateExpectInputError(t, input, "requests[0].entries[0].term")
}

// 数组字段名只改变大小写时同样要检查每一份数组。
func TestCLIDuplicateArrayFieldCaseVariantNullRejected(t *testing.T) {
	cases := []struct {
		name  string
		input string
		path  string
	}{
		{
			name: "duplicate LOG case variant",
			input: `{"currentTerm":1,
			  "LOG":[{"index":1,"term":null,"command":"a"}],
			  "log":[]}`,
			path: "log[0].term",
		},
		{
			name: "duplicate REQUESTS case variant",
			input: `{"currentTerm":1,
			  "REQUESTS":[{"term":null,"entries":[]}],
			  "requests":[]}`,
			path: "requests[0].term",
		},
		{
			name: "duplicate ENTRIES case variant",
			input: `{"currentTerm":1,"requests":[
			  {"term":1,"ENTRIES":[{"index":null,"term":1}],"entries":[]}]}`,
			path: "requests[0].entries[0].index",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReplicateExpectInputError(t, tc.input, tc.path)
		})
	}
}

// 即使带 null 的条目尚未提交、applyKV 也未开启，重复键检查仍在读取阶段失败。
func TestCLIDuplicateNullRejectedRegardlessOfCommitAndApplyKV(t *testing.T) {
	input := `{"currentTerm":1,"applyKV":false,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,
	   "entries":[{"index":1,"term":1,"command":"set a=1"}]},
	  {"term":1,"prevLogIndex":1,"prevLogTerm":1,"leaderCommit":1,
	   "entries":[{"index":2,"term":null,"term":2,"command":"b"}]}
	]}`
	runReplicateExpectInputError(t, input, "requests[1].entries[0].term")
}

// 合法输入的重复键不额外禁止：所有出现都不含数值 null 时，仍按既有 JSON
// 读取规则（重复键后者生效）得到初始状态与请求。
func TestCLIDuplicateKeysWithoutNullKeepLastWins(t *testing.T) {
	t.Run("duplicate currentTerm last wins", func(t *testing.T) {
		out, _ := runReplicateRaw(t, `{"currentTerm":1,"currentTerm":3,"requests":[]}`)
		if out.FinalTerm != 3 {
			t.Fatalf("finalTerm = %d, want 3 (last duplicate wins)", out.FinalTerm)
		}
	})

	t.Run("duplicate log arrays last wins", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "log":[{"index":1,"term":1,"command":"a"}],
		  "log":[{"index":1,"term":1,"command":"b"}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "b" {
			t.Fatalf("final log = %+v, want only the second duplicate array's entry b", out.FinalLog)
		}
	})

	t.Run("duplicate requests arrays last wins", func(t *testing.T) {
		input := `{"currentTerm":1,
		  "requests":[{"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}],
		  "requests":[{"term":2,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.Results) != 1 || out.Results[0].Term != 2 || out.FinalTerm != 2 {
			t.Fatalf("results = %+v finalTerm = %d, want only the second array's term-2 request",
				out.Results, out.FinalTerm)
		}
	})

	t.Run("duplicate entries arrays last wins", func(t *testing.T) {
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
		   "entries":[{"index":1,"term":1,"command":"a"}],
		   "entries":[{"index":1,"term":1,"command":"b"}]}
		]}`
		out, _ := runReplicateRaw(t, input)
		if len(out.FinalLog) != 1 || out.FinalLog[0].Command != "b" {
			t.Fatalf("final log = %+v, want entry b from the second entries array", out.FinalLog)
		}
	})

	t.Run("duplicated legal zero keeps ordinary meaning", func(t *testing.T) {
		// prevLogIndex/prevLogTerm/leaderCommit 重复写成 0：0 仍是日志起点与
		// “尚未提交”的普通含义，请求被正常接受。
		input := `{"currentTerm":1,"requests":[
		  {"term":1,"prevLogIndex":0,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":0,"entries":[]}]}`
		out, _ := runReplicateRaw(t, input)
		if !out.Results[0].Accepted {
			t.Fatalf("duplicated legal zero must keep its ordinary meaning: %+v", out.Results[0])
		}
	})
}

// 带重复键的合法输入在开启 applyKV 时依旧完整跑通：输出可解码，复制与键值
// 应用的既有行为不因扫描检查改变。
func TestCLIDuplicateKeysValidWithApplyKV(t *testing.T) {
	input := `{"currentTerm":1,"currentTerm":1,"applyKV":true,"requests":[
	  {"term":1,"prevLogIndex":0,"prevLogTerm":0,"leaderCommit":1,
	   "entries":[{"index":1,"term":1,"command":"set k=v"}]}
	]}`
	var stdout, stderr bytes.Buffer
	if code := runReplicateIO(strings.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid output JSON: %v\n%s", err, stdout.String())
	}
	kv, ok := out["finalKV"].(map[string]interface{})
	if !ok || kv["k"] != "v" {
		t.Fatalf("finalKV = %v, want k=v applied as before", out["finalKV"])
	}
}
