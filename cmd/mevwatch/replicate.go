package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// replicateInput 是 replicate 子命令从标准输入读取的 JSON。数值字段必须经过
// decodeReplicateInput 解码：直接用 encoding/json 解码到 int 会把显式 null
// 静默当成零值，使“明确写成 null”与“省略字段”无法区分。
type replicateInput struct {
	CurrentTerm    int                      `json:"currentTerm"`
	CommittedIndex int                      `json:"committedIndex"`
	Log            []mevwatch.LogEntry      `json:"log"`
	ApplyKV        bool                     `json:"applyKV"`
	Requests       []mevwatch.AppendRequest `json:"requests"`
}

// runReplicate 从标准输入读取一份 JSON（初始状态 + 顺序到达的复制请求），
// 把逐次接收结果与最终日志作为一份 JSON 写到标准输出。
// 初始状态非法或 JSON 无法解析时，以非零退出码和明确错误结束。
func runReplicate() int {
	return runReplicateIO(os.Stdin, os.Stdout, os.Stderr)
}

func runReplicateIO(stdin io.Reader, stdout, stderr io.Writer) int {
	data, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "replicate: read stdin: %v\n", err)
		return 1
	}
	input, err := decodeReplicateInput(data)
	if err != nil {
		fmt.Fprintf(stderr, "replicate: %v\n", err)
		return 1
	}
	output, err := mevwatch.ReplicateWithOptions(mevwatch.InitialState{
		CurrentTerm:    input.CurrentTerm,
		CommittedIndex: input.CommittedIndex,
		Log:            input.Log,
	}, input.Requests, mevwatch.ReplicateOptions{ApplyKV: input.ApplyKV})
	if err != nil {
		fmt.Fprintf(stderr, "replicate: %v\n", err)
		return 1
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "replicate: encode output JSON: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}

// decodeReplicateInput 解析 replicate 的输入 JSON，语义与直接
// json.Unmarshal 到 replicateInput 保持一致（省略字段取默认零值、{} 是合法
// 空初始状态、无关键与数组型字段上的 null 沿用既有处理），但有一个额外
// 保证：任何已识别的数值字段被显式写成 null 时，整份输入按字段类型错误
// 拒绝，错误指出字段的完整位置，例如 requests[1].leaderCommit。
//
// 这一检查必须在读取输入阶段完成，不能依赖后续逻辑校验：encoding/json
// 会把 null 静默解码为 int 零值，于是初始 committedIndex 的 null 会被当成
// “尚无提交”，使初始日志失去提交保护；请求数值字段上的 null 也会以真实
// 任期或索引参与复制。已识别键的判定与 encoding/json 的字段匹配规则一致
// （按 Unicode 大小写折叠），只改字母大小写的键名同样不能绕过检查。
func decodeReplicateInput(data []byte) (replicateInput, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return replicateInput{}, fmt.Errorf("parse input JSON: %v", err)
	}

	var input replicateInput
	numericFields := map[string]struct{}{
		"currentTerm": {}, "committedIndex": {},
	}
	if err := decodeNumericObject(root, numericFields, "", func(key string, value json.RawMessage) error {
		switch key {
		case "currentTerm":
			return json.Unmarshal(value, &input.CurrentTerm)
		case "committedIndex":
			return json.Unmarshal(value, &input.CommittedIndex)
		}
		return nil
	}); err != nil {
		return replicateInput{}, err
	}

	// applyKV 是布尔字段，不属于数值校验范围；按常规方式解码。
	if raw, ok := lookupKey(root, "applyKV"); ok {
		if err := json.Unmarshal(raw, &input.ApplyKV); err != nil {
			return replicateInput{}, fmt.Errorf("parse input JSON: %v", err)
		}
	}

	// log 为数组型字段：log: null 维持既有语义（解码成 nil 切片），
	// 只校验其中已识别条目的数值字段。
	if raw, ok := lookupKey(root, "log"); ok && !isNull(raw) {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return replicateInput{}, fmt.Errorf("parse input JSON: %v", err)
		}
		input.Log = make([]mevwatch.LogEntry, 0, len(entries))
		for j, entry := range entries {
			decoded, err := decodeLogEntry(entry, fmt.Sprintf("log[%d]", j))
			if err != nil {
				return replicateInput{}, err
			}
			input.Log = append(input.Log, decoded)
		}
	}

	// requests 同为数组型字段：requests: null 维持既有语义，只校验每条
	// 请求及其日志条目已识别的数值字段。请求与条目位置均从 0 开始计数。
	if raw, ok := lookupKey(root, "requests"); ok && !isNull(raw) {
		var requests []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &requests); err != nil {
			return replicateInput{}, fmt.Errorf("parse input JSON: %v", err)
		}
		input.Requests = make([]mevwatch.AppendRequest, 0, len(requests))
		for i, request := range requests {
			decoded, err := decodeAppendRequest(request, i)
			if err != nil {
				return replicateInput{}, err
			}
			input.Requests = append(input.Requests, decoded)
		}
	}
	return input, nil
}

// decodeAppendRequest 解析第 i 条复制请求（i 从 0 开始）。
func decodeAppendRequest(request map[string]json.RawMessage, i int) (mevwatch.AppendRequest, error) {
	var decoded mevwatch.AppendRequest
	numericFields := map[string]struct{}{
		"term": {}, "prevLogIndex": {}, "prevLogTerm": {}, "leaderCommit": {},
	}
	pathPrefix := fmt.Sprintf("requests[%d].", i)
	if err := decodeNumericObject(request, numericFields, pathPrefix, func(key string, value json.RawMessage) error {
		switch key {
		case "term":
			return json.Unmarshal(value, &decoded.Term)
		case "prevLogIndex":
			return json.Unmarshal(value, &decoded.PrevLogIndex)
		case "prevLogTerm":
			return json.Unmarshal(value, &decoded.PrevLogTerm)
		case "leaderCommit":
			return json.Unmarshal(value, &decoded.LeaderCommit)
		}
		return nil
	}); err != nil {
		return mevwatch.AppendRequest{}, err
	}

	if raw, ok := lookupKey(request, "entries"); ok && !isNull(raw) {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return mevwatch.AppendRequest{}, fmt.Errorf("parse input JSON: %v", err)
		}
		decoded.Entries = make([]mevwatch.LogEntry, 0, len(entries))
		for j, entry := range entries {
			decodedEntry, err := decodeLogEntry(entry, fmt.Sprintf("requests[%d].entries[%d]", i, j))
			if err != nil {
				return mevwatch.AppendRequest{}, err
			}
			decoded.Entries = append(decoded.Entries, decodedEntry)
		}
	}
	return decoded, nil
}

// decodeLogEntry 解析位于 path（如 "log[0]" 或 "requests[1].entries[0]"）的
// 一条日志条目，校验其 index/term 不被显式写成 null，并常规解码全部字段。
func decodeLogEntry(entry map[string]json.RawMessage, path string) (mevwatch.LogEntry, error) {
	var decoded mevwatch.LogEntry
	numericFields := map[string]struct{}{
		"index": {}, "term": {},
	}
	if err := decodeNumericObject(entry, numericFields, path+".", func(key string, value json.RawMessage) error {
		switch key {
		case "index":
			return json.Unmarshal(value, &decoded.Index)
		case "term":
			return json.Unmarshal(value, &decoded.Term)
		}
		return nil
	}); err != nil {
		return mevwatch.LogEntry{}, err
	}
	if raw, ok := lookupKey(entry, "command"); ok {
		if err := json.Unmarshal(raw, &decoded.Command); err != nil {
			return mevwatch.LogEntry{}, fmt.Errorf("parse input JSON: %v", err)
		}
	}
	return decoded, nil
}

// decodeNumericObject 遍历一个已解析的 JSON 对象，对 object 中每一个与
// numericFields 中的键按 encoding/json 字段匹配规则（Unicode 大小写折叠）
// 同名的键检查其值：显式 null 报告为带完整位置的字段类型错误；其余值交给
// assign 按规范字段名常规解码。无关键不做检查，交由既有处理。
//
// pathPrefix 是该层字段的位置前缀：根对象为空串（错误形如 committedIndex），
// 其余以点号结尾（如 "requests[0]."、"log[2]."）。
func decodeNumericObject(object map[string]json.RawMessage, numericFields map[string]struct{}, pathPrefix string, assign func(canonicalKey string, value json.RawMessage) error) error {
	for rawKey, value := range object {
		canonical, matched := matchNumericKey(rawKey, numericFields)
		if !matched {
			continue
		}
		if isNull(value) {
			return fmt.Errorf("invalid input: field %s%s must be a number, got null", pathPrefix, canonical)
		}
		if err := assign(canonical, value); err != nil {
			// 数值字段写成字符串、布尔或对象等错误类型沿用 JSON 解码错误。
			return fmt.Errorf("parse input JSON: %v", err)
		}
	}
	return nil
}

// matchNumericKey 按 encoding/json 的字段名匹配规则报告 objectKey 是否命中
// 某个已识别数值字段：比较按 Unicode 大小写折叠（等价于 bytes.EqualFold），
// 只改字母大小写的键名返回它命中的规范字段名。
func matchNumericKey(objectKey string, numericFields map[string]struct{}) (string, bool) {
	for canonical := range numericFields {
		if bytes.EqualFold([]byte(objectKey), []byte(canonical)) {
			return canonical, true
		}
	}
	return "", false
}

// lookupKey 按字段匹配规则（大小写折叠）取出对象中某个已识别键的原始值。
func lookupKey(object map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	for objectKey, value := range object {
		if bytes.EqualFold([]byte(objectKey), []byte(key)) {
			return value, true
		}
	}
	return nil, false
}

// isNull 报告原始 JSON 值是否为显式 null（允许空白）。
func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
