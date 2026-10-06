package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// replicateInput 是 replicate 子命令从标准输入读取的 JSON。
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
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Fprintf(stderr, "replicate: parse input JSON: %v\n", err)
		return 1
	}
	// 已识别的数值字段被显式写成 null 时，类型化解码会静默当成零值继续
	// 处理（例如 committedIndex 为 null 被当成“尚未提交”），必须在读取
	// 输入阶段把整份输入作为字段类型错误拒绝。
	if path := nullNumericFieldPath(raw); path != "" {
		fmt.Fprintf(stderr, "replicate: invalid field type: %s must be a number, got null\n", path)
		return 1
	}
	var input replicateInput
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(stderr, "replicate: parse input JSON: %v\n", err)
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

// nullNumericFieldPath 在已解析的输入 JSON 中查找第一个被显式写成 null 的
// 已识别数值字段，返回它的完整位置；没有时返回空串。检查范围是初始状态
// （currentTerm、committedIndex、log[i].index、log[i].term）与每条复制请求
// （term、prevLogIndex、prevLogTerm、leaderCommit 及 entries[j].index、
// entries[j].term）；请求与条目下标从 0 开始，例如第二条请求的提交位置记为
// requests[1].leaderCommit。字段名识别与 encoding/json 一致，只改变字母
// 大小写的写法同样命中。数组字段本身与未知键里的 null 沿用既有处理，不在
// 检查范围内。
func nullNumericFieldPath(raw interface{}) string {
	root, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, name := range []string{"currentTerm", "committedIndex"} {
		if hasExplicitNull(root, name) {
			return name
		}
	}
	if entries, ok := lookupArray(root, "log"); ok {
		for i, entry := range entries {
			if path := nullEntryFieldPath(entry, fmt.Sprintf("log[%d]", i)); path != "" {
				return path
			}
		}
	}
	if requests, ok := lookupArray(root, "requests"); ok {
		for i, request := range requests {
			obj, ok := request.(map[string]interface{})
			if !ok {
				continue
			}
			prefix := fmt.Sprintf("requests[%d]", i)
			for _, name := range []string{"term", "prevLogIndex", "prevLogTerm", "leaderCommit"} {
				if hasExplicitNull(obj, name) {
					return prefix + "." + name
				}
			}
			if entries, ok := lookupArray(obj, "entries"); ok {
				for j, entry := range entries {
					if path := nullEntryFieldPath(entry, fmt.Sprintf("%s.entries[%d]", prefix, j)); path != "" {
						return path
					}
				}
			}
		}
	}
	return ""
}

// nullEntryFieldPath 检查一条日志条目（初始日志或请求条目）的 index 与 term
// 是否被显式写成 null，返回带 prefix 的完整位置；条目不是对象或没有 null
// 数值字段时返回空串。
func nullEntryFieldPath(entry interface{}, prefix string) string {
	obj, ok := entry.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, name := range []string{"index", "term"} {
		if hasExplicitNull(obj, name) {
			return prefix + "." + name
		}
	}
	return ""
}

// hasExplicitNull 报告对象中按 encoding/json 的字段名识别规则（大小写不敏感）
// 命中 name 的键是否被显式写成 null。
func hasExplicitNull(obj map[string]interface{}, name string) bool {
	for key, value := range obj {
		if strings.EqualFold(key, name) && value == nil {
			return true
		}
	}
	return false
}

// lookupArray 按同样的识别规则取出对象的数组字段；字段不存在或不是数组时
// ok 为 false（数组字段为 null 等情况沿用既有处理，不属于数值校验）。
func lookupArray(obj map[string]interface{}, name string) ([]interface{}, bool) {
	if value, ok := obj[name]; ok {
		arr, isArr := value.([]interface{})
		return arr, isArr
	}
	for key, value := range obj {
		if strings.EqualFold(key, name) {
			arr, isArr := value.([]interface{})
			return arr, isArr
		}
	}
	return nil, false
}
