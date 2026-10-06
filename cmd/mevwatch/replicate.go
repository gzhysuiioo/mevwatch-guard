package main

import (
	"bytes"
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
	// 已识别的数值字段被显式写成 null 时，类型化解码会静默当成零值继续
	// 处理（例如 committedIndex 为 null 被当成“尚未提交”），必须在读取
	// 输入阶段把整份输入作为字段类型错误拒绝。检查在 Token 流上进行而不
	// 是在 map 上：同名字段在对象中重复出现时，后值会覆盖前值（如
	// {"currentTerm":null,"currentTerm":1}），log/requests/entries 等数组
	// 字段重复时也是如此；流式扫描能看到每一次出现，任何一份里的数值 null
	// 都不会被后面的值或数组盖掉。
	path, scanErr := nullNumericFieldPath(data)
	if scanErr != nil {
		fmt.Fprintf(stderr, "replicate: parse input JSON: %v\n", scanErr)
		return 1
	}
	if path != "" {
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

// nullNumericFieldPath 在输入 JSON 中查找第一个被显式写成 null 的已识别
// 数值字段，返回它的完整位置；没有时返回空串。检查范围是初始状态
// （currentTerm、committedIndex、log[i].index、log[i].term）与每条复制请求
// （term、prevLogIndex、prevLogTerm、leaderCommit 及 entries[j].index、
// entries[j].term）；请求与条目下标从 0 开始，例如第二条请求的提交位置记为
// requests[1].leaderCommit。
//
// 扫描基于 json.Decoder 的 Token 流而不是先解成 map：同名字段在 JSON 对象中
// 重复出现时，map 只保留最后一次出现，{"currentTerm":null,"currentTerm":1}
// 里先前的 null 会被盖掉，log/requests/entries 数组字段重复时也是如此。
// Token 流保留每一次出现，因此无论 null 在数字之前还是之后、字段名只改变
// 大小写、或重复数组中的任一份含有数值 null，都能被发现。字段名识别与
// encoding/json 一致（大小写不敏感）。数组字段本身为 null 与未知键里的
// null 沿用既有处理，不在检查范围内；未知对象即使含 index/term 同名键也不
// 属于日志条目。
func nullNumericFieldPath(data []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	rootTok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if rootTok != json.Delim('{') {
		// 顶层不是对象：交给随后的类型化解码按原规则报错。
		return "", nil
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", err
		}
		key := keyTok.(string)
		if path, matched, err := scanRootField(dec, key); err != nil {
			return "", err
		} else if matched {
			return path, nil
		}
	}
	if _, err := dec.Token(); err != nil { // 根对象的 '}'
		return "", err
	}
	return "", nil
}

// scanRootField 消费根对象中字段 key 的整个值（调用时值尚未读取）。
// matched 为 true 时 path 是发现的数值 null 位置。
func scanRootField(dec *json.Decoder, key string) (path string, matched bool, err error) {
	switch {
	case strings.EqualFold(key, "currentTerm") || strings.EqualFold(key, "committedIndex"):
		tok, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		if tok == nil {
			return canonicalRootName(key), true, nil
		}
		return "", false, nil
	case strings.EqualFold(key, "log"):
		return scanEntryArray(dec, "log")
	case strings.EqualFold(key, "requests"):
		return scanRequests(dec)
	default:
		// 未知字段（含 applyKV）：原样跳过整个值，其中的同名键不属于
		// 已识别字段。
		if err := skipValue(dec); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
}

// canonicalRootName 把只改变大小写的根数值字段名归一成标准字段名。
func canonicalRootName(key string) string {
	if strings.EqualFold(key, "currentTerm") {
		return "currentTerm"
	}
	return "committedIndex"
}

// scanRequests 消费 requests 数组（调用时值尚未读取），逐元素检查请求对象；
// 字段自身为 null 或不是数组时沿用既有处理，不做数值校验。
func scanRequests(dec *json.Decoder) (string, bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", false, err
	}
	if tok != json.Delim('[') {
		// 字段为 null 或标量：交给类型化解码沿用既有规则处理。
		return "", false, nil
	}
	for i := 0; dec.More(); i++ {
		startTok, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		if startTok != json.Delim('{') {
			// 数组元素不是对象：跳过，沿用既有处理。
			if err := skipToken(startTok, dec); err != nil {
				return "", false, err
			}
			continue
		}
		prefix := fmt.Sprintf("requests[%d]", i)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return "", false, err
			}
			key := keyTok.(string)
			if path, matched, err := scanRequestField(dec, key, prefix); err != nil {
				return "", false, err
			} else if matched {
				return path, true, nil
			}
		}
		if _, err := dec.Token(); err != nil { // 请求对象的 '}'
			return "", false, err
		}
	}
	if _, err := dec.Token(); err != nil { // requests 数组的 ']'
		return "", false, err
	}
	return "", false, nil
}

// scanRequestField 消费一条请求对象中字段 key 的整个值（调用时值尚未读取）。
func scanRequestField(dec *json.Decoder, key, prefix string) (path string, matched bool, err error) {
	switch {
	case strings.EqualFold(key, "term") ||
		strings.EqualFold(key, "prevLogIndex") ||
		strings.EqualFold(key, "prevLogTerm") ||
		strings.EqualFold(key, "leaderCommit"):
		tok, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		if tok == nil {
			return prefix + "." + canonicalRequestFieldName(key), true, nil
		}
		return "", false, nil
	case strings.EqualFold(key, "entries"):
		return scanEntryArray(dec, prefix+".entries")
	default:
		// 未知键：跳过整个值，其中即使含有 index/term 同名键也不属于
		// 日志数值字段。
		if err := skipValue(dec); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
}

// canonicalRequestFieldName 把只改变大小写的请求数值字段名归一成标准字段名。
func canonicalRequestFieldName(key string) string {
	for _, name := range []string{"term", "prevLogIndex", "prevLogTerm", "leaderCommit"} {
		if strings.EqualFold(key, name) {
			return name
		}
	}
	return key
}

// scanEntryArray 消费一个日志条目数组（初始 log 或请求的 entries），prefix
// 是不含下标的数组位置前缀（"log" 或 "requests[i].entries"），遍历时追加
// 下标。调用时值尚未读取。数组字段本身为 null 或不是数组时沿用既有处理
// （entries 为 null 在类型化解码后等同空切片），不属于数值校验。
func scanEntryArray(dec *json.Decoder, prefix string) (string, bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", false, err
	}
	if tok != json.Delim('[') {
		return "", false, nil
	}
	for i := 0; dec.More(); i++ {
		startTok, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		if startTok != json.Delim('{') {
			if err := skipToken(startTok, dec); err != nil {
				return "", false, err
			}
			continue
		}
		entryPrefix := fmt.Sprintf("%s[%d]", prefix, i)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return "", false, err
			}
			key := keyTok.(string)
			if strings.EqualFold(key, "index") || strings.EqualFold(key, "term") {
				valueTok, err := dec.Token()
				if err != nil {
					return "", false, err
				}
				if valueTok == nil {
					name := "index"
					if strings.EqualFold(key, "term") {
						name = "term"
					}
					return entryPrefix + "." + name, true, nil
				}
			} else {
				// command 与未知键：跳过整个值（未知对象里的同名
				// index/term 键不属于日志数值字段）。
				if err := skipValue(dec); err != nil {
					return "", false, err
				}
			}
		}
		if _, err := dec.Token(); err != nil { // 条目对象的 '}'
			return "", false, err
		}
	}
	if _, err := dec.Token(); err != nil { // 数组的 ']'
		return "", false, err
	}
	return "", false, nil
}

// skipValue 跳过下一个完整的 JSON 值（调用时值尚未读取）。
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return skipToken(tok, dec)
}

// skipToken 跳过以 tok 为起始 Token 的完整 JSON 值；标量与 null 已经被
// Token() 整体读出，只需平衡成对的花括号与方括号。
func skipToken(tok json.Token, dec *json.Decoder) error {
	switch tok {
	case json.Delim('{'), json.Delim('['):
		open := tok.(json.Delim)
		closeDelim := json.Delim('}')
		if open == '[' {
			closeDelim = ']'
		}
		depth := 1
		for depth > 0 {
			next, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := next.(json.Delim); ok {
				switch d {
				case open:
					depth++
				case closeDelim:
					depth--
				}
			}
		}
	}
	return nil
}
