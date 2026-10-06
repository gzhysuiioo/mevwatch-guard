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
	var syntaxCheck interface{}
	if err := json.Unmarshal(data, &syntaxCheck); err != nil {
		fmt.Fprintf(stderr, "replicate: parse input JSON: %v\n", err)
		return 1
	}
	// 已识别的数值字段被显式写成 null 时，类型化解码会静默当成零值继续
	// 处理（例如 committedIndex 为 null 被当成“尚未提交”），必须在读取
	// 输入阶段把整份输入作为字段类型错误拒绝。检查直接扫描 JSON token
	// 而不是先解进 map：map 解码对重复键只保留最后一次出现，既会漏掉
	// 写在数字前面的 null，也会让后出现的 log/requests/entries 数组盖掉
	// 前一份数组，因此重复键的每一次出现都必须单独检查。
	if path := nullNumericFieldPath(data); path != "" {
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

// fieldSpec 描述一层对象中已识别字段的数值 null 检查规则：scalars 是直接
// 数值字段（被显式写成 null 时报告其完整位置），arrays 是元素应按对象检查
// 的数组字段（对每个对象元素递归应用 elem 规则）。规范里只出现一次的规则
// 由根状态、复制请求与日志条目三层共用各自的 fieldSpec 实例表达，字段定位
// 与无关内容跳过的扫描逻辑因此只有一份。
type fieldSpec struct {
	scalars []string
	arrays  []arraySpec
}

// arraySpec 是一个已识别数组字段：name 为标准字段名，elem 为数组元素（对象）
// 的检查规则。
type arraySpec struct {
	name string
	elem *fieldSpec
}

// 各层对象的检查规则。字段名识别与 encoding/json 一致，只改变字母大小写的
// 写法同样命中；报告位置始终使用这里的标准拼写，而不是输入里的大小写变体。
var (
	// entryFields 是日志条目的规则：index 与 term 是数值字段。
	entryFields = &fieldSpec{scalars: []string{"index", "term"}}
	// requestFields 是单条复制请求的规则：term、prevLogIndex、prevLogTerm、
	// leaderCommit 是数值字段，entries 是条目数组。
	requestFields = &fieldSpec{
		scalars: []string{"term", "prevLogIndex", "prevLogTerm", "leaderCommit"},
		arrays:  []arraySpec{{name: "entries", elem: entryFields}},
	}
	// rootFields 是整份输入的规则：currentTerm、committedIndex 是数值字段，
	// log 是初始日志条目数组，requests 是复制请求数组。
	rootFields = &fieldSpec{
		scalars: []string{"currentTerm", "committedIndex"},
		arrays: []arraySpec{
			{name: "log", elem: entryFields},
			{name: "requests", elem: requestFields},
		},
	}
)

// scalar 按标准名匹配已识别数值字段，命中时返回标准拼写。
func (s *fieldSpec) scalar(key string) (string, bool) {
	for _, name := range s.scalars {
		if strings.EqualFold(key, name) {
			return name, true
		}
	}
	return "", false
}

// array 按标准名匹配已识别数组字段，命中时返回其规则。
func (s *fieldSpec) array(key string) (arraySpec, bool) {
	for _, arr := range s.arrays {
		if strings.EqualFold(key, arr.name) {
			return arr, true
		}
	}
	return arraySpec{}, false
}

// nullNumericFieldPath 扫描整份输入 JSON 的 token 流，查找第一个被显式写成
// null 的已识别数值字段，返回它的完整位置；没有时返回空串。检查范围是初始
// 状态（currentTerm、committedIndex、log[i].index、log[i].term）与每条复制
// 请求（term、prevLogIndex、prevLogTerm、leaderCommit 及 entries[j].index、
// entries[j].term）；请求与条目下标从 0 开始，例如第二条请求的提交位置记为
// requests[1].leaderCommit。字段名识别与 encoding/json 一致，只改变字母大小
// 写的写法同样命中。
//
// 必须扫描 token 而不能先解进 map[string]interface{}：map 解码遇到重复键只
// 保留最后一次出现的值。{"currentTerm":null,"currentTerm":1} 里先出现的
// null 会因此漏检；log/requests/entries 自身重复出现时，前一份数组里的数值
// null 也会被后一份数组盖掉。token 流保留键的每一次出现，重复字段无论 null
// 在数字之前还是之后、数组字段重复多少次、拼写是否只改变大小写，都逃不过
// 检查。数组字段本身为 null、未知键（含未知对象里的同名键）里的 null 不在
// 检查范围内，扫描时只按结构识别已知字段，不进入其他对象与数组。
func nullNumericFieldPath(data []byte) string {
	dec := json.NewDecoder(bytes.NewReader(data))

	// 取根对象的第一个 token；输入不是对象或 JSON 非法时没有可报告的数值
	// 字段位置，交由随后的类型化解码产出既有的解析错误。
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}
	return scanObject(dec, rootFields, "")
}

// scanObject 检查一个已读出 '{' 的对象的每个字段，并消费到匹配的 '}' 为止。
// prefix 是该对象的位置前缀（根对象为空，其余以 '.' 结尾，如 "requests[1]."）。
// 命中数值字段且该次出现为 null 时返回完整位置；命中数组字段时递归扫描；
// 其余字段（含未知对象里的同名字段）整体跳过。
func scanObject(dec *json.Decoder, spec *fieldSpec, prefix string) string {
	for dec.More() {
		key, ok := decodeKey(dec)
		if !ok {
			return ""
		}
		if name, ok := spec.scalar(key); ok {
			if nullScalarPath(dec) {
				return prefix + name
			}
			continue
		}
		if arr, ok := spec.array(key); ok {
			// 元素位置前缀由外层前缀与标准字段名拼成：log[i].、
			// requests[i].、requests[r].entries[i].。
			if path := scanArray(dec, arr.elem, func(i int) string {
				return prefix + arr.name + fmt.Sprintf("[%d].", i)
			}); path != "" {
				return path
			}
			continue
		}
		skipValue(dec)
	}
	if _, err := dec.Token(); err != nil { // 对象的 '}'
		return ""
	}
	return ""
}

// scanArray 消费一个数组字段的完整 token 流（字段重复出现时由调用方对每一
// 份数组分别触发），对每个对象元素应用 spec 检查，返回第一个数值 null 的
// 完整位置。elemPrefix 按下标给出元素的位置前缀。
//
// 字段值不是数组（如 null 或被写成对象）时沿用既有处理：类型错误由随后的
// 类型化解码按既有格式报告，这里只把整个值消费完——起始分隔符已经读出，
// 若就此返回，扫描会落到对象内部，把其中的 term/index 等字段冒充成真实
// 字段，其后的真实数值 null 也会被漏检。
func scanArray(dec *json.Decoder, spec *fieldSpec, elemPrefix func(i int) string) string {
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	if tok != json.Delim('[') {
		if d, ok := tok.(json.Delim); ok {
			skipRest(dec, d)
		}
		return ""
	}
	for i := 0; dec.More(); i++ {
		if path := scanElement(dec, spec, elemPrefix(i)); path != "" {
			return path
		}
	}
	if _, err := dec.Token(); err != nil { // 数组的 ']'
		return ""
	}
	return ""
}

// scanElement 消费一个数组元素的完整 token 流；元素为对象时按 spec 检查其
// 字段，非对象元素不可能含已识别字段，但若它本身是容器仍要消费完整。
func scanElement(dec *json.Decoder, spec *fieldSpec, prefix string) string {
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	if tok != json.Delim('{') {
		if d, ok := tok.(json.Delim); ok {
			skipRest(dec, d)
		}
		return ""
	}
	return scanObject(dec, spec, prefix)
}

// decodeKey 读取并断言下一个 token 是对象键。
func decodeKey(dec *json.Decoder) (string, bool) {
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	key, ok := tok.(string)
	return key, ok
}

// nullScalarPath 消费一个已识别数值字段的值 token 流，报告该次出现是否被
// 显式写成 null。值为对象或数组时整体跳过（结构异常的输入留给类型化解码
// 报告既有错误）。
func nullScalarPath(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if tok == nil {
		return true
	}
	if d, ok := tok.(json.Delim); ok {
		skipRest(dec, d)
	}
	return false
}

// skipValue 读取并消费一个完整的 JSON 值（标量或容器）。
func skipValue(dec *json.Decoder) {
	tok, err := dec.Token()
	if err != nil {
		return
	}
	if d, ok := tok.(json.Delim); ok {
		skipRest(dec, d)
	}
}

// skipRest 消费一个容器剩余的 token 流，open 是已经读出的起始分隔符；
// 起始分隔符不是 '{' / '[' 时无需消费，直接返回。
func skipRest(dec *json.Decoder, open json.Delim) {
	if open != '{' && open != '[' {
		return
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
}
