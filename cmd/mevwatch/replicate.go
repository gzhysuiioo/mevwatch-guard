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
//
// log、requests 以及请求内 entries 是允许在同一对象中重复出现的数组字段，约定
// 后者生效。encoding/json 把重复出现的数组解到同一个非 nil 切片时，只会按下标
// 覆盖既有元素：后一份数组较短时尾部残留旧元素，元素省略的字段（command、
// index、term）也会从相同位置的旧元素继承，等于让用户给出的后一份日志借用了
// 前一份的内容。因此这三个数组都用整体替换的包装类型（replicateInputLog 等）
// 解码：每一次出现都解进一份全新的切片并整体替换，最后一份数组是什么就保留
// 什么，元素省略的数值按默认 0、省略的命令按空字符串解释。
type replicateInput struct {
	CurrentTerm    int                    `json:"currentTerm"`
	CommittedIndex int                    `json:"committedIndex"`
	Log            replicateInputLog      `json:"log"`
	ApplyKV        bool                   `json:"applyKV"`
	Requests       replicateInputRequests `json:"requests"`
}

// replicateInputLog 是根对象的 log 字段：重复出现时最后一份数组整体替换。
type replicateInputLog []mevwatch.LogEntry

func (l *replicateInputLog) UnmarshalJSON(data []byte) error {
	return unmarshalLastWinsArray(data, (*[]mevwatch.LogEntry)(l))
}

// replicateInputRequest 与 mevwatch.AppendRequest 字段相同，区别只是 entries
// 也走整体替换解码。
type replicateInputRequest struct {
	Term         int                   `json:"term"`
	PrevLogIndex int                   `json:"prevLogIndex"`
	PrevLogTerm  int                   `json:"prevLogTerm"`
	Entries      replicateInputEntries `json:"entries"`
	LeaderCommit int                   `json:"leaderCommit"`
}

// replicateInputRequests 是根对象的 requests 字段：重复出现时最后一份数组
// 整体替换，而不是把后一份请求按下标并进前一份。
type replicateInputRequests []replicateInputRequest

func (r *replicateInputRequests) UnmarshalJSON(data []byte) error {
	return unmarshalLastWinsArray(data, (*[]replicateInputRequest)(r))
}

// replicateInputEntries 是单个请求内的 entries 字段：同一请求对象里重复
// 出现时，最后一份条目数组整体替换。
type replicateInputEntries []mevwatch.LogEntry

func (e *replicateInputEntries) UnmarshalJSON(data []byte) error {
	return unmarshalLastWinsArray(data, (*[]mevwatch.LogEntry)(e))
}

// unmarshalLastWinsArray 把一次数组字段出现解进一份全新的切片，并用它整体
// 替换 dst。它必须先解进局部切片而不能直接解到 dst：encoding/json 对“非 nil
// 现有切片 + 重复数组键”只做下标覆盖，短数组的尾部与元素内省略的字段都会
// 残留上一次出现的内容。null 与既有行为一致，把目标置为空切片（nil）。
func unmarshalLastWinsArray[T any](data []byte, dst *[]T) error {
	var next []T
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	*dst = next
	return nil
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
	// 语法检查用 UseNumber 流式解码而不是解进 interface{}：后者把每个数字
	// 都转成 float64，未知字段里 1e400 这类超出浮点范围但完全合法的 JSON
	// 数字会让整份输入在解析阶段被误判为输入错误。未知字段不参与跟随者
	// 状态计算，其数值大小不应决定输入能否解析；UseNumber 把数字保留为
	// 原始字面量，只校验语法不做范围转换。已识别数值字段上的同类大数仍由
	// 随后的类型化解码按既有整数范围限制拒绝。
	syntaxDec := json.NewDecoder(bytes.NewReader(data))
	syntaxDec.UseNumber()
	var syntaxCheck interface{}
	if err := syntaxDec.Decode(&syntaxCheck); err != nil {
		fmt.Fprintf(stderr, "replicate: parse input JSON: %v\n", err)
		return 1
	}
	// 与 json.Unmarshal 一致：一份完整文档之后不允许再跟另一份 JSON 或
	// 其他内容。
	if syntaxDec.More() {
		fmt.Fprintf(stderr, "replicate: parse input JSON: unexpected data after top-level JSON value\n")
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
	// 三个数组经整体替换解码后再逐元素转成库类型：转换只按最后一份数组的实际
	// 内容进行，不携带任何同名前序数组的条目字段。
	initialLog := append([]mevwatch.LogEntry(nil), input.Log...)
	requests := make([]mevwatch.AppendRequest, len(input.Requests))
	for i, req := range input.Requests {
		requests[i] = mevwatch.AppendRequest{
			Term:         req.Term,
			PrevLogIndex: req.PrevLogIndex,
			PrevLogTerm:  req.PrevLogTerm,
			Entries:      append([]mevwatch.LogEntry(nil), req.Entries...),
			LeaderCommit: req.LeaderCommit,
		}
	}
	output, err := mevwatch.ReplicateWithOptions(mevwatch.InitialState{
		CurrentTerm:    input.CurrentTerm,
		CommittedIndex: input.CommittedIndex,
		Log:            initialLog,
	}, requests, mevwatch.ReplicateOptions{ApplyKV: input.ApplyKV})
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

// objectSchema 描述某一层次对象里已识别的字段：numerics 是显式写成 null 时
// 必须拒绝整份输入的数值字段（标准拼写），arrays 是元素为对象的数组字段及其
// 元素层次。字段名识别与 encoding/json 一致，只改变字母大小写的写法同样命中；
// 错误位置始终使用这里的标准拼写而不是输入里的大小写变体。根状态、复制请求
// 与日志条目共用同一套扫描逻辑，区别只在下面三份 schema。
type objectSchema struct {
	numerics []string
	arrays   []arrayField
}

// arrayField 是一个已识别的对象数组字段：name 为标准字段名，elem 为数组元素
// 所在层次的 schema。
type arrayField struct {
	name string
	elem *objectSchema
}

var (
	// 日志条目层次：log[i] 与 requests[r].entries[i] 是同一种对象。
	entryObjectSchema = &objectSchema{numerics: []string{"index", "term"}}
	// 复制请求层次：数值字段外还嵌套 entries 条目数组。
	requestObjectSchema = &objectSchema{
		numerics: []string{"term", "prevLogIndex", "prevLogTerm", "leaderCommit"},
		arrays:   []arrayField{{name: "entries", elem: entryObjectSchema}},
	}
	// 根输入层次：初始状态的数值字段外还嵌套 log 与 requests 两个数组。
	rootObjectSchema = &objectSchema{
		numerics: []string{"currentTerm", "committedIndex"},
		arrays: []arrayField{
			{name: "log", elem: entryObjectSchema},
			{name: "requests", elem: requestObjectSchema},
		},
	}
)

// numericName 在 key 命中本层次某个已识别数值字段时返回它的标准拼写。
func (s *objectSchema) numericName(key string) (string, bool) {
	for _, name := range s.numerics {
		if strings.EqualFold(key, name) {
			return name, true
		}
	}
	return "", false
}

// arrayField 在 key 命中本层次某个已识别数组字段时返回它的定义（含标准拼写）。
func (s *objectSchema) arrayField(key string) (arrayField, bool) {
	for _, field := range s.arrays {
		if strings.EqualFold(key, field.name) {
			return field, true
		}
	}
	return arrayField{}, false
}

// nullNumericFieldPath 扫描整份输入 JSON 的 token 流，查找第一个被显式写成
// null 的已识别数值字段，返回它的完整位置；没有时返回空串。检查范围是初始
// 状态（currentTerm、committedIndex、log[i].index、log[i].term）与每条复制
// 请求（term、prevLogIndex、prevLogTerm、leaderCommit 及 entries[j].index、
// entries[j].term）；请求与条目下标从 0 开始，例如第二条请求的提交位置记为
// requests[1].leaderCommit。
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
	// 数字一律按原始字面量（json.Number）读取：默认的 Token 行为会把数字
	// 转成 float64，未知字段里 1e400 这类超出浮点范围的合法数字会让扫描
	// 中途出错返回，从而遮住排在其后的真实数值 null。这里只关心结构，
	// 不需要任何数值转换。
	dec.UseNumber()

	// 取根对象的第一个 token；输入不是对象或 JSON 非法时没有可报告的数值
	// 字段位置，交由随后的类型化解码产出既有的解析错误。
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}
	return scanObjectFields(dec, rootObjectSchema, "")
}

// scanObjectFields 扫描一个已读入起始 '{' 的对象的字段流，prefix 是该对象
// 的位置前缀（根对象为空，其余层次以 "." 结尾，如 "requests[1]."）。每个键
// 按所在层次的 schema 分派：已识别数值字段检查是否写成 null，已识别数组字段
// 递归扫描元素，其余键的值整体跳过。返回第一个数值 null 的完整位置。
func scanObjectFields(dec *json.Decoder, schema *objectSchema, prefix string) string {
	for dec.More() {
		key, ok := decodeKey(dec)
		if !ok {
			return ""
		}
		if name, ok := schema.numericName(key); ok {
			if nullScalarPath(dec) {
				return prefix + name
			}
			continue
		}
		if field, ok := schema.arrayField(key); ok {
			if path := scanObjectArray(dec, field.elem, prefix+field.name); path != "" {
				return path
			}
			continue
		}
		skipValue(dec)
	}
	return ""
}

// scanObjectArray 扫描一个对象数组字段的完整 token 流（数组字段重复出现时由
// 调用方对每一份数组分别调用），arrayPath 是数组自身的位置（如 "log" 或
// "requests[r].entries"），返回第一个数值 null 的完整位置。
func scanObjectArray(dec *json.Decoder, elem *objectSchema, arrayPath string) string {
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	if tok != json.Delim('[') {
		// 数组字段本身为 null 或其他类型（如被写成对象）：沿用既有处理，
		// 类型错误由随后的类型化解码按既有格式报告。这里必须把整个值消费
		// 完——起始分隔符已经读出，若就此返回，调用方的循环会落到对象内部，
		// 把其中的 term/index 等字段当成外层已识别字段，其后的真实数值
		// null 也会被漏检。
		if d, ok := tok.(json.Delim); ok {
			skipRest(dec, d)
		}
		return ""
	}
	for i := 0; dec.More(); i++ {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if tok != json.Delim('{') {
			// 非对象元素不可能含已识别字段；若它本身是容器仍要消费完整。
			if d, ok := tok.(json.Delim); ok {
				skipRest(dec, d)
			}
			continue
		}
		prefix := fmt.Sprintf("%s[%d].", arrayPath, i)
		if path := scanObjectFields(dec, elem, prefix); path != "" {
			return path
		}
		if _, err := dec.Token(); err != nil { // 元素对象的 '}'
			return ""
		}
	}
	if _, err := dec.Token(); err != nil { // 数组的 ']'
		return ""
	}
	return ""
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
