// 已提交命令的键值应用：把日志命令解释为 set/delete/incr 键值操作，在本次调用内
// 从空键值表开始，随提交位置推进按日志索引顺序应用。本文件只做纯逻辑处理。
package mevwatch

import (
	"strconv"
	"strings"
	"unicode"
)

// 键值命令格式错误的原因（稳定标识符，帮助文档中有说明）。
const (
	ApplyReasonUnknownCommand   = `invalid command: expected "set <key>=<value>" or "delete <key>"`
	ApplyReasonEmptyKey         = "invalid command: key is empty"
	ApplyReasonKeyHasWhitespace = "invalid command: key contains whitespace"
	ApplyReasonKeyHasEquals     = "invalid command: key contains '='"
	ApplyReasonSetMissingEquals = "invalid command: set requires '=' between key and value"
	// incr 特有的三类失败：增量本身非法、当前值不是整数、相加溢出。
	ApplyReasonIncrMissingEquals = "invalid command: incr requires '=' between key and delta"
	ApplyReasonIncrBadDelta      = "invalid command: incr delta is not a signed 64-bit decimal integer"
	ApplyReasonIncrBadCurrent    = "invalid command: current value is not a signed 64-bit decimal integer"
	ApplyReasonIncrOverflow      = "invalid command: incr result exceeds signed 64-bit integer range"
)

// ApplyError 描述已提交命令中第一个格式错误：出错条目的日志索引与具体原因。
type ApplyError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// kvOperation 是一条解析成功的键值命令。各动作共有的格式规则（等号分隔、键
// 校验）由 parseKVCommand 统一保证；各动作自己的参数含义与失败原因由各自的
// apply 方法保留，执行方不再区分动作种类。
type kvOperation struct {
	isDelete bool
	isIncr   bool
	key      string
	value    string // 仅 set 使用；按原文保留，允许为空
	delta    int64  // 仅 incr 使用；解析时已校验为有符号 64 位整数
}

// parseKVCommand 把一条命令解释为键值操作，失败时返回具体原因。
// 命令区分大小写，命令名后必须恰好有一个普通空格；键不能为空、不能含空白
// 或等号；set 与 incr 都以键后的第一个等号分隔参数：set 的值按原文保留
// （可为空、含空格、中文及额外等号），incr 的增量必须是有符号 64 位十进制
// 整数（允许负号与前导零，其余形式一律非法）。命令两端不做任何空白裁剪。
func parseKVCommand(command string) (kvOperation, string) {
	if rest, ok := strings.CutPrefix(command, "set "); ok {
		key, value, reason := splitKVPair(rest, ApplyReasonSetMissingEquals)
		if reason != "" {
			return kvOperation{}, reason
		}
		return kvOperation{key: key, value: value}, ""
	}
	if rest, ok := strings.CutPrefix(command, "delete "); ok {
		if reason := validateKVKey(rest); reason != "" {
			return kvOperation{}, reason
		}
		return kvOperation{isDelete: true, key: rest}, ""
	}
	if rest, ok := strings.CutPrefix(command, "incr "); ok {
		key, deltaText, reason := splitKVPair(rest, ApplyReasonIncrMissingEquals)
		if reason != "" {
			return kvOperation{}, reason
		}
		delta, ok := parseKVInt(deltaText)
		if !ok {
			return kvOperation{}, ApplyReasonIncrBadDelta
		}
		return kvOperation{isIncr: true, key: key, delta: delta}, ""
	}
	return kvOperation{}, ApplyReasonUnknownCommand
}

// splitKVPair 按键后的第一个等号把命令参数分成键与值，并校验键。缺少等号时
// 返回调用方给定的原因：写入与累加分别说明缺少值的分隔符或增量的分隔符，
// 等号分隔与键校验这套共有规则只在此维护一份。
func splitKVPair(rest, missingEquals string) (key, value, reason string) {
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return "", "", missingEquals
	}
	key, value = rest[:eq], rest[eq+1:]
	if reason := validateKVKey(key); reason != "" {
		return "", "", reason
	}
	return key, value, ""
}

// validateKVKey 校验键：不能为空、不能含空白或等号。
func validateKVKey(key string) string {
	if key == "" {
		return ApplyReasonEmptyKey
	}
	for _, r := range key {
		if unicode.IsSpace(r) {
			return ApplyReasonKeyHasWhitespace
		}
		if r == '=' {
			return ApplyReasonKeyHasEquals
		}
	}
	return ""
}

// parseKVInt 把字符串按有符号 64 位十进制整数解析：允许负号与前导零，
// 不接受正号、空白、小数、指数形式或非 ASCII 数字，空字符串也不是整数；
// 超出 int64 范围同样失败。先逐字节校验形状，再交给 strconv 判定范围。
func parseKVInt(s string) (int64, bool) {
	digits := s
	if strings.HasPrefix(digits, "-") {
		digits = digits[1:]
	}
	if digits == "" {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// addKVInt 计算两个有符号 64 位整数之和，结果超出 int64 范围时 ok 为 false。
func addKVInt(a, b int64) (sum int64, ok bool) {
	sum = a + b
	// Go 的有符号溢出按二进制补码回绕：b 为正而和反而变小，或 b 为负而和
	// 反而变大，即越界。
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, false
	}
	return sum, true
}

// kvApplier 在本次调用内从空键值表开始，按日志索引顺序应用已提交命令。
// 一旦遇到格式错误，应用状态停住：已应用索引不再前进，错误保留到调用结束。
type kvApplier struct {
	kv           map[string]string
	appliedIndex int         // 已应用的最高日志索引，0 表示尚未应用任何条目
	err          *ApplyError // 非空后应用状态停住
}

func newKVApplier() *kvApplier {
	return &kvApplier{kv: map[string]string{}}
}

// applyUpTo 应用 (appliedIndex, committedIndex] 区间内尚未应用的已提交条目。
// 只前进不后退：空条目心跳、重复复制、提交位置不变时不会重复应用（incr 也
// 不会因此重复累加）；已出错时不再应用任何条目。未提交的条目不在此触及，
// 其格式错误不会提前暴露。
func (a *kvApplier) applyUpTo(log []LogEntry, committedIndex int) {
	if a.err != nil {
		return
	}
	for a.appliedIndex < committedIndex {
		next := a.appliedIndex + 1
		op, reason := parseKVCommand(log[next-1].Command)
		if reason == "" {
			reason = op.apply(a.kv)
		}
		if reason != "" {
			// 保留此前已成功应用的结果，已应用索引停在出错位置的前一条；
			// 本条命令不改变键值表。
			a.err = &ApplyError{Index: next, Reason: reason}
			return
		}
		a.appliedIndex = next
	}
}

// apply 把解析成功的操作作用到键值表，成功时返回空原因。各动作保留自己的
// 参数含义与失败原因：set 按原文写值，delete 删除（键不存在同样算成功），
// incr 按此前已生效的值累加。失败时键值表保持不变。
func (op kvOperation) apply(kv map[string]string) string {
	switch {
	case op.isDelete:
		delete(kv, op.key)
		return ""
	case op.isIncr:
		return op.applyIncr(kv)
	default:
		kv[op.key] = op.value
		return ""
	}
}

// applyIncr 计算一次增量后的新值并写回：键不存在时当前值按 0 处理（并因此
// 创建该键）；当前值必须是有符号 64 位十进制整数，相加结果也不得超出该范围。
// 成功时写回不带前导零的规范十进制形式（零统一为 "0"），增量为 0 同样写回
// 规范形式；失败时返回具体原因，键值表保持不变。
func (op kvOperation) applyIncr(kv map[string]string) string {
	current := int64(0)
	if existing, ok := kv[op.key]; ok {
		value, valid := parseKVInt(existing)
		if !valid {
			return ApplyReasonIncrBadCurrent
		}
		current = value
	}
	sum, ok := addKVInt(current, op.delta)
	if !ok {
		return ApplyReasonIncrOverflow
	}
	kv[op.key] = strconv.FormatInt(sum, 10)
	return ""
}
