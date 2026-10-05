// 已提交命令的键值应用：把日志命令解释为 set/delete/incr 键值操作，在本次
// 调用内从空键值表开始，随提交位置推进按日志索引顺序应用。本文件只做纯逻辑处理。
package mevwatch

import (
	"math"
	"strconv"
	"strings"
	"unicode"
)

// 键值命令格式错误的原因（稳定标识符，帮助文档中有说明）。
const (
	ApplyReasonUnknownCommand   = `invalid command: expected "set <key>=<value>", "delete <key>" or "incr <key>=<delta>"`
	ApplyReasonEmptyKey         = "invalid command: key is empty"
	ApplyReasonKeyHasWhitespace = "invalid command: key contains whitespace"
	ApplyReasonKeyHasEquals     = "invalid command: key contains '='"
	ApplyReasonSetMissingEquals = "invalid command: set requires '=' between key and value"
	// incr 的三类运行时错误互相区分：当前值不是合法整数、增量不是合法整数、
	// 两者相加超出有符号 64 位范围。任一发生时该条命令都不改变键值表。
	ApplyReasonIncrCurrentInvalid = "invalid incr: current value is not a signed 64-bit decimal integer"
	ApplyReasonIncrDeltaInvalid   = "invalid incr: delta is not a signed 64-bit decimal integer"
	ApplyReasonIncrOverflow       = "invalid incr: current value plus delta overflows signed 64-bit integer"
)

// ApplyError 描述已提交命令中第一个格式错误：出错条目的日志索引与具体原因。
type ApplyError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// kvOperation 是一条解析成功的键值命令。isDelete/isIncr 均为 false 时是 set。
type kvOperation struct {
	isDelete bool
	isIncr   bool
	key      string
	value    string // set 为按原文保留的值（允许为空）；incr 为增量原文
}

// parseKVCommand 把一条命令解释为键值操作，失败时返回具体原因。
// 命令区分大小写，命令名后必须恰好有一个普通空格；键不能为空、不能含空白
// 或等号；set/incr 以键后的第一个等号分隔右侧部分，set 的值按原文保留
// （可为空、含空格、中文及额外等号），incr 的增量是否为合法整数留到应用时
// 结合键值表当前值一起判定。命令两端不做任何空白裁剪。
func parseKVCommand(command string) (kvOperation, string) {
	if rest, ok := strings.CutPrefix(command, "set "); ok {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return kvOperation{}, ApplyReasonSetMissingEquals
		}
		key, value := rest[:eq], rest[eq+1:]
		if reason := validateKVKey(key); reason != "" {
			return kvOperation{}, reason
		}
		return kvOperation{key: key, value: value}, ""
	}
	if rest, ok := strings.CutPrefix(command, "incr "); ok {
		// 没有等号时右侧增量按空字符串处理：空字符串不是整数，应用时报增量非法。
		key, delta := rest, ""
		if eq := strings.IndexByte(rest, '='); eq >= 0 {
			key, delta = rest[:eq], rest[eq+1:]
		}
		if reason := validateKVKey(key); reason != "" {
			return kvOperation{}, reason
		}
		return kvOperation{isIncr: true, key: key, value: delta}, ""
	}
	if rest, ok := strings.CutPrefix(command, "delete "); ok {
		if reason := validateKVKey(rest); reason != "" {
			return kvOperation{}, reason
		}
		return kvOperation{isDelete: true, key: rest}, ""
	}
	return kvOperation{}, ApplyReasonUnknownCommand
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

// parseSignedInt64 把字符串严格解释为有符号 64 位十进制整数：只接受可选的
// 单个负号后接至少一个 ASCII 十进制数字，允许前导零。不接受正号、空白、小数
// 点、指数形式或非 ASCII 数字，空字符串也不是整数；数值必须落在
// [-2^63, 2^63-1]。先按字符串长度与逐位 ASCII 校验、再与同长度边界比较，
// 整个过程不依赖主机整数运算容纳超出范围的值。
func parseSignedInt64(literal string) (int64, bool) {
	if literal == "" {
		return 0, false
	}
	neg := false
	digits := literal
	if literal[0] == '-' {
		neg = true
		digits = literal[1:]
		if digits == "" {
			return 0, false
		}
	}
	if len(digits) > 19 {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	limit := "9223372036854775807"
	if neg {
		limit = "9223372036854775808" // |MinInt64|
	}
	if len(digits) == 19 && digits > limit {
		return 0, false
	}
	// 已按长度与同长度边界比较排除了越界值，因此幅值不超过 2^63，用无符号
	// 累加保证中间过程不溢出；再按下述规则转回有符号 int64。
	var magnitude uint64
	for i := 0; i < len(digits); i++ {
		magnitude = magnitude*10 + uint64(digits[i]-'0')
	}
	if !neg {
		return int64(magnitude), true // 此时 magnitude <= 2^63-1
	}
	if magnitude == uint64(1)<<63 {
		return math.MinInt64, true // 超出 MaxInt64 的唯一合法负值
	}
	return -int64(magnitude), true
}

// addInt64 计算两个合法 int64 的和，和超出有符号 64 位范围时报告溢出；
// 用范围比较而非直接相加，避免求和本身回绕。
func addInt64(current, delta int64) (int64, bool) {
	switch {
	case delta > 0 && current > math.MaxInt64-delta:
		return 0, false
	case delta < 0 && current < math.MinInt64-delta:
		return 0, false
	}
	return current + delta, true
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
// 只前进不后退：空条目心跳、重复复制、提交位置不变时不会重复应用；已出错时
// 不再应用任何条目。未提交的条目不在此触及，其格式错误不会提前暴露。
func (a *kvApplier) applyUpTo(log []LogEntry, committedIndex int) {
	if a.err != nil {
		return
	}
	for a.appliedIndex < committedIndex {
		next := a.appliedIndex + 1
		op, reason := parseKVCommand(log[next-1].Command)
		if reason != "" {
			// 保留此前已成功应用的结果，已应用索引停在出错位置的前一条。
			a.err = &ApplyError{Index: next, Reason: reason}
			return
		}
		switch {
		case op.isDelete:
			delete(a.kv, op.key) // 删除不存在的键同样算成功，该位置照常标记已应用
		case op.isIncr:
			if reason := a.applyIncr(op); reason != "" {
				// 增量命令非法时键值表保持原值，已应用索引停在该条之前。
				a.err = &ApplyError{Index: next, Reason: reason}
				return
			}
		default:
			a.kv[op.key] = op.value
		}
		a.appliedIndex = next
	}
}

// applyIncr 执行一条增量命令并在成功时写入规范十进制结果，返回空原因；失败
// 时不改变键值表并返回具体原因。判定顺序与规则描述一致：先看键的当前值
// （取决于同一日志中此前已生效的写入或删除），再看命令自带的增量文本，最后
// 判定相加是否溢出——多个问题同时存在时报告最先发现的那个。键不存在时当前
// 值按 0 计算并创建该键。
func (a *kvApplier) applyIncr(op kvOperation) string {
	current := int64(0)
	if existing, exists := a.kv[op.key]; exists {
		value, ok := parseSignedInt64(existing)
		if !ok {
			return ApplyReasonIncrCurrentInvalid
		}
		current = value
	}
	delta, ok := parseSignedInt64(op.value)
	if !ok {
		return ApplyReasonIncrDeltaInvalid
	}
	sum, ok := addInt64(current, delta)
	if !ok {
		return ApplyReasonIncrOverflow
	}
	// 规范形式：无前导零的十进制，零统一为 "0"；delta 为 0 也同样重写并推进。
	a.kv[op.key] = strconv.FormatInt(sum, 10)
	return ""
}
