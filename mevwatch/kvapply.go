// 已提交命令的键值应用：把日志命令解释为 set/delete 键值操作，在本次调用内
// 从空键值表开始，随提交位置推进按日志索引顺序应用。本文件只做纯逻辑处理。
package mevwatch

import (
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
)

// ApplyError 描述已提交命令中第一个格式错误：出错条目的日志索引与具体原因。
type ApplyError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// kvOperation 是一条解析成功的键值命令。
type kvOperation struct {
	isDelete bool
	key      string
	value    string // 仅 set 使用；按原文保留，允许为空
}

// parseKVCommand 把一条命令解释为键值操作，失败时返回具体原因。
// 命令区分大小写，命令名后必须恰好有一个普通空格；键不能为空、不能含空白
// 或等号；set 以键后的第一个等号分隔值，值按原文保留（可为空、含空格、
// 中文及额外等号）。命令两端不做任何空白裁剪。
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
		if op.isDelete {
			delete(a.kv, op.key) // 删除不存在的键同样算成功，该位置照常标记已应用
		} else {
			a.kv[op.key] = op.value
		}
		a.appliedIndex = next
	}
}
