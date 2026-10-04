// 日志条目的共同规则：初始日志与复制请求条目都必须满足索引连续、任期为正、
// 任期沿条目不下降、任期不超过各自的任期上限（初始状态为 currentTerm，请求
// 为请求 term）。规则本身只在本文件维护一份，后续调整同一项规则时只改这里；
// 初始状态与请求各自的错误表达（初始状态错误文本、请求拒绝原因常量）由各自
// 的映射方法保留原有差异。本文件只做纯逻辑处理。
package mevwatch

import (
	"fmt"
	"math"
)

// logEntryRuleKind 标识条目共同规则中最先违反的规则。检查在每条条目上按
// 索引连续、任期为正、任期不下降、任期不超过上限的次序进行，多处问题同时
// 出现时只报告这一次序下最先的一项——初始状态与请求原有的错误优先级都依赖
// 这个次序。
type logEntryRuleKind int

const (
	logEntryRuleOK logEntryRuleKind = iota
	logEntryRuleIndexGap
	logEntryRuleNonPositiveTerm
	logEntryRuleTermDecreases
	logEntryRuleTermExceedsBound
)

// logEntryRuleError 记录共同规则的首次违反：
//   - kind：违反的规则；
//   - position：该条目按连续性应当占据的日志位置（anchorIndex 起逐条加 1）；
//   - index/term：条目实际给出的索引与任期；
//   - comparedTerm：对比任期——任期不下降时是前一条目任期，超上限时是上限。
type logEntryRuleError struct {
	kind         logEntryRuleKind
	position     int
	index        int
	term         int
	comparedTerm int
}

// checkLogEntryRules 按序校验 entries：条目必须依次位于 anchorIndex+1、
// anchorIndex+2、……，任期为正、沿条目自身不下降、且不超过 boundTerm。
// anchorIndex 必须非负：初始日志传 0（首条位置为 1），请求传 prevLogIndex
// （首条位置为 prevLogIndex+1），调用方负责先保证其非负。
//
// 位置必须用检查过的加法逐条推进，不能直接相加：anchorIndex 或链上任一位置
// 已是当前 int 上限时，下一位置无法表示，而输入里的负索引恰好在数学上等于
// 回绕后的位置，直接相加会静默溢出把它误判为连续。这种输入按索引不连续处
// 理：空序列不要求存在下一位置，最后一条恰好到达 int 上限同样合法。
// 返回零值表示全部通过。
func checkLogEntryRules(entries []LogEntry, anchorIndex, boundTerm int) logEntryRuleError {
	position := anchorIndex
	for i, entry := range entries {
		if position == math.MaxInt {
			// 下一位置无法用 int 表示：与普通索引不连续同属一类。初始日志
			// 长度受切片长度限制到不了这里；请求路径靠该分支拦住回绕负索引。
			return logEntryRuleError{kind: logEntryRuleIndexGap, position: position, index: entry.Index}
		}
		position++
		// 索引 0 是哨兵，真实条目位置必为正；entry.Index<=0 一并按不连续拒绝。
		if entry.Index <= 0 || entry.Index != position {
			return logEntryRuleError{kind: logEntryRuleIndexGap, position: position, index: entry.Index}
		}
		if entry.Term <= 0 {
			return logEntryRuleError{kind: logEntryRuleNonPositiveTerm, position: position, term: entry.Term}
		}
		if i > 0 && entry.Term < entries[i-1].Term {
			return logEntryRuleError{
				kind: logEntryRuleTermDecreases, position: position,
				term: entry.Term, comparedTerm: entries[i-1].Term,
			}
		}
		if entry.Term > boundTerm {
			return logEntryRuleError{
				kind: logEntryRuleTermExceedsBound, position: position,
				term: entry.Term, comparedTerm: boundTerm,
			}
		}
	}
	return logEntryRuleError{}
}

func (e logEntryRuleError) ok() bool { return e.kind == logEntryRuleOK }

// initialStateError 把共同规则的违反翻译成初始状态错误，文本与 newReplicateState
// 原有的逐条表达完全一致；没有违反时返回 nil。
func (e logEntryRuleError) initialStateError() error {
	switch e.kind {
	case logEntryRuleIndexGap:
		return fmt.Errorf("invalid initial state: log entry %d has non-consecutive index %d", e.position, e.index)
	case logEntryRuleNonPositiveTerm:
		return fmt.Errorf("invalid initial state: log entry %d has non-positive term %d", e.position, e.term)
	case logEntryRuleTermDecreases:
		return fmt.Errorf("invalid initial state: log entry %d term %d is lower than previous term %d", e.position, e.term, e.comparedTerm)
	case logEntryRuleTermExceedsBound:
		return fmt.Errorf("invalid initial state: log entry %d term %d exceeds currentTerm %d", e.position, e.term, e.comparedTerm)
	default:
		return nil
	}
}

// requestReason 把共同规则的违反翻译成单条复制请求的拒绝原因标识符，与
// validateRequest 原有结果完全一致；没有违反时返回 ReasonOK。
func (e logEntryRuleError) requestReason() string {
	switch e.kind {
	case logEntryRuleIndexGap:
		return ReasonEntryIndexGap
	case logEntryRuleNonPositiveTerm:
		return ReasonEmptyEntryTerm
	case logEntryRuleTermDecreases:
		return ReasonEntryTermDecreases
	case logEntryRuleTermExceedsBound:
		return ReasonEntryTermExceedsReqTerm
	default:
		return ReasonOK
	}
}
