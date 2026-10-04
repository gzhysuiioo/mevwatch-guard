package mevwatch

import (
	"math"
	"strings"
	"testing"
)

// 共同检查器必须按条目逐条、且每条内按索引连续、任期为正、任期不下降、任期
// 不超过上限的次序返回首次违反——这一次序同时决定初始状态错误与请求拒绝原因，
// 必须与整理前两侧各自的判断一致。
func TestCheckLogEntryRulesFirstViolationOrder(t *testing.T) {
	cases := []struct {
		name     string
		entries  []LogEntry
		anchor   int
		bound    int
		wantKind logEntryRuleKind
	}{
		{"all valid", []LogEntry{entry(1, 1, "a"), entry(2, 2, "b")}, 0, 2, logEntryRuleOK},
		{"valid from anchor", []LogEntry{entry(3, 2, "c"), entry(4, 2, "d")}, 2, 2, logEntryRuleOK},
		{"empty requires no next position", nil, math.MaxInt, 9, logEntryRuleOK},
		{"gap beats bad term on same entry", []LogEntry{entry(2, 0, "a")}, 0, 5, logEntryRuleIndexGap},
		{"non-positive term beats decrease on same entry",
			[]LogEntry{entry(1, 3, "a"), entry(2, 0, "b")}, 0, 5, logEntryRuleNonPositiveTerm},
		{"term decreases within bound",
			[]LogEntry{entry(1, 3, "a"), entry(2, 2, "b")}, 0, 9, logEntryRuleTermDecreases},
		{"term exceeds bound", []LogEntry{entry(1, 6, "a")}, 0, 5, logEntryRuleTermExceedsBound},
		{"first violation reported, not later",
			[]LogEntry{entry(1, 5, "a"), entry(3, 0, "b")}, 0, 5, logEntryRuleIndexGap},
		{"negative index is a gap", []LogEntry{entry(-1, 5, "a")}, 0, 5, logEntryRuleIndexGap},
		{"zero index is a gap", []LogEntry{entry(0, 5, "a")}, 0, 5, logEntryRuleIndexGap},
		{"overflow at first position is a gap",
			[]LogEntry{entry(math.MinInt, 9, "x")}, math.MaxInt, 9, logEntryRuleIndexGap},
		{"overflow mid-chain is a gap",
			[]LogEntry{entry(math.MaxInt, 9, "x"), entry(math.MinInt, 9, "y")}, math.MaxInt - 1, 9, logEntryRuleIndexGap},
		{"last position at max int is legal",
			[]LogEntry{entry(math.MaxInt, 9, "x")}, math.MaxInt - 1, 9, logEntryRuleOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkLogEntryRules(tc.entries, tc.anchor, tc.bound)
			if got.kind != tc.wantKind {
				t.Fatalf("kind = %d, want %d (%+v)", got.kind, tc.wantKind, got)
			}
		})
	}
}

// 两侧映射必须给出整理前各自的错误表达：请求侧是稳定原因常量，初始状态侧是
// 带索引/任期数值的错误文本。
func TestLogEntryRuleErrorMappings(t *testing.T) {
	if reason := (logEntryRuleError{}).requestReason(); reason != ReasonOK {
		t.Fatalf("empty violation maps to %q, want %q", reason, ReasonOK)
	}
	if err := (logEntryRuleError{}).initialStateError(); err != nil {
		t.Fatalf("empty violation maps to error %v, want nil", err)
	}

	indexGap := logEntryRuleError{kind: logEntryRuleIndexGap, position: 3, index: 7}
	if reason := indexGap.requestReason(); reason != ReasonEntryIndexGap {
		t.Fatalf("request reason = %q, want %q", reason, ReasonEntryIndexGap)
	}
	if msg := indexGap.initialStateError().Error(); !strings.Contains(msg, "log entry 3 has non-consecutive index 7") {
		t.Fatalf("initial error = %q", msg)
	}

	nonPositive := logEntryRuleError{kind: logEntryRuleNonPositiveTerm, position: 2, term: 0}
	if reason := nonPositive.requestReason(); reason != ReasonEmptyEntryTerm {
		t.Fatalf("request reason = %q, want %q", reason, ReasonEmptyEntryTerm)
	}
	if msg := nonPositive.initialStateError().Error(); !strings.Contains(msg, "log entry 2 has non-positive term 0") {
		t.Fatalf("initial error = %q", msg)
	}

	decrease := logEntryRuleError{kind: logEntryRuleTermDecreases, position: 2, term: 2, comparedTerm: 3}
	if reason := decrease.requestReason(); reason != ReasonEntryTermDecreases {
		t.Fatalf("request reason = %q, want %q", reason, ReasonEntryTermDecreases)
	}
	if msg := decrease.initialStateError().Error(); !strings.Contains(msg, "term 2 is lower than previous term 3") {
		t.Fatalf("initial error = %q", msg)
	}

	exceeds := logEntryRuleError{kind: logEntryRuleTermExceedsBound, position: 1, term: 3, comparedTerm: 2}
	if reason := exceeds.requestReason(); reason != ReasonEntryTermExceedsReqTerm {
		t.Fatalf("request reason = %q, want %q", reason, ReasonEntryTermExceedsReqTerm)
	}
	if msg := exceeds.initialStateError().Error(); !strings.Contains(msg, "term 3 exceeds currentTerm 2") {
		t.Fatalf("initial error = %q", msg)
	}
}
