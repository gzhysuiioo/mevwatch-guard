// Raft 跟随者本地日志复制：在单次命令调用内维护节点状态，顺序应用
// 领导者发来的 AppendEntries 请求。本文件只做纯逻辑处理，不连接网络。
package mevwatch

import (
	"fmt"
	"math"
)

// LogEntry 是一条日志：Index 从 1 开始连续编号，Term 为该条目写入时的任期，
// Command 为字符串命令。
type LogEntry struct {
	Index   int    `json:"index"`
	Term    int    `json:"term"`
	Command string `json:"command"`
}

// InitialState 是跟随者在本次调用开始时的状态。
type InitialState struct {
	// CurrentTerm 是该节点已知的最新任期。
	CurrentTerm int `json:"currentTerm"`
	// CommittedIndex 是已经提交（不可覆盖）的最高日志索引。
	CommittedIndex int `json:"committedIndex"`
	// Log 是从索引 1 开始的连续日志。
	Log []LogEntry `json:"log"`
}

// AppendRequest 是顺序到达的一次日志复制请求。
type AppendRequest struct {
	// Term 是领导者任期。
	Term int `json:"term"`
	// PrevLogIndex / PrevLogTerm 是新条目紧邻的前一条日志的索引与任期；
	// 均为 0 表示日志起点（哨兵），不是真实条目。
	PrevLogIndex int `json:"prevLogIndex"`
	PrevLogTerm  int `json:"prevLogTerm"`
	// Entries 是待追加的条目，必须从前一条索引加 1 开始连续排列，允许为空。
	Entries []LogEntry `json:"entries"`
	// LeaderCommit 是领导者已提交索引。
	LeaderCommit int `json:"leaderCommit"`
}

// ConflictHint 是前置日志不匹配时给调用方的重发建议：Index 是建议重发的
// 起始索引，Term 是冲突位置的本地任期。只描述本次请求检查时的本地日志，
// 不随拒绝改变任何状态。
type ConflictHint struct {
	Index int `json:"index"`
	Term  int `json:"term"`
}

// AppendResult 是单条请求处理后节点对该请求的答复。
type AppendResult struct {
	// Accepted 表示本次复制是否成功。
	Accepted bool `json:"accepted"`
	// Reason 是成功 ok 或被拒绝的具体原因。
	Reason string `json:"reason"`
	// Term 是处理后节点的当前任期（较高任期请求即便最终被拒绝也会留下任期更新）。
	Term int `json:"term"`
	// CommittedIndex 是处理后节点的已提交索引。
	CommittedIndex int `json:"committedIndex"`
	// Conflict 仅在实际因前置日志不匹配而拒绝时出现；成功请求与其他原因
	// 的拒绝都不携带。
	Conflict *ConflictHint `json:"conflict,omitempty"`
	// AppliedIndex / ApplyError 仅在启用键值应用（ReplicateOptions.ApplyKV）
	// 时填充：处理本请求后已应用的最高日志索引与首个应用错误。
	// 复制是否被接受与命令应用是否失败相互独立表达。
	AppliedIndex *int        `json:"appliedIndex,omitempty"`
	ApplyError   *ApplyError `json:"applyError,omitempty"`
	// applyFields 为 true 时 JSON 输出总是带上 appliedIndex 与 applyError
	// （无错误时 applyError 为 null）；为 false 时两个字段完全不出现。
	// 编解码规则见 applyfields.go。
	applyFields bool
}

// ReplicateOutput 是整次调用的结果。
type ReplicateOutput struct {
	// Results 与输入请求一一对应。
	Results []AppendResult `json:"results"`
	// FinalTerm / FinalCommittedIndex 是最终状态。
	FinalTerm           int `json:"finalTerm"`
	FinalCommittedIndex int `json:"finalCommittedIndex"`
	// FinalLog 是处理完所有请求后的完整日志。
	FinalLog []LogEntry `json:"finalLog"`
	// FinalAppliedIndex / FinalKV / FinalApplyError 仅在启用键值应用时填充：
	// 最终已应用的最高日志索引、最终键值表与首个应用错误。没有请求时同样
	// 反映初始已提交前缀的应用结果。
	FinalAppliedIndex *int              `json:"finalAppliedIndex,omitempty"`
	FinalKV           map[string]string `json:"finalKV,omitempty"`
	FinalApplyError   *ApplyError       `json:"finalApplyError,omitempty"`
	// applyFields 含义同 AppendResult.applyFields，编解码规则见 applyfields.go。
	applyFields bool
}

// 拒绝原因（稳定标识符，帮助文档中有说明）。
const (
	ReasonOK                      = "ok"
	ReasonStaleTerm               = "stale term: leader term is lower than current term"
	ReasonRequestTermNegative     = "invalid request: term is negative"
	ReasonPrevLogIndexNegative    = "invalid request: prevLogIndex is negative"
	ReasonPrevLogTermNegative     = "invalid request: prevLogTerm is negative"
	ReasonLeaderCommitNegative    = "invalid request: leaderCommit is negative"
	ReasonEmptyEntryTerm          = "invalid request: log entry has zero term"
	ReasonEntryIndexGap           = "invalid request: entries are not consecutive from prevLogIndex+1"
	ReasonEntryTermDecreases      = "invalid request: entry terms are not non-decreasing"
	ReasonEntryTermExceedsReqTerm = "invalid request: entry term exceeds request term"
	ReasonPrevLogMismatch         = "prev log mismatch: entry at prevLogIndex is missing or has a different term"
	ReasonCommandConflictSameTerm = "entry conflict: same index and term but different command"
	ReasonWouldOverwriteCommitted = "would overwrite committed entry"
)

type replicateState struct {
	currentTerm    int
	committedIndex int
	log            []LogEntry // log[i].Index == i+1
}

// ReplicateOptions 控制 Replicate 的可选行为。零值保持原有处理与输出。
type ReplicateOptions struct {
	// ApplyKV 为 true 时把已提交命令解释为键值操作（set/delete/incr），在本次
	// 调用内从空键值表开始，随提交位置推进按日志次序逐条应用；为 false
	// 时命令仍是不加解释的任意字符串。
	ApplyKV bool
}

// Replicate 校验初始状态并顺序应用全部复制请求，返回逐次结果与最终状态。
// 初始状态非法时返回错误（调用方应以非零退出码结束）。单条请求违反字段规则
// 时只记录一次拒绝、不改变任何状态，随后继续处理下一条请求。
func Replicate(initial InitialState, requests []AppendRequest) (ReplicateOutput, error) {
	return ReplicateWithOptions(initial, requests, ReplicateOptions{})
}

// ReplicateWithOptions 与 Replicate 相同，但可通过 ReplicateOptions 启用
// 可选行为（如键值应用）。
func ReplicateWithOptions(initial InitialState, requests []AppendRequest, opts ReplicateOptions) (ReplicateOutput, error) {
	state, err := newReplicateState(initial)
	if err != nil {
		return ReplicateOutput{}, err
	}

	var applier *kvApplier
	if opts.ApplyKV {
		applier = newKVApplier()
		// 先按索引顺序应用初始日志中已提交的前缀，再顺序处理复制请求。
		applier.applyUpTo(state.log, state.committedIndex)
	}

	results := make([]AppendResult, 0, len(requests))
	for _, request := range requests {
		result := state.apply(request)
		if applier != nil {
			// 每条请求处理结束后，只应用新提交且尚未应用的日志；应用失败
			// 不改变复制的接受与否、提交位置或拒绝原因。
			applier.applyUpTo(state.log, state.committedIndex)
			result.setApplyFields(applier.appliedIndex, applier.err)
		}
		results = append(results, result)
	}
	finalLog := append([]LogEntry{}, state.log...)
	if finalLog == nil {
		finalLog = []LogEntry{}
	}
	output := ReplicateOutput{
		Results:             results,
		FinalTerm:           state.currentTerm,
		FinalCommittedIndex: state.committedIndex,
		FinalLog:            finalLog,
	}
	if applier != nil {
		output.setApplyFields(applier.appliedIndex, applier.kv, applier.err)
	}
	return output, nil
}

func newReplicateState(initial InitialState) (replicateState, error) {
	if initial.CurrentTerm < 0 {
		return replicateState{}, fmt.Errorf("invalid initial state: currentTerm must be a non-negative integer")
	}
	if initial.CommittedIndex < 0 {
		return replicateState{}, fmt.Errorf("invalid initial state: committedIndex must be a non-negative integer")
	}
	if initial.CommittedIndex > len(initial.Log) {
		return replicateState{}, fmt.Errorf("invalid initial state: committedIndex %d exceeds log length %d", initial.CommittedIndex, len(initial.Log))
	}
	log := append([]LogEntry(nil), initial.Log...)
	if rule, i := checkEntryRules(log, 0, initial.CurrentTerm); rule != entryRuleOK {
		expected := i + 1
		entry := log[i]
		switch rule {
		case entryRuleIndexGap:
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d has non-consecutive index %d", expected, entry.Index)
		case entryRuleTermNonPositive:
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d has non-positive term %d", expected, entry.Term)
		case entryRuleTermDecreases:
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d term %d is lower than previous term %d", expected, entry.Term, log[i-1].Term)
		case entryRuleTermExceedsMax:
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d term %d exceeds currentTerm %d", expected, entry.Term, initial.CurrentTerm)
		}
	}
	return replicateState{
		currentTerm:    initial.CurrentTerm,
		committedIndex: initial.CommittedIndex,
		log:            log,
	}, nil
}

// termAt 返回索引 idx 处条目的任期；idx 为 0 时是日志起点哨兵，超出日志长度时 ok 为 false。
func (s *replicateState) termAt(idx int) (term int, ok bool) {
	switch {
	case idx == 0:
		return 0, true
	case idx < 0 || idx > len(s.log):
		return 0, false
	default:
		return s.log[idx-1].Term, true
	}
}

// conflictFor 按检查时的完整本地日志（含已提交前缀）生成前置日志不匹配的
// 重发建议：prevLogIndex 越过日志末尾时建议从末尾加一处重发、任期记 0（空
// 日志因此是索引 1）；索引存在但任期不同时，反馈该位置的本地任期以及这个
// 任期在本地日志中第一次出现的索引。索引 0 是哨兵，其本地任期视为 0，而
// 任期 0 不会出现在真实条目中，第一次出现的位置按索引 1 处理。
func (s *replicateState) conflictFor(prevLogIndex int) *ConflictHint {
	if prevLogIndex > len(s.log) {
		return &ConflictHint{Index: len(s.log) + 1, Term: 0}
	}
	term, _ := s.termAt(prevLogIndex)
	first := 1
	for i, entry := range s.log {
		if entry.Term == term {
			first = i + 1
			break
		}
	}
	return &ConflictHint{Index: first, Term: term}
}

// appendDecision 是单条请求的裁决结果。裁决只在只读副本上推导，不触碰
// replicateState 本身，把“接受/拒绝与冲突判断”和“状态落笔”彻底分开：
//
//   - accepted 为 true 时，mergedLog 是合并后的完整新日志、commitTo 是本次
//     允许提交位置推进到的目标；
//   - accepted 为 false 时，reason 是既有拒绝原因、conflict 仅在前置日志不
//     匹配时非空，mergedLog 为 nil；
//   - termToKeep 是处理后必须保留的当前任期：字段非法与低任期拒绝保持请求
//     前的任期，合法请求（含被拒绝的高任期请求）携带更高任期时为该新任期。
//
// 每种拒绝允许留下哪些状态变化，只由 apply 对这些字段的统一处理决定，裁决
// 函数不再各自维护日志与提交位置的回滚。
type appendDecision struct {
	accepted   bool
	reason     string
	conflict   *ConflictHint
	termToKeep int
	mergedLog  []LogEntry // 仅 accepted 时非 nil
	commitTo   int        // 仅 accepted 时有效
}

// apply 处理单条请求。裁决（decide）与落笔（commitDecision）分开后，各类
// 拒绝能留下的状态变化只有一处统一边界：
//
//   - 字段非法、低任期：裁决不触碰状态，任期、日志、提交位置全部保持；
//   - 前置不匹配、同任期命令冲突、覆盖已提交条目：仅保留更高任期（若有），
//     日志与提交位置保持请求前的值；
//   - 接受：整体替换为裁决出的合并日志，并只向前推进提交位置。
//
// 裁决在状态副本上进行，因此拒绝路径不需要回滚，接受路径一次性落笔，任何
// 拒绝都不会在日志与已提交索引上留下部分变更。
func (s *replicateState) apply(request AppendRequest) AppendResult {
	decision := s.decide(request)
	s.commitDecision(decision)
	return AppendResult{
		Accepted:       decision.accepted,
		Reason:         decision.reason,
		Term:           s.currentTerm,
		CommittedIndex: s.committedIndex,
		Conflict:       decision.conflict,
	}
}

// commitDecision 按裁决落笔，是全部裁决共用的唯一状态变更点：接受时一次性
// 替换日志并只在新目标更高时推进提交位置；拒绝时只保留任期。日志与提交位置
// 除接受外不会被写入，因此无需快照回滚。
func (s *replicateState) commitDecision(d appendDecision) {
	s.currentTerm = d.termToKeep
	if !d.accepted {
		return
	}
	s.log = d.mergedLog
	if d.commitTo > s.committedIndex {
		s.committedIndex = d.commitTo
	}
}

// decide 在状态副本上裁决单条请求，返回带明确状态边界的裁决。整个推导只读
// s：所有可能改动日志的合并动作都发生在副本上，校验未全部通过时副本被直接
// 丢弃，不产生任何部分修改。
func (s *replicateState) decide(request AppendRequest) appendDecision {
	// 规则 1：先做字段合法性校验。违反字段规则的请求只记录拒绝、不改变任何
	// 状态——即使它携带更高任期，也不能更新节点。
	if reason := validateRequest(request); reason != ReasonOK {
		return s.reject(reason, nil)
	}

	// 规则 2：较低任期直接拒绝，状态（含任期）完全不变。
	if request.Term < s.currentTerm {
		return s.reject(ReasonStaleTerm, nil)
	}

	// 规则 3：首条目任期不得低于前一条日志任期（整段日志必须不下降）。
	// 这仍属于字段规则，放在任期更新之前：非法请求不能借高任期改变节点。
	if len(request.Entries) > 0 && request.Entries[0].Term < request.PrevLogTerm {
		return s.reject(ReasonEntryTermDecreases, nil)
	}

	// 至此字段合法且任期不低于当前任期。先在裁决中确定处理后的任期：较高
	// 任期即使随后被拒绝也必须保留，其余情况沿用当前任期。
	term := s.currentTerm
	if request.Term > term {
		term = request.Term
	}

	// 规则 4：前一条日志必须存在且任期相同。索引 0 始终只与任期 0 匹配。
	// 只有这种拒绝附带重发建议，且建议按此时（未因本请求改变）的本地日志生成。
	prevTerm, ok := s.termAt(request.PrevLogIndex)
	if !ok || prevTerm != request.PrevLogTerm {
		return s.rejectKeepingTerm(term, ReasonPrevLogMismatch, s.conflictFor(request.PrevLogIndex))
	}

	// 规则 5：在副本上规划日志合并。同任期不同命令、不同任期覆盖已提交条目
	// 都在落笔前判定为拒绝；副本连同其中的中间修改一并丢弃，状态保持请求前
	// 的值（任期除外，已在上面确定保留）。
	mergedLog, reason := planMergedLog(s.log, request, s.committedIndex)
	if reason != ReasonOK {
		return s.rejectKeepingTerm(term, reason, nil)
	}

	// 规则 6：提交位置推进至 leaderCommit 与本次确认的最后索引的较小值；
	// 是否只前进不后退由 commitDecision 统一保证。空条目请求的确认位置就是
	// 前一条索引。
	lastIndex := request.PrevLogIndex + len(request.Entries)
	commitTo := request.LeaderCommit
	if lastIndex < commitTo {
		commitTo = lastIndex
	}
	return appendDecision{
		accepted:   true,
		reason:     ReasonOK,
		termToKeep: term,
		mergedLog:  mergedLog,
		commitTo:   commitTo,
	}
}

// reject 构造“状态完全不变”的拒绝裁决：任期保持请求前的当前任期。字段非法
// 与低任期拒绝共用这一边界。
func (s *replicateState) reject(reason string, conflict *ConflictHint) appendDecision {
	return s.rejectKeepingTerm(s.currentTerm, reason, conflict)
}

// rejectKeepingTerm 构造拒绝裁决并显式给出处理后保留的任期；conflict 仅在
// 实际因前置日志不匹配而拒绝时非空。
func (s *replicateState) rejectKeepingTerm(term int, reason string, conflict *ConflictHint) appendDecision {
	return appendDecision{
		accepted:   false,
		reason:     reason,
		conflict:   conflict,
		termToKeep: term,
	}
}

// planMergedLog 在前一条日志已匹配的前提下计算合并后的完整日志。它只读取
// state 日志、不修改入参切片：比对中产生的截断发生在本地副本上，任何拒绝
// 都不会改动调用方日志。
//
// 合并语义（与原有行为保持一致）：
//   - 同位置同任期同命令的已存在条目继续保留，重复请求不会产生重复条目；
//   - 全部匹配的较短请求不能删除本地多出的尾部；
//   - 在仍需比对的位置遇到同任期不同命令：拒绝（ReasonCommandConflictSameTerm）；
//   - 未提交位置首次出现不同任期：从该位置起的旧后缀由本次条目替换，其后
//     的旧命令不再成为同任期命令冲突的依据（检查在首个任期分界处即停止）；
//   - 不同任期条目将覆盖已提交位置：拒绝（ReasonWouldOverwriteCommitted），
//     不返回部分结果。
//
// 超出本地日志长度的位置尚不存在，无需比对，随本次条目整体追加。
func planMergedLog(state []LogEntry, request AppendRequest, committedIndex int) ([]LogEntry, string) {
	start := request.PrevLogIndex // entries[k] 对应日志索引 start+1+k
	cutAt := -1                   // 首个不同任期的现有位置（切片下标）
	matched := 0                  // 与现有位置完全相同（同任期同命令）的连续前缀长度
	for offset, incoming := range request.Entries {
		idx := start + 1 + offset
		if idx > len(state) {
			break // 该位置及之后都不存在：稍后整体追加
		}
		existing := state[idx-1]
		switch {
		case existing.Term == incoming.Term && existing.Command == incoming.Command:
			matched++
		case existing.Term == incoming.Term:
			// 同索引同任期却命令不同：拒绝，不留下任何日志修改。
			return nil, ReasonCommandConflictSameTerm
		case idx <= committedIndex:
			// 不同任期意味着要覆盖该处及其后缀；已提交条目不可覆盖。
			return nil, ReasonWouldOverwriteCommitted
		default:
			// 未提交位置上的任期分界：截断到此处再追加，其后旧日志整段丢弃，
			// 被替换后缀里的旧命令不再参与后续比对。
			cutAt = idx - 1
		}
		if cutAt >= 0 {
			break
		}
	}

	// 全部匹配的短请求（无任期分界且 matched == len(entries)）原样保留本地
	// 多出的尾部；出现任期分界时，保留分界之前的部分（其中此前完全相同的
	// 匹配前缀继续保留），再整体追加分界起的本次条目。
	if cutAt < 0 {
		if matched == len(request.Entries) {
			return state, ReasonOK
		}
		return append(append([]LogEntry(nil), state...), request.Entries[matched:]...), ReasonOK
	}
	merged := append([]LogEntry(nil), state[:cutAt]...)
	return append(merged, request.Entries[cutAt-start:]...), ReasonOK
}

func validateRequest(request AppendRequest) string {
	if request.Term < 0 {
		return ReasonRequestTermNegative
	}
	if request.PrevLogIndex < 0 {
		return ReasonPrevLogIndexNegative
	}
	if request.PrevLogTerm < 0 {
		return ReasonPrevLogTermNegative
	}
	if request.LeaderCommit < 0 {
		return ReasonLeaderCommitNegative
	}
	// 条目必须从前一条索引加 1 开始连续排列；任期为正、沿请求条目自身
	// 不下降，且不得超过请求（领导者）任期。与 prevLogTerm 的衔接在
	// decide 中单独检查。
	switch rule, _ := checkEntryRules(request.Entries, request.PrevLogIndex, request.Term); rule {
	case entryRuleIndexGap:
		return ReasonEntryIndexGap
	case entryRuleTermNonPositive:
		return ReasonEmptyEntryTerm
	case entryRuleTermDecreases:
		return ReasonEntryTermDecreases
	case entryRuleTermExceedsMax:
		return ReasonEntryTermExceedsReqTerm
	}
	return ReasonOK
}

// entryRule 是日志条目序列共有校验发现的违规类别。初始日志与复制请求条目
// 共用同一套规则（见 checkEntryRules），各自把类别翻译成自己的错误表达。
type entryRule int

const (
	entryRuleOK entryRule = iota
	// entryRuleIndexGap：索引未从期望位置连续排列（含下一位置超出 int 上限）。
	entryRuleIndexGap
	// entryRuleTermNonPositive：任期非正。
	entryRuleTermNonPositive
	// entryRuleTermDecreases：任期低于序列内前一条目。
	entryRuleTermDecreases
	// entryRuleTermExceedsMax：任期超过调用方给定的上限。
	entryRuleTermExceedsMax
)

// checkEntryRules 按条目顺序校验 entries 是否从 prevPosition+1 开始连续编号、
// 任期为正、沿序列自身不下降且不超过 maxTerm，返回首个违规的类别与该条目在
// entries 中的下标；全部通过时返回 entryRuleOK 与 -1。与序列之前一条日志
// （prevLogTerm）的任期衔接不属于本函数职责，由调用方单独检查。
//
// 位置必须用检查过的加法逐条推进：prevPosition+1 或链上任一后续位置超过当前
// int 上限时，输入里的负索引恰好在数学上等于回绕后的位置，直接相加会静默溢出
// 把它误判为连续。这种情况按索引不连续处理。空条目序列不要求存在下一位置，
// 最后一条恰好到达 int 上限同样合法。索引 0 是哨兵，真实条目索引必为正。
func checkEntryRules(entries []LogEntry, prevPosition, maxTerm int) (entryRule, int) {
	position := prevPosition
	for i, entry := range entries {
		if position == math.MaxInt {
			return entryRuleIndexGap, i // 下一位置无法用 int 表示
		}
		position++
		if entry.Index <= 0 || entry.Index != position {
			return entryRuleIndexGap, i
		}
		if entry.Term <= 0 {
			return entryRuleTermNonPositive, i
		}
		if i > 0 && entry.Term < entries[i-1].Term {
			return entryRuleTermDecreases, i
		}
		if entry.Term > maxTerm {
			return entryRuleTermExceedsMax, i
		}
	}
	return entryRuleOK, -1
}
