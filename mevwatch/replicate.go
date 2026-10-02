// Raft 跟随者本地日志复制：在单次命令调用内维护节点状态，顺序应用
// 领导者发来的 AppendEntries 请求。本文件只做纯逻辑处理，不连接网络。
package mevwatch

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
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
	// ApplyKV 为 true 时把已提交命令解释为 set/delete 键值操作；
	// 为 false（默认）时命令是任意字符串，输出也不包含键值相关字段。
	ApplyKV bool `json:"applyKV"`
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
	// AppliedIndex 仅在启用 applyKV 时出现：处理后已应用键值命令的最高日志索引。
	AppliedIndex int `json:"appliedIndex"`
	// ApplyError 仅在启用 applyKV 时出现：null 或第一条已提交的格式错误。
	ApplyError *ApplyError `json:"applyError"`

	// kvEnabled 控制 JSON 是否包含键值字段，不对外暴露。
	kvEnabled bool
}

// ApplyError 描述键值应用过程中遇到的第一条已提交格式错误。
type ApplyError struct {
	// Index 是出错日志条目的索引。
	Index int `json:"index"`
	// Reason 是具体的格式问题。
	Reason string `json:"reason"`
}

// MarshalJSON 按是否启用 applyKV 输出不同字段集：未启用时与旧输出完全一致。
func (r AppendResult) MarshalJSON() ([]byte, error) {
	if !r.kvEnabled {
		type plain struct {
			Accepted       bool   `json:"accepted"`
			Reason         string `json:"reason"`
			Term           int    `json:"term"`
			CommittedIndex int    `json:"committedIndex"`
		}
		return json.Marshal(plain{r.Accepted, r.Reason, r.Term, r.CommittedIndex})
	}
	type enabled struct {
		Accepted       bool        `json:"accepted"`
		Reason         string      `json:"reason"`
		Term           int         `json:"term"`
		CommittedIndex int         `json:"committedIndex"`
		AppliedIndex   int         `json:"appliedIndex"`
		ApplyError     *ApplyError `json:"applyError"`
	}
	return json.Marshal(enabled{
		Accepted:       r.Accepted,
		Reason:         r.Reason,
		Term:           r.Term,
		CommittedIndex: r.CommittedIndex,
		AppliedIndex:   r.AppliedIndex,
		ApplyError:     r.ApplyError,
	})
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
	// FinalAppliedIndex 仅在启用 applyKV 时出现：最终已应用的最高日志索引。
	FinalAppliedIndex int `json:"finalAppliedIndex"`
	// FinalKV 仅在启用 applyKV 时出现：最终键值表，空表输出 {}。
	FinalKV map[string]string `json:"finalKV"`
	// FinalApplyError 仅在启用 applyKV 时出现：null 或第一条已提交的格式错误。
	FinalApplyError *ApplyError `json:"finalApplyError"`

	// kvEnabled 控制 JSON 是否包含键值字段，不对外暴露。
	kvEnabled bool
}

// MarshalJSON 按是否启用 applyKV 输出不同字段集：未启用时与旧输出完全一致。
func (o ReplicateOutput) MarshalJSON() ([]byte, error) {
	if !o.kvEnabled {
		type plain struct {
			Results             []AppendResult `json:"results"`
			FinalTerm           int            `json:"finalTerm"`
			FinalCommittedIndex int            `json:"finalCommittedIndex"`
			FinalLog            []LogEntry     `json:"finalLog"`
		}
		return json.Marshal(plain{o.Results, o.FinalTerm, o.FinalCommittedIndex, o.FinalLog})
	}
	type enabled struct {
		Results             []AppendResult    `json:"results"`
		FinalTerm           int               `json:"finalTerm"`
		FinalCommittedIndex int               `json:"finalCommittedIndex"`
		FinalLog            []LogEntry        `json:"finalLog"`
		FinalAppliedIndex   int               `json:"finalAppliedIndex"`
		FinalKV             map[string]string `json:"finalKV"`
		FinalApplyError     *ApplyError       `json:"finalApplyError"`
	}
	return json.Marshal(enabled{
		Results:             o.Results,
		FinalTerm:           o.FinalTerm,
		FinalCommittedIndex: o.FinalCommittedIndex,
		FinalLog:            o.FinalLog,
		FinalAppliedIndex:   o.FinalAppliedIndex,
		FinalKV:             o.FinalKV,
		FinalApplyError:     o.FinalApplyError,
	})
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

// Replicate 校验初始状态并顺序应用全部复制请求，返回逐次结果与最终状态。
// 初始状态非法时返回错误（调用方应以非零退出码结束）。单条请求违反字段规则
// 时只记录一次拒绝、不改变任何状态，随后继续处理下一条请求。
//
// 当初始状态启用 ApplyKV 时，已提交的命令会被解释为 set/delete 键值操作：
// 先应用初始日志中已提交的前缀，再在每条请求处理结束后应用新提交且尚未应用
// 的条目。已提交命令出现格式错误时，应用停在出错条目之前且本次调用不再继续；
// 未提交条目的格式错误不会提前报错。
func Replicate(initial InitialState, requests []AppendRequest) (ReplicateOutput, error) {
	state, err := newReplicateState(initial)
	if err != nil {
		return ReplicateOutput{}, err
	}

	output := ReplicateOutput{
		Results:  make([]AppendResult, 0, len(requests)),
		FinalLog: []LogEntry{},
	}
	if initial.ApplyKV {
		output.kvEnabled = true
		output.FinalKV = map[string]string{}
		// 先按索引顺序应用初始日志中已提交的前缀。
		output.FinalAppliedIndex, output.FinalApplyError =
			applyCommitted(state.log, state.committedIndex, output.FinalKV, 0)
	}

	for _, request := range requests {
		result := state.apply(request)
		if initial.ApplyKV {
			result.kvEnabled = true
			// 每条请求处理结束后，只应用新提交且尚未应用的日志；
			// 一旦出错，本次调用的应用状态保持停住。
			if output.FinalApplyError == nil {
				output.FinalAppliedIndex, output.FinalApplyError = applyCommitted(
					state.log, state.committedIndex, output.FinalKV, output.FinalAppliedIndex)
			}
			result.AppliedIndex = output.FinalAppliedIndex
			result.ApplyError = output.FinalApplyError
		}
		output.Results = append(output.Results, result)
	}

	output.FinalTerm = state.currentTerm
	output.FinalCommittedIndex = state.committedIndex
	output.FinalLog = append([]LogEntry{}, state.log...)
	if output.FinalLog == nil {
		output.FinalLog = []LogEntry{}
	}
	return output, nil
}

// applyCommitted 顺序应用索引在 (appliedIndex, committedIndex] 内的已提交日志。
// 出错时保留此前成功应用的结果，appliedIndex 停在出错条目之前，出错条目及其后
// 所有条目都不执行。返回新的已应用最高索引与第一条格式错误（无错误时为 nil）。
func applyCommitted(log []LogEntry, committedIndex int, kv map[string]string, appliedIndex int) (int, *ApplyError) {
	for idx := appliedIndex + 1; idx <= committedIndex; idx++ {
		if reason, ok := applyCommand(log[idx-1].Command, kv); !ok {
			return idx - 1, &ApplyError{Index: idx, Reason: reason}
		}
		appliedIndex = idx
	}
	return appliedIndex, nil
}

// applyCommand 解析并执行一条键值命令。命令区分大小写，只接受两种形式：
//
//	set <key>=<value>   写入或覆盖一个键，值以原文保留（可为空、含空格或额外等号）
//	delete <key>        删除一个键，删除不存在的键也算成功
//
// 命令名后必须恰好有一个普通空格；键不能为空，不能含空白或等号；命令两端的
// 空白不会被自动去掉。返回的 ok 为 false 时，reason 描述具体的格式问题。
func applyCommand(command string, kv map[string]string) (reason string, ok bool) {
	switch {
	case strings.HasPrefix(command, "set"):
		if len(command) == 3 || command[3] != ' ' {
			return `malformed command: "set" must be followed by exactly one space`, false
		}
		rest := command[4:]
		end := keyEnd(rest)
		if end == 0 {
			return "malformed command: empty key", false
		}
		if end == len(rest) || rest[end] != '=' {
			if end < len(rest) && rest[end] != '=' {
				return "malformed command: key contains whitespace", false
			}
			return `malformed command: "set" requires "=" after key`, false
		}
		kv[rest[:end]] = rest[end+1:]
		return "", true
	case strings.HasPrefix(command, "delete"):
		if len(command) == 6 || command[6] != ' ' {
			return `malformed command: "delete" must be followed by exactly one space`, false
		}
		rest := command[7:]
		end := keyEnd(rest)
		if end == 0 {
			return "malformed command: empty key", false
		}
		if end < len(rest) {
			if rest[end] == '=' {
				return `malformed command: key contains "="`, false
			}
			return "malformed command: key contains whitespace", false
		}
		delete(kv, rest)
		return "", true
	default:
		return `malformed command: expected "set <key>=<value>" or "delete <key>"`, false
	}
}

// keyEnd 返回键的结束位置（字节偏移）：第一个 '=' 或空白的位置，
// 或整个字符串长度（二者皆无）。
func keyEnd(s string) int {
	for i, r := range s {
		if r == '=' || unicode.IsSpace(r) {
			return i
		}
	}
	return len(s)
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
	for i, entry := range log {
		expected := i + 1
		if entry.Index != expected {
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d has non-consecutive index %d", expected, entry.Index)
		}
		if entry.Term <= 0 {
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d has non-positive term %d", expected, entry.Term)
		}
		if i > 0 && entry.Term < log[i-1].Term {
			return replicateState{}, fmt.Errorf("invalid initial state: log entry %d term %d is lower than previous term %d", expected, entry.Term, log[i-1].Term)
		}
		if entry.Term > initial.CurrentTerm {
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

// apply 处理单条请求。整个操作是原子的：任何拒绝都不会在日志、已提交索引上
// 留下部分变更；唯一例外是较高任期带来的 currentTerm 更新，按规则必须保留。
func (s *replicateState) apply(request AppendRequest) AppendResult {
	snapshot := *s
	accepted, reason := s.tryApply(request)
	if !accepted {
		// 回滚日志与提交位置；较高任期更新（若已发生）保留在 s.currentTerm 中。
		s.log = snapshot.log
		s.committedIndex = snapshot.committedIndex
	}
	return AppendResult{
		Accepted:       accepted,
		Reason:         reason,
		Term:           s.currentTerm,
		CommittedIndex: s.committedIndex,
	}
}

func (s *replicateState) tryApply(request AppendRequest) (bool, string) {
	// 规则 1：先做字段合法性校验。违反字段规则的请求只记录拒绝、不改变任何
	// 状态——即使它携带更高任期，也不能更新节点。
	if reason := validateRequest(request); reason != ReasonOK {
		return false, reason
	}

	// 规则 2：较低任期直接拒绝，状态（含任期）完全不变。
	if request.Term < s.currentTerm {
		return false, ReasonStaleTerm
	}

	// 规则 3：首条目任期不得低于前一条日志任期（整段日志必须不下降）。
	// 这仍属于字段规则，放在任期更新之前：非法请求不能借高任期改变节点。
	if len(request.Entries) > 0 && request.Entries[0].Term < request.PrevLogTerm {
		return false, ReasonEntryTermDecreases
	}

	// 规则 4：较高任期先更新当前任期，再核对日志；之后即便因前缀不匹配被拒，
	// 任期更新也保留。
	if request.Term > s.currentTerm {
		s.currentTerm = request.Term
	}

	// 规则 5：前一条日志必须存在且任期相同。索引 0 始终只与任期 0 匹配。
	prevTerm, ok := s.termAt(request.PrevLogIndex)
	if !ok || prevTerm != request.PrevLogTerm {
		return false, ReasonPrevLogMismatch
	}

	// 规则 6：把待追加条目与现有位置逐一比对——全部检查通过后才落笔，
	// 保证“即使前面已发现可追加内容，也不能留下部分变更”。第一个任期冲突
	// 位置之后的旧日志都会被整段替换，因此只需在冲突位置之前检查命令冲突。
	// matched 是请求条目中与现有位置完全相同（同任期同命令）的连续前缀长度；
	// 超出本地日志长度的位置尚不存在，不属于已匹配，稍后追加。
	start := request.PrevLogIndex // entries[k] 对应索引 start+1+k
	cutAt := -1                   // 首个任期不同的现有位置（切片下标）
	matched := 0
	for offset, incoming := range request.Entries {
		idx := start + 1 + offset
		if idx > len(s.log) {
			break // 该位置及之后都不存在：稍后整体追加
		}
		existing := s.log[idx-1]
		switch {
		case existing.Term == incoming.Term && existing.Command == incoming.Command:
			// 完全相同：保留，重复请求不会产生重复条目。
			matched++
		case existing.Term == incoming.Term:
			// 同索引同任期却命令不同：拒绝，日志与提交位置保持原样。
			return false, ReasonCommandConflictSameTerm
		case idx <= s.committedIndex:
			// 不同任期意味着要覆盖该处及其后缀；已提交条目不可覆盖。
			return false, ReasonWouldOverwriteCommitted
		default:
			// 未提交位置上的任期冲突：截断到此处再追加，其后旧日志整段丢弃。
			cutAt = idx - 1
		}
		if cutAt >= 0 {
			break
		}
	}

	// 规则 7：合并日志。全部匹配的短请求（matched == len(entries)）不删除
	// 本地多出的尾部；任期冲突时截断冲突位置及其后缀；其余缺失位置追加。
	if cutAt >= 0 {
		matched = cutAt - start
		s.log = append([]LogEntry(nil), s.log[:cutAt]...)
	}
	if matched < len(request.Entries) {
		s.log = append(s.log, request.Entries[matched:]...)
	}

	// 规则 8：提交位置推进至 leaderCommit 与本次确认的最后索引的较小值，
	// 且不会后退。空条目请求的确认位置就是前一条索引。
	lastIndex := request.PrevLogIndex + len(request.Entries)
	newCommit := request.LeaderCommit
	if lastIndex < newCommit {
		newCommit = lastIndex
	}
	if newCommit > s.committedIndex {
		s.committedIndex = newCommit
	}
	return true, ReasonOK
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
	// tryApply 中单独检查。索引 0 是哨兵，真实条目索引必为正。
	for i, entry := range request.Entries {
		if entry.Index != request.PrevLogIndex+1+i {
			return ReasonEntryIndexGap
		}
		if entry.Term <= 0 {
			return ReasonEmptyEntryTerm
		}
		if i > 0 && entry.Term < request.Entries[i-1].Term {
			return ReasonEntryTermDecreases
		}
		if entry.Term > request.Term {
			return ReasonEntryTermExceedsReqTerm
		}
	}
	return ReasonOK
}
