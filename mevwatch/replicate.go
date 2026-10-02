// Package mevwatch implements mempool risk detection.
package mevwatch

import (
	"errors"
	"fmt"
)

// LogEntry is one entry in the replicated log. Indexes start at 1 and are
// contiguous; index 0 with term 0 denotes the log origin, not a real entry.
type LogEntry struct {
	Index   int    `json:"index"`
	Term    int    `json:"term"`
	Command string `json:"command"`
}

// AppendEntry is one entry carried by a replication request. Its index is
// implicit: the first entry in the slice sits at prev_log_index+1, and the
// slice is contiguous (gaps are not representable).
type AppendEntry struct {
	Term    int    `json:"term"`
	Command string `json:"command"`
}

// InitialState is the follower state before any request is applied.
type InitialState struct {
	CurrentTerm int        `json:"current_term"`
	CommitIndex int        `json:"commit_index"`
	Log         []LogEntry `json:"log"`
}

// ReplicationRequest is one leader replication request (Raft AppendEntries).
type ReplicationRequest struct {
	LeaderTerm   int           `json:"leader_term"`
	PrevLogIndex int           `json:"prev_log_index"`
	PrevLogTerm  int           `json:"prev_log_term"`
	Entries      []AppendEntry `json:"entries"`
	LeaderCommit int           `json:"leader_commit"`
}

// ReplicateInput is the document consumed by the replicate command.
type ReplicateInput struct {
	InitialState InitialState         `json:"initial_state"`
	Requests     []ReplicationRequest `json:"requests"`
}

// Reason codes for request outcomes.
const (
	// ReasonOK marks a successfully applied request.
	ReasonOK = "ok"
	// ReasonLowerTerm: leader term is below current term; state untouched.
	ReasonLowerTerm = "lower_term"
	// ReasonInvalidRequest: request violates field rules; state untouched,
	// including the term (a higher term must not be adopted).
	ReasonInvalidRequest = "invalid_request"
	// ReasonPrevLogMissing: prev_log_index is beyond the local log.
	ReasonPrevLogMissing = "prev_log_missing"
	// ReasonPrevLogTermMismatch: local entry at prev_log_index has a
	// different term (or index 0 is paired with a nonzero term).
	ReasonPrevLogTermMismatch = "prev_log_term_mismatch"
	// ReasonCommandMismatch: same index and term but different command.
	ReasonCommandMismatch = "command_mismatch"
	// ReasonCommittedOverwrite: resolving a term conflict would overwrite a
	// committed entry.
	ReasonCommittedOverwrite = "committed_overwrite"
)

// RequestResult is the outcome of one replication request.
type RequestResult struct {
	OK          bool   `json:"ok"`
	Reason      string `json:"reason"`
	Message     string `json:"message"`
	Term        int    `json:"term"`
	CommitIndex int    `json:"commit_index"`
}

// ReplicateOutput is the document returned by the replicate command.
type ReplicateOutput struct {
	Results     []RequestResult `json:"results"`
	Term        int             `json:"term"`
	CommitIndex int             `json:"commit_index"`
	Log         []LogEntry      `json:"log"`
}

// Replicate validates the initial follower state and applies the request
// sequence in order. It is a pure function: identical inputs yield identical
// outputs, and no network or process state is touched.
func Replicate(in ReplicateInput) (ReplicateOutput, error) {
	if err := ValidateInitialState(in.InitialState); err != nil {
		return ReplicateOutput{}, err
	}
	s := &follower{
		term:   in.InitialState.CurrentTerm,
		commit: in.InitialState.CommitIndex,
		log:    append([]LogEntry(nil), in.InitialState.Log...),
	}
	out := ReplicateOutput{
		Results: make([]RequestResult, 0, len(in.Requests)),
		Log:     []LogEntry{},
	}
	for _, req := range in.Requests {
		out.Results = append(out.Results, s.apply(req))
	}
	out.Term = s.term
	out.CommitIndex = s.commit
	out.Log = append([]LogEntry(nil), s.log...)
	return out, nil
}

type follower struct {
	term   int
	commit int
	log    []LogEntry
}

func (s *follower) apply(req ReplicationRequest) RequestResult {
	// Field rules are checked before anything else: an invalid request must
	// not move the term even if it carries a higher leader term.
	if err := ValidateRequest(req); err != nil {
		return reject(ReasonInvalidRequest, err.Error(), s.term, s.commit)
	}
	if req.LeaderTerm < s.term {
		return reject(ReasonLowerTerm,
			fmt.Sprintf("领导者任期 %d 低于当前任期 %d，拒绝复制且状态不变", req.LeaderTerm, s.term),
			s.term, s.commit)
	}
	if req.LeaderTerm > s.term {
		// Adopt the higher term before checking the log, so a prefix
		// mismatch still leaves the term update in place.
		s.term = req.LeaderTerm
	}

	// Prefix check. Index 0 is the log origin and only matches term 0.
	if req.PrevLogIndex == 0 {
		if req.PrevLogTerm != 0 {
			return reject(ReasonPrevLogTermMismatch,
				fmt.Sprintf("索引 0 是日志起点，只与任期 0 匹配，收到任期 %d", req.PrevLogTerm),
				s.term, s.commit)
		}
	} else if req.PrevLogIndex > len(s.log) {
		return reject(ReasonPrevLogMissing,
			fmt.Sprintf("前一条日志索引 %d 不存在（当前日志长度 %d）", req.PrevLogIndex, len(s.log)),
			s.term, s.commit)
	} else if s.log[req.PrevLogIndex-1].Term != req.PrevLogTerm {
		return reject(ReasonPrevLogTermMismatch,
			fmt.Sprintf("索引 %d 处日志任期为 %d，请求声称 %d", req.PrevLogIndex, s.log[req.PrevLogIndex-1].Term, req.PrevLogTerm),
			s.term, s.commit)
	}

	// Prefix matched. Build the candidate log on a copy and only commit it
	// after the whole batch validates, so a rejection leaves log and commit
	// index untouched even if appendable content was already found.
	newLog := append([]LogEntry(nil), s.log...)
	conflictAt := -1
	for i, e := range req.Entries {
		idx := req.PrevLogIndex + i + 1
		if idx > len(newLog) {
			newLog = append(newLog, LogEntry{Index: idx, Term: e.Term, Command: e.Command})
			continue
		}
		old := newLog[idx-1]
		if old.Term == e.Term {
			if old.Command != e.Command {
				return reject(ReasonCommandMismatch,
					fmt.Sprintf("索引 %d 处任期相同（%d）但命令不同：本地 %q，请求 %q", idx, e.Term, old.Command, e.Command),
					s.term, s.commit)
			}
			continue
		}
		// Different term at an existing index.
		if idx <= s.commit {
			return reject(ReasonCommittedOverwrite,
				fmt.Sprintf("索引 %d 处任期冲突（本地 %d，请求 %d），且该索引已提交（提交位置 %d）", idx, old.Term, e.Term, s.commit),
				s.term, s.commit)
		}
		conflictAt = idx
		break
	}
	if conflictAt > 0 {
		// Replace the conflicting entry and everything after it.
		newLog = newLog[:conflictAt-1]
		for j := conflictAt - req.PrevLogIndex - 1; j < len(req.Entries); j++ {
			idx := req.PrevLogIndex + j + 1
			newLog = append(newLog, LogEntry{Index: idx, Term: req.Entries[j].Term, Command: req.Entries[j].Command})
		}
	}
	s.log = newLog

	// Commit advances to min(leaderCommit, last confirmed index), never
	// backwards. An empty batch confirms only prevLogIndex, so extra local
	// tail entries are kept but not committed.
	lastConfirmed := req.PrevLogIndex + len(req.Entries)
	commitCap := req.LeaderCommit
	if lastConfirmed < commitCap {
		commitCap = lastConfirmed
	}
	if commitCap > s.commit {
		s.commit = commitCap
	}
	return RequestResult{OK: true, Reason: ReasonOK, Message: "复制成功", Term: s.term, CommitIndex: s.commit}
}

func reject(reason, message string, term, commit int) RequestResult {
	return RequestResult{OK: false, Reason: reason, Message: message, Term: term, CommitIndex: commit}
}

// ValidateInitialState checks the follower state against the field rules:
// nonnegative term/commit, contiguous indexes from 1, positive non-decreasing
// entry terms not above the current term, and commit index within the log.
func ValidateInitialState(st InitialState) error {
	if st.CurrentTerm < 0 {
		return errors.New("初始状态非法：current_term 不能为负")
	}
	if st.CommitIndex < 0 {
		return errors.New("初始状态非法：commit_index 不能为负")
	}
	prevTerm := 0
	for i, e := range st.Log {
		if e.Index != i+1 {
			return fmt.Errorf("初始状态非法：日志第 %d 个条目的索引应为 %d，实际为 %d", i+1, i+1, e.Index)
		}
		if e.Term <= 0 {
			return fmt.Errorf("初始状态非法：索引 %d 的条目任期必须为正数，实际为 %d", e.Index, e.Term)
		}
		if e.Term < prevTerm {
			return fmt.Errorf("初始状态非法：日志任期沿索引不下降，索引 %d 的任期 %d 小于前一条任期 %d", e.Index, e.Term, prevTerm)
		}
		if e.Term > st.CurrentTerm {
			return fmt.Errorf("初始状态非法：索引 %d 的条目任期 %d 超过当前任期 %d", e.Index, e.Term, st.CurrentTerm)
		}
		prevTerm = e.Term
	}
	if st.CommitIndex > len(st.Log) {
		return fmt.Errorf("初始状态非法：已提交索引 %d 超过日志长度 %d", st.CommitIndex, len(st.Log))
	}
	return nil
}

// ValidateRequest checks one replication request against the field rules:
// nonnegative term/index/commit, positive non-decreasing entry terms not
// above the request term.
func ValidateRequest(req ReplicationRequest) error {
	if req.LeaderTerm < 0 {
		return errors.New("请求非法：leader_term 不能为负")
	}
	if req.PrevLogIndex < 0 {
		return errors.New("请求非法：prev_log_index 不能为负")
	}
	if req.PrevLogTerm < 0 {
		return errors.New("请求非法：prev_log_term 不能为负")
	}
	if req.LeaderCommit < 0 {
		return errors.New("请求非法：leader_commit 不能为负")
	}
	prevTerm := 0
	for i, e := range req.Entries {
		if e.Term <= 0 {
			return fmt.Errorf("请求非法：第 %d 个待追加条目（索引 %d）的任期必须为正数，实际为 %d", i+1, req.PrevLogIndex+i+1, e.Term)
		}
		if e.Term < prevTerm {
			return fmt.Errorf("请求非法：待追加条目任期沿索引不下降，索引 %d 的任期 %d 小于前一条任期 %d", req.PrevLogIndex+i+1, e.Term, prevTerm)
		}
		if e.Term > req.LeaderTerm {
			return fmt.Errorf("请求非法：索引 %d 的条目任期 %d 超过请求任期 %d", req.PrevLogIndex+i+1, e.Term, req.LeaderTerm)
		}
		prevTerm = e.Term
	}
	return nil
}
