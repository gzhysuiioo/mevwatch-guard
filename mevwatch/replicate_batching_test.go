package mevwatch

import (
	"reflect"
	"testing"
)

// 本文件是“复制请求如何分批，不改变同一段已提交日志最终生效的键值结果”的回归
// 保障：在相同的合法初始状态下送达同一段日志（每条日志的索引、任期、命令与顺序
// 完全相同），比较整段一次送达、切成多次连续请求送达，以及先复制完整日志、再用
// 空条目请求推进提交这几种正常使用方式。
//
// 每种分批方式都必须满足：
//   - 各次复制都被接受（reason ok），且逐条结果始终使用相同的领导者任期；
//   - 最终确认的日志范围与提交位置相同，完整日志（含最终提交范围以外、当时尚未
//     提交的条目）也相同；
//   - 逐条答复中的提交位置只向前推进、不超过最终位置，且只反映各自请求处理结束
//     时的状态——分批后请求数量与提交时机不同，不要求逐答复彼此相同；
//   - 开启 applyKV 后，最终日志、当前任期、提交位置、应用位置、键值表与首个应用
//     错误在所有分批方式之间一致；应用位置同样只向前、不超过最终提交位置。
//
// 重点覆盖依赖先前值的增量命令：初始已提交日志把 count 设为字符串 "10"，随后
// 依次是 incr count=5 与 incr count=-2，切分位置落在两次累加之间、或者复制全部
// 完成后才提交，都不能造成漏加、重复累加或把初始值重新写回，最终值必须为 "13"。

// batchLeaderTerm 是本文件所有分批场景共用的领导者任期：初始当前任期与其相同，
// 因此任何一条合法答复的任期都必须保持为该值。
const batchLeaderTerm = 2

// batchingInitial 是分批回归场景共用的合法初始状态：当前任期 2，idx1（任期 1，
// set count=10）已提交——计数初始为字符串 "10"。
func batchingInitial() InitialState {
	return InitialState{CurrentTerm: batchLeaderTerm, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set count=10"),
	}}
}

// appendSeg 构造一次携带条目的复制请求：任期固定为共用的领导者任期，前置索引与
// 任期、领导者提交位置由调用方给出，条目必须从 prevIndex+1 开始连续排列。
func appendSeg(prevIndex, prevTerm, leaderCommit int, entries ...LogEntry) AppendRequest {
	return AppendRequest{
		Term:         batchLeaderTerm,
		PrevLogIndex: prevIndex,
		PrevLogTerm:  prevTerm,
		LeaderCommit: leaderCommit,
		Entries:      entries,
	}
}

// heartbeatSeg 构造一次不携带条目的复制请求（空条目心跳），仅用于推进提交位置。
func heartbeatSeg(prevIndex, prevTerm, leaderCommit int) AppendRequest {
	return AppendRequest{
		Term:         batchLeaderTerm,
		PrevLogIndex: prevIndex,
		PrevLogTerm:  prevTerm,
		LeaderCommit: leaderCommit,
	}
}

// batchStepExpect 是某一种分批方式中逐条请求在“该次请求处理结束时”应有的状态：
// commit 为提交位置，applied 为应用位置（仅 applyKV 模式检查），errIdx 为首个
// 应用错误指向的日志索引，0 表示当时没有应用错误。
type batchStepExpect struct {
	commit  int
	applied int
	errIdx  int
}

// assertBatchVariant 跑完一种分批方式并断言逐次答复：每次复制都被接受、原因固定
// 为 ok、答复任期始终是同一个领导者任期；提交位置与（开启 applyKV 时的）应用
// 位置严格按预期逐次推进、只向前且不超过最终位置；应用错误恰在提交覆盖非法条目
// 的那次请求出现，之后一直保留。未开启 applyKV 时答复不得出现任何应用字段。
// 返回整次调用输出，供调用方比较最终状态。
func assertBatchVariant(t *testing.T, initial InitialState, requests []AppendRequest,
	steps []batchStepExpect, applyKV bool) ReplicateOutput {
	t.Helper()
	var out ReplicateOutput
	var err error
	if applyKV {
		out, err = ReplicateWithOptions(initial, requests, ReplicateOptions{ApplyKV: true})
	} else {
		out, err = Replicate(initial, requests)
	}
	if err != nil {
		t.Fatalf("Replicate applyKV=%v returned error: %v", applyKV, err)
	}
	if len(out.Results) != len(steps) {
		t.Fatalf("got %d results, want %d", len(out.Results), len(steps))
	}
	prevCommit := initial.CommittedIndex
	prevApplied := initial.CommittedIndex // 初始已提交前缀在调用开始时即已应用
	for i, want := range steps {
		result := out.Results[i]
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("applyKV=%v step %d: every replication must be accepted, got %+v",
				applyKV, i, result)
		}
		if result.Term != batchLeaderTerm {
			t.Fatalf("applyKV=%v step %d: term = %d, want the same leader term %d",
				applyKV, i, result.Term, batchLeaderTerm)
		}
		if result.CommittedIndex != want.commit {
			t.Fatalf("applyKV=%v step %d: committedIndex = %d, want %d (point-in-time state)",
				applyKV, i, result.CommittedIndex, want.commit)
		}
		// 提交位置只向前推进，且任何中间位置都不超过最终位置。
		if result.CommittedIndex < prevCommit {
			t.Fatalf("applyKV=%v step %d: commit moved backward %d -> %d",
				applyKV, i, prevCommit, result.CommittedIndex)
		}
		if result.CommittedIndex > out.FinalCommittedIndex {
			t.Fatalf("applyKV=%v step %d: intermediate commit %d exceeds final %d",
				applyKV, i, result.CommittedIndex, out.FinalCommittedIndex)
		}
		prevCommit = result.CommittedIndex

		if !applyKV {
			if result.AppliedIndex != nil || result.ApplyError != nil {
				t.Fatalf("applyKV disabled: step %d must omit apply fields, got %+v", i, result)
			}
			continue
		}
		if got := appliedIndexOf(t, result); got != want.applied {
			t.Fatalf("step %d: appliedIndex = %d, want %d (point-in-time state)",
				i, got, want.applied)
		}
		if got := *result.AppliedIndex; got < prevApplied {
			t.Fatalf("step %d: applied index moved backward %d -> %d", i, prevApplied, got)
		}
		if got := *result.AppliedIndex; got > result.CommittedIndex {
			t.Fatalf("step %d: applied index %d exceeds committed index %d", i, got, result.CommittedIndex)
		}
		prevApplied = *result.AppliedIndex
		switch {
		case want.errIdx == 0:
			if result.ApplyError != nil {
				t.Fatalf("step %d: unexpected apply error before the bad entry is committed: %+v",
					i, result.ApplyError)
			}
		default:
			if result.ApplyError == nil || result.ApplyError.Index != want.errIdx ||
				result.ApplyError.Reason != ApplyReasonIncrBadDelta {
				t.Fatalf("step %d: applyError = %+v, want index %d with %q",
					i, result.ApplyError, want.errIdx, ApplyReasonIncrBadDelta)
			}
		}
	}
	if out.FinalCommittedIndex != prevCommit {
		t.Fatalf("final committedIndex = %d, want last step value %d",
			out.FinalCommittedIndex, prevCommit)
	}
	return out
}

// assertSameBatchFinals 断言两种分批方式的最终状态完全一致：最终日志（完整日志，
// 含最终提交范围以外的条目）、当前任期与提交位置必须相同；开启 applyKV 时，最终
// 应用位置、键值表与首个应用错误也必须相同。
func assertSameBatchFinals(t *testing.T, got, want ReplicateOutput, applyKV bool) {
	t.Helper()
	if got.FinalTerm != want.FinalTerm || got.FinalCommittedIndex != want.FinalCommittedIndex {
		t.Fatalf("final replication state = term %d ci %d, want term %d ci %d",
			got.FinalTerm, got.FinalCommittedIndex, want.FinalTerm, want.FinalCommittedIndex)
	}
	if !reflect.DeepEqual(got.FinalLog, want.FinalLog) {
		t.Fatalf("final log differs by batching:\n got %+v\nwant %+v", got.FinalLog, want.FinalLog)
	}
	if !applyKV {
		if got.FinalAppliedIndex != nil || got.FinalKV != nil || got.FinalApplyError != nil {
			t.Fatalf("applyKV disabled: output must omit final apply fields, got %+v", got)
		}
		return
	}
	if *got.FinalAppliedIndex != *want.FinalAppliedIndex {
		t.Fatalf("final appliedIndex = %d, want %d", *got.FinalAppliedIndex, *want.FinalAppliedIndex)
	}
	if gotKV, wantKV := finalKVOf(t, got), finalKVOf(t, want); !reflect.DeepEqual(gotKV, wantKV) {
		t.Fatalf("final kv differs by batching: got %v, want %v", gotKV, wantKV)
	}
	if !reflect.DeepEqual(got.FinalApplyError, want.FinalApplyError) {
		t.Fatalf("final applyError differs by batching: got %+v, want %+v",
			got.FinalApplyError, want.FinalApplyError)
	}
}

// TestReplicateBatchingConvergesSameKV 回归保障合法日志在不同分批方式下最终生效
// 结果一致。初始已提交的 set count=10 之后依次复制 incr count=5、incr count=-2
// 与一条合法写入 set marker=done：
//   - 整段一次送达，提交位置随整段请求直接到 4；
//   - 切分点落在两次累加之间：第一次只复制 incr count=5 且不提交，第二次携带余下
//     两条并提交；
//   - 每条日志一个请求，前两个请求都不推进提交；
//   - 先把整段日志复制完（完全不提交），再用空条目请求把提交位置推进到 4。
//
// 四种方式最终都必须是 count="13"（10+5-2，既不漏加也不重复累加、更不会重新
// 写回初始值 "10"）、marker="done"，应用位置到达最后一条 idx4，且无应用错误。
func TestReplicateBatchingConvergesSameKV(t *testing.T) {
	initial := batchingInitial()
	incrFive := entry(2, batchLeaderTerm, "incr count=5")
	incrMinusTwo := entry(3, batchLeaderTerm, "incr count=-2")
	setMarker := entry(4, batchLeaderTerm, "set marker=done")

	cases := []struct {
		name     string
		requests []AppendRequest
		steps    []batchStepExpect
	}{
		{
			"whole segment delivered and committed in one request",
			[]AppendRequest{appendSeg(1, 1, 4, incrFive, incrMinusTwo, setMarker)},
			[]batchStepExpect{{commit: 4, applied: 4}},
		},
		{
			"split between the two increments, commit only with the second request",
			[]AppendRequest{
				appendSeg(1, 1, 0, incrFive),
				appendSeg(2, batchLeaderTerm, 4, incrMinusTwo, setMarker),
			},
			[]batchStepExpect{
				{commit: 1, applied: 1}, // 只复制未提交：不累加
				{commit: 4, applied: 4},
			},
		},
		{
			"one entry per request, last request commits",
			[]AppendRequest{
				appendSeg(1, 1, 0, incrFive),
				appendSeg(2, batchLeaderTerm, 0, incrMinusTwo),
				appendSeg(3, batchLeaderTerm, 4, setMarker),
			},
			[]batchStepExpect{
				{commit: 1, applied: 1},
				{commit: 1, applied: 1},
				{commit: 4, applied: 4},
			},
		},
		{
			"replicate whole segment uncommitted, then advance commit with empty entries",
			[]AppendRequest{
				appendSeg(1, 1, 0, incrFive, incrMinusTwo, setMarker),
				heartbeatSeg(4, batchLeaderTerm, 4),
			},
			[]batchStepExpect{
				{commit: 1, applied: 1}, // 完整日志已在本地，但一条都没提交
				{commit: 4, applied: 4},
			},
		},
	}

	var baselineKV, baselinePlain ReplicateOutput
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kvOut := assertBatchVariant(t, initial, tc.requests, tc.steps, true)
			plainOut := assertBatchVariant(t, initial, tc.requests, tc.steps, false)
			if i == 0 {
				baselineKV, baselinePlain = kvOut, plainOut
			} else {
				assertSameBatchFinals(t, kvOut, baselineKV, true)
				assertSameBatchFinals(t, plainOut, baselinePlain, false)
			}
		})
	}

	// 共同的最终状态：完整日志四条、任期 2、提交到 4；键值表中两次增量恰如其分
	// 地各生效一次，count 为 "13"，应用位置到达最后一条，无应用错误。
	wantLog := []LogEntry{
		entry(1, 1, "set count=10"),
		incrFive, incrMinusTwo, setMarker,
	}
	if !reflect.DeepEqual(baselineKV.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", baselineKV.FinalLog, wantLog)
	}
	if baselineKV.FinalTerm != batchLeaderTerm || baselineKV.FinalCommittedIndex != 4 {
		t.Fatalf("final state = term %d ci %d, want term %d ci 4",
			baselineKV.FinalTerm, baselineKV.FinalCommittedIndex, batchLeaderTerm)
	}
	if *baselineKV.FinalAppliedIndex != 4 {
		t.Fatalf("final appliedIndex = %d, want 4 (last entry)", *baselineKV.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, baselineKV); !reflect.DeepEqual(kv, map[string]string{
		"count":  "13",
		"marker": "done",
	}) {
		t.Fatalf("final kv = %v, want count=13 and marker=done", kv)
	}
	if baselineKV.FinalApplyError != nil {
		t.Fatalf("unexpected final apply error: %+v", baselineKV.FinalApplyError)
	}

	// 先复制不提交时的中间快照：最终提交范围以外的三条日志都保留在完整日志中，
	// 但不能提前影响键值表——计数仍是初始的 "10"，marker 不存在，提交与应用
	// 位置停在 idx1，也没有任何应用错误。
	stopped := runKV(t, initial, appendSeg(1, 1, 0, incrFive, incrMinusTwo, setMarker))
	if len(stopped.Results) != 1 || !stopped.Results[0].Accepted {
		t.Fatalf("uncommitted replication must be accepted: %+v", stopped.Results)
	}
	if len(stopped.FinalLog) != 4 {
		t.Fatalf("entries beyond final commit must stay in the full log, got %+v", stopped.FinalLog)
	}
	if stopped.FinalCommittedIndex != 1 || *stopped.FinalAppliedIndex != 1 {
		t.Fatalf("stopped state = ci %d applied %d, want 1/1",
			stopped.FinalCommittedIndex, *stopped.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, stopped); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("uncommitted entries affected the kv table: %v, want only count=10", kv)
	}
	if stopped.FinalApplyError != nil {
		t.Fatalf("uncommitted entries produced an apply error: %+v", stopped.FinalApplyError)
	}
}

// TestReplicateBatchingWithCommittedBadIncr 回归保障已提交日志中出现非法增量时，
// 分批一致性同样成立。两次合法累加之后接 incr count=oops（增量不是有符号十进制
// 整数），再接一条合法写入 set after=1。无论非法命令与其前后条目是否处于同一个
// 请求，也无论提交随哪个请求发生：
//   - 每次复制都正常接受，答复任期始终相同；提交它以后，后续合法复制仍被接受并
//     继续推进提交位置——应用停滞不能被误当成复制拒绝；
//   - 分批过程中非法条目尚未提交时，不提前产生应用错误；
//   - 最终都保留 count="13"（idx2/idx3 的两次累加恰各生效一次），应用位置停在
//     非法条目 idx4 之前的 idx3，首个应用错误指向 idx4 且原因固定为现有的增量
//     格式错误；idx5 的写入不生效（after 不得进入键值表）；
//   - 最终完整日志仍保留全部五条（含非法条目与其后的写入）。
func TestReplicateBatchingWithCommittedBadIncr(t *testing.T) {
	initial := batchingInitial()
	incrFive := entry(2, batchLeaderTerm, "incr count=5")
	incrMinusTwo := entry(3, batchLeaderTerm, "incr count=-2")
	badIncr := entry(4, batchLeaderTerm, "incr count=oops")
	setAfter := entry(5, batchLeaderTerm, "set after=1")

	cases := []struct {
		name     string
		requests []AppendRequest
		steps    []batchStepExpect
	}{
		{
			"whole segment including the bad incr and the later write in one request",
			[]AppendRequest{appendSeg(1, 1, 5, incrFive, incrMinusTwo, badIncr, setAfter)},
			[]batchStepExpect{{commit: 5, applied: 3, errIdx: 4}},
		},
		{
			"bad incr and later write replicated together after the increments committed",
			[]AppendRequest{
				appendSeg(1, 1, 3, incrFive, incrMinusTwo),
				appendSeg(3, batchLeaderTerm, 5, badIncr, setAfter),
			},
			[]batchStepExpect{
				{commit: 3, applied: 3}, // 两次累加先提交：count=13，尚无错误
				{commit: 5, applied: 3, errIdx: 4},
			},
		},
		{
			"bad incr committed with the increments, later write in a following request",
			[]AppendRequest{
				appendSeg(1, 1, 4, incrFive, incrMinusTwo, badIncr),
				appendSeg(4, batchLeaderTerm, 5, setAfter),
			},
			[]batchStepExpect{
				{commit: 4, applied: 3, errIdx: 4}, // 提交到非法条目：错误在此出现
				{commit: 5, applied: 3, errIdx: 4}, // 应用已停住，错误保留
			},
		},
		{
			"bad incr alone in its own request, later valid write still accepted",
			[]AppendRequest{
				appendSeg(1, 1, 3, incrFive, incrMinusTwo),
				appendSeg(3, batchLeaderTerm, 4, badIncr),
				appendSeg(4, batchLeaderTerm, 5, setAfter),
			},
			[]batchStepExpect{
				{commit: 3, applied: 3},
				{commit: 4, applied: 3, errIdx: 4},
				// 提交非法条目之后，后续合法复制仍必须被接受并把提交位置推进到 5。
				{commit: 5, applied: 3, errIdx: 4},
			},
		},
		{
			"whole segment replicated uncommitted, then a single empty-entry commit",
			[]AppendRequest{
				appendSeg(1, 1, 0, incrFive, incrMinusTwo, badIncr, setAfter),
				heartbeatSeg(5, batchLeaderTerm, 5),
			},
			[]batchStepExpect{
				{commit: 1, applied: 1}, // 非法条目尚未提交：不提前报错
				{commit: 5, applied: 3, errIdx: 4},
			},
		},
		{
			"bad incr replicated uncommitted with the increments, committed only with the later write",
			[]AppendRequest{
				appendSeg(1, 1, 0, incrFive, incrMinusTwo, badIncr),
				appendSeg(4, batchLeaderTerm, 5, setAfter),
			},
			[]batchStepExpect{
				{commit: 1, applied: 1}, // idx4 已在本地日志但未提交：无错误
				{commit: 5, applied: 3, errIdx: 4},
			},
		},
	}

	var baselineKV, baselinePlain ReplicateOutput
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kvOut := assertBatchVariant(t, initial, tc.requests, tc.steps, true)
			plainOut := assertBatchVariant(t, initial, tc.requests, tc.steps, false)
			if i == 0 {
				baselineKV, baselinePlain = kvOut, plainOut
			} else {
				assertSameBatchFinals(t, kvOut, baselineKV, true)
				assertSameBatchFinals(t, plainOut, baselinePlain, false)
			}
		})
	}

	// 共同的最终状态：完整日志五条全部保留（非法增量与其后的写入都在），任期 2、
	// 提交到 5；应用停在 idx3，count 保持两次累加后的 "13"，after 未写入，首个
	// 应用错误指向 idx4 且原因是现有的增量格式错误。
	wantLog := []LogEntry{
		entry(1, 1, "set count=10"),
		incrFive, incrMinusTwo, badIncr, setAfter,
	}
	if !reflect.DeepEqual(baselineKV.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", baselineKV.FinalLog, wantLog)
	}
	if baselineKV.FinalTerm != batchLeaderTerm || baselineKV.FinalCommittedIndex != 5 {
		t.Fatalf("final state = term %d ci %d, want term %d ci 5",
			baselineKV.FinalTerm, baselineKV.FinalCommittedIndex, batchLeaderTerm)
	}
	if *baselineKV.FinalAppliedIndex != 3 {
		t.Fatalf("final appliedIndex = %d, want 3 (stopped before bad idx4)",
			*baselineKV.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, baselineKV); !reflect.DeepEqual(kv, map[string]string{"count": "13"}) {
		t.Fatalf("final kv = %v, want only count=13 (later write must not take effect)", kv)
	}
	if baselineKV.FinalApplyError == nil ||
		baselineKV.FinalApplyError.Index != 4 ||
		baselineKV.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("final applyError = %+v, want index 4 with %q",
			baselineKV.FinalApplyError, ApplyReasonIncrBadDelta)
	}
	// 未开启 applyKV 时复制结论一致：五条日志、任期 2、提交到 5，且不带应用字段。
	if len(baselinePlain.FinalLog) != 5 ||
		baselinePlain.FinalTerm != batchLeaderTerm || baselinePlain.FinalCommittedIndex != 5 {
		t.Fatalf("plain final state wrong: term=%d ci=%d log=%+v",
			baselinePlain.FinalTerm, baselinePlain.FinalCommittedIndex, baselinePlain.FinalLog)
	}

	// 中间快照：整段（含非法增量与后续写入）都已复制、但一条新日志都未提交时，
	// 五条日志全部保留；提交与应用位置停在 idx1，计数仍是 "10"，非法增量不能
	// 提前产生应用错误，after 也不能提前出现。
	stopped := runKV(t, initial,
		appendSeg(1, 1, 0, incrFive, incrMinusTwo, badIncr, setAfter))
	if len(stopped.Results) != 1 || !stopped.Results[0].Accepted {
		t.Fatalf("uncommitted replication must be accepted: %+v", stopped.Results)
	}
	if len(stopped.FinalLog) != 5 {
		t.Fatalf("all five entries must stay in the full log before commit, got %+v", stopped.FinalLog)
	}
	if stopped.FinalCommittedIndex != 1 || *stopped.FinalAppliedIndex != 1 {
		t.Fatalf("stopped state = ci %d applied %d, want 1/1",
			stopped.FinalCommittedIndex, *stopped.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, stopped); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("uncommitted entries affected the kv table: %v, want only count=10", kv)
	}
	if stopped.FinalApplyError != nil {
		t.Fatalf("uncommitted bad incr produced an apply error early: %+v", stopped.FinalApplyError)
	}
}
