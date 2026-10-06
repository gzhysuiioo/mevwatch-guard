package mevwatch

import (
	"reflect"
	"testing"
)

// 本文件是“复制请求如何分批不改变同一段已提交日志最终生效结果”的回归保障：
// 从相同的合法初始状态出发，同一段日志（每条日志的索引、任期、命令及顺序完全
// 相同）无论是整段一次送达、分成多次连续请求送达，还是先复制再用空条目请求
// 推进提交，各次复制都能被接受，最终确认的日志范围、提交位置、应用位置、键值
// 表与首个应用错误都必须一致；中间提交位置只向前推进且不超过最终位置。逐条
// 请求的答复反映各自处理结束时的状态——分批方式不同，请求数量与提交时机自然
// 不同，这些答复不作逐项比较。

// batchingInitial 是本文件回归场景共享的初始状态：当前任期 2，idx1
// （set count=10，任期 1）已提交，没有未提交尾部。后续所有送达方式都使用
// 相同的领导者任期 2。
func batchingInitial() InitialState {
	return InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set count=10"),
	}}
}

// batchDelivery 是同一段日志的一种送达方式：name 用于子测试，requests 为按序
// 到达的复制请求；wantCommits / wantApplied 是逐条请求处理结束时的提交位置与
// 应用位置（与 requests 一一对应）。
type batchDelivery struct {
	name        string
	requests    []AppendRequest
	wantCommits []int
	wantApplied []int
}

// finalSummary 汇总一次调用结束时与分批方式无关的最终状态，用于跨方式比较。
type finalSummary struct {
	term      int
	committed int
	log       []LogEntry
	applied   int
	kv        map[string]string
	applyErr  *ApplyError
}

func summarizeFinal(t *testing.T, out ReplicateOutput) finalSummary {
	t.Helper()
	if out.FinalAppliedIndex == nil || out.FinalKV == nil {
		t.Fatalf("final apply fields missing in %+v", out)
	}
	return finalSummary{
		term:      out.FinalTerm,
		committed: out.FinalCommittedIndex,
		log:       out.FinalLog,
		applied:   *out.FinalAppliedIndex,
		kv:        out.FinalKV,
		applyErr:  out.FinalApplyError,
	}
}

// wantBatchingResults 断言每次复制都以 ok 接受、逐条答复的提交位置只向前推进
// 且不超过最终位置，并与期望的逐条提交位置、应用位置一致。
func wantBatchingResults(t *testing.T, delivery batchDelivery, out ReplicateOutput, initialCommit int) {
	t.Helper()
	if len(out.Results) != len(delivery.requests) {
		t.Fatalf("got %d results, want %d", len(out.Results), len(delivery.requests))
	}
	previous := initialCommit
	for i, result := range out.Results {
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("result %d must be accepted with reason ok, got %+v", i, result)
		}
		if result.Term != 2 {
			t.Fatalf("result %d term = %d, want 2", i, result.Term)
		}
		if result.CommittedIndex < previous {
			t.Fatalf("result %d committedIndex moved backward: %d < %d",
				i, result.CommittedIndex, previous)
		}
		if result.CommittedIndex > out.FinalCommittedIndex {
			t.Fatalf("result %d committedIndex %d exceeds final %d",
				i, result.CommittedIndex, out.FinalCommittedIndex)
		}
		if result.CommittedIndex != delivery.wantCommits[i] {
			t.Fatalf("result %d committedIndex = %d, want %d",
				i, result.CommittedIndex, delivery.wantCommits[i])
		}
		if got := appliedIndexOf(t, result); got != delivery.wantApplied[i] {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, got, delivery.wantApplied[i])
		}
		previous = result.CommittedIndex
	}
}

// batchingIncrEntries 是场景一共享的日志段：两次依赖先前值的累加，加一条最终
// 提交范围以外的写入。三条日志的索引、任期、命令及顺序在所有送达方式中相同。
func batchingIncrEntries() []LogEntry {
	return []LogEntry{
		entry(2, 2, "incr count=5"),
		entry(3, 2, "incr count=-2"),
		entry(4, 2, "set extra=late"), // 最终提交范围以外：保留在日志中但不生效
	}
}

// batchingIncrDeliveries 是场景一的各种送达方式：整段一次送达、在两次累加之间
// 切分、逐条送达、先复制再用空条目请求推进提交。最终提交位置都是 3。
func batchingIncrDeliveries() []batchDelivery {
	entries := batchingIncrEntries()
	return []batchDelivery{
		{
			"whole segment in one request",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3, Entries: entries},
			},
			[]int{3},
			[]int{3},
		},
		{
			"split between the two increments",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2, Entries: entries[:1]},
				{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3, Entries: entries[1:]},
			},
			[]int{2, 3},
			[]int{2, 3},
		},
		{
			"one request per entry",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2, Entries: entries[:1]},
				{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3, Entries: entries[1:2]},
				{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 3, Entries: entries[2:]},
			},
			[]int{2, 3, 3},
			[]int{2, 3, 3},
		},
		{
			"replicate first then commit via heartbeat",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1, Entries: entries},
				{Term: 2, PrevLogIndex: 4, PrevLogTerm: 2, LeaderCommit: 3},
			},
			[]int{1, 3},
			[]int{1, 3},
		},
	}
}

// TestBatchingDoesNotChangeFinalIncrOutcome 场景一：初始已提交日志把 count 设为
// 字符串 "10"，随后依次提交 incr count=5 与 incr count=-2。无论整段一次送达、
// 在两次累加之间切分、逐条送达，还是复制完成后才用空条目请求提交，最终日志、
// 任期、提交位置、应用位置、键值表与首个应用错误都必须一致：count 最终为
// "13"（不漏加、不重复累加、不重新写回初始值），应用位置到达最后一条已提交
// 日志 idx3；idx4 的写入在最终提交范围以外，保留在完整日志中但不影响键值表。
func TestBatchingDoesNotChangeFinalIncrOutcome(t *testing.T) {
	wantLog := append([]LogEntry{entry(1, 1, "set count=10")}, batchingIncrEntries()...)
	var baseline *finalSummary
	for _, delivery := range batchingIncrDeliveries() {
		t.Run(delivery.name, func(t *testing.T) {
			out := runKV(t, batchingInitial(), delivery.requests...)
			wantBatchingResults(t, delivery, out, 1)
			for i, result := range out.Results {
				if result.ApplyError != nil {
					t.Fatalf("result %d unexpected apply error: %+v", i, result.ApplyError)
				}
			}

			if !reflect.DeepEqual(out.FinalLog, wantLog) {
				t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
			}
			if out.FinalTerm != 2 || out.FinalCommittedIndex != 3 {
				t.Fatalf("final state = term %d ci %d, want term 2 ci 3",
					out.FinalTerm, out.FinalCommittedIndex)
			}
			if *out.FinalAppliedIndex != 3 {
				t.Fatalf("final appliedIndex = %d, want 3 (last committed entry)",
					*out.FinalAppliedIndex)
			}
			kv := finalKVOf(t, out)
			if !reflect.DeepEqual(kv, map[string]string{"count": "13"}) {
				t.Fatalf("final kv = %v, want only count=13", kv)
			}
			if _, ok := kv["extra"]; ok {
				t.Fatalf("uncommitted entry idx4 took effect: %v", kv)
			}
			if out.FinalApplyError != nil {
				t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
			}

			// 与第一种送达方式比较最终状态：分批方式不得改变最终生效结果。
			summary := summarizeFinal(t, out)
			if baseline == nil {
				baseline = &summary
			} else if !reflect.DeepEqual(summary, *baseline) {
				t.Fatalf("final state differs across deliveries:\n got %+v\nwant %+v",
					summary, *baseline)
			}
		})
	}
}

// batchingIllegalIncrEntries 是场景二共享的日志段：两次合法累加之后接一条非法
// 增量，再接一条合法写入。四条日志的索引、任期、命令及顺序在所有送达方式中相同。
func batchingIllegalIncrEntries() []LogEntry {
	return []LogEntry{
		entry(2, 2, "incr count=5"),
		entry(3, 2, "incr count=-2"),
		entry(4, 2, "incr count=oops"), // 非法增量：提交后应用停在其前
		entry(5, 2, "set receipt=ok"),  // 错误之后的合法写入：不能生效
	}
}

// batchingIllegalIncrDeliveries 是场景二的各种送达方式：非法条目与前后条目同
// 在一个请求、独占一个请求，或先全部复制再用空条目请求逐步推进提交。最终提交
// 位置都是 5。
func batchingIllegalIncrDeliveries() []batchDelivery {
	entries := batchingIllegalIncrEntries()
	return []batchDelivery{
		{
			"whole segment in one request",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 5, Entries: entries},
			},
			[]int{5},
			[]int{3},
		},
		{
			"illegal entry shares a request with its neighbors",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3, Entries: entries[:2]},
				{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 5, Entries: entries[2:]},
			},
			[]int{3, 5},
			[]int{3, 3},
		},
		{
			"illegal entry in its own request",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3, Entries: entries[:2]},
				{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 4, Entries: entries[2:3]},
				{Term: 2, PrevLogIndex: 4, PrevLogTerm: 2, LeaderCommit: 5, Entries: entries[3:]},
			},
			[]int{3, 4, 5},
			[]int{3, 3, 3},
		},
		{
			"replicate first then commit via heartbeats",
			[]AppendRequest{
				{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1, Entries: entries},
				{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2, LeaderCommit: 4},
				{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2, LeaderCommit: 5},
			},
			[]int{1, 4, 5},
			[]int{1, 3, 3},
		},
	}
}

// TestBatchingCommittedIllegalIncrOutcomeIsBatchingIndependent 场景二：遇到已提交
// 的非法增量时，分批一致性同样成立。无论非法命令与前后条目是否处于同一个请求，
// 最终都保留 count 的 "13"，应用位置停在非法条目之前（idx3），首个应用错误指向
// idx4 并报告现有的增量格式错误，idx5 的合法写入不能生效；完整日志与提交位置
// 不受应用停滞影响。逐条答复中，应用错误只能在非法条目提交之后出现。
func TestBatchingCommittedIllegalIncrOutcomeIsBatchingIndependent(t *testing.T) {
	wantLog := append([]LogEntry{entry(1, 1, "set count=10")}, batchingIllegalIncrEntries()...)
	wantErr := &ApplyError{Index: 4, Reason: ApplyReasonIncrBadDelta}
	var baseline *finalSummary
	for _, delivery := range batchingIllegalIncrDeliveries() {
		t.Run(delivery.name, func(t *testing.T) {
			out := runKV(t, batchingInitial(), delivery.requests...)
			wantBatchingResults(t, delivery, out, 1)
			// 非法条目 idx4 尚未提交时不提前产生应用错误；提交它以后错误出现，
			// 且后续合法复制仍被接受、提交位置继续推进。
			for i, result := range out.Results {
				switch {
				case result.CommittedIndex >= 4:
					if result.ApplyError == nil || *result.ApplyError != *wantErr {
						t.Fatalf("result %d applyError = %+v, want %+v", i, result.ApplyError, wantErr)
					}
				default:
					if result.ApplyError != nil {
						t.Fatalf("result %d reported error before idx4 was committed: %+v",
							i, result.ApplyError)
					}
				}
			}

			if !reflect.DeepEqual(out.FinalLog, wantLog) {
				t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
			}
			if out.FinalTerm != 2 || out.FinalCommittedIndex != 5 {
				t.Fatalf("final state = term %d ci %d, want term 2 ci 5",
					out.FinalTerm, out.FinalCommittedIndex)
			}
			if *out.FinalAppliedIndex != 3 {
				t.Fatalf("final appliedIndex = %d, want 3 (stops before the illegal entry)",
					*out.FinalAppliedIndex)
			}
			kv := finalKVOf(t, out)
			if !reflect.DeepEqual(kv, map[string]string{"count": "13"}) {
				t.Fatalf("final kv = %v, want only count=13", kv)
			}
			if _, ok := kv["receipt"]; ok {
				t.Fatalf("write after the illegal entry took effect: %v", kv)
			}
			if out.FinalApplyError == nil || *out.FinalApplyError != *wantErr {
				t.Fatalf("final applyError = %+v, want %+v", out.FinalApplyError, wantErr)
			}

			// 与第一种送达方式比较最终状态：非法条目如何分批不改变最终结果。
			summary := summarizeFinal(t, out)
			if baseline == nil {
				baseline = &summary
			} else if !reflect.DeepEqual(summary, *baseline) {
				t.Fatalf("final state differs across deliveries:\n got %+v\nwant %+v",
					summary, *baseline)
			}
		})
	}
}

// TestBatchingApplyStallIsNotReplicationRejection 回归保障：非法增量提交后应用
// 停滞，但复制本身不因此转为拒绝。先整段复制（未提交，无应用错误），再用空条目
// 心跳把提交推进到非法条目（错误出现、应用停在 idx3），之后合法复制仍被接受并
// 继续推进提交位置——包括纯心跳推进与追加新条目，应用位置与已报告的错误保持
// 不变，错误之后的写入不生效。
func TestBatchingApplyStallIsNotReplicationRejection(t *testing.T) {
	entries := batchingIllegalIncrEntries()
	out := runKV(t, batchingInitial(),
		// 整段复制，暂不提交：非法条目未提交，不产生应用错误。
		AppendRequest{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 1, Entries: entries},
		// 空条目心跳把提交推进到 idx4：非法增量此时才报告，应用停在 idx3。
		AppendRequest{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2, LeaderCommit: 4},
		// 应用已停滞，后续合法复制仍被接受：心跳推进提交到 idx5。
		AppendRequest{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2, LeaderCommit: 5},
		// 追加新条目并提交：复制照常接受，错误之后的写入仍不生效。
		AppendRequest{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2, LeaderCommit: 6,
			Entries: []LogEntry{entry(6, 2, "set later=nope")}},
	)

	wantCommits := []int{1, 4, 5, 6}
	wantApplied := []int{1, 3, 3, 3}
	wantErr := &ApplyError{Index: 4, Reason: ApplyReasonIncrBadDelta}
	if len(out.Results) != 4 {
		t.Fatalf("got %d results, want 4", len(out.Results))
	}
	for i, result := range out.Results {
		if !result.Accepted || result.Reason != ReasonOK {
			t.Fatalf("result %d must stay accepted despite the apply stall: %+v", i, result)
		}
		if result.CommittedIndex != wantCommits[i] {
			t.Fatalf("result %d committedIndex = %d, want %d", i, result.CommittedIndex, wantCommits[i])
		}
		if got := appliedIndexOf(t, result); got != wantApplied[i] {
			t.Fatalf("result %d appliedIndex = %d, want %d", i, got, wantApplied[i])
		}
		if i == 0 {
			if result.ApplyError != nil {
				t.Fatalf("uncommitted illegal entry reported early: %+v", result.ApplyError)
			}
		} else if result.ApplyError == nil || *result.ApplyError != *wantErr {
			t.Fatalf("result %d applyError = %+v, want %+v", i, result.ApplyError, wantErr)
		}
	}

	wantLog := append(append([]LogEntry{entry(1, 1, "set count=10")}, batchingIllegalIncrEntries()...),
		entry(6, 2, "set later=nope"))
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 6 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 6",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 3 {
		t.Fatalf("final appliedIndex = %d, want 3", *out.FinalAppliedIndex)
	}
	kv := finalKVOf(t, out)
	if !reflect.DeepEqual(kv, map[string]string{"count": "13"}) {
		t.Fatalf("final kv = %v, want only count=13", kv)
	}
	if out.FinalApplyError == nil || *out.FinalApplyError != *wantErr {
		t.Fatalf("final applyError = %+v, want %+v", out.FinalApplyError, wantErr)
	}
}
