// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"fmt"
	"os"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

func main() {
	command := "demo"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "demo":
		runDemo()
	case "version":
		fmt.Println("mevwatch 0.1.0")
	case "replicate":
		os.Exit(runReplicate())
	case "help", "-h", "--help":
		if len(os.Args) > 2 {
			commandHelp(os.Args[2])
			return
		}
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: mevwatch [demo|version|replicate|help]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  demo       run a small built-in detection demo")
	fmt.Println("  version    print the mevwatch version")
	fmt.Println("  replicate  simulate Raft follower log replication from a JSON document on stdin")
	fmt.Println("  help       print this help; `help replicate` shows the replicate JSON reference")
}

func commandHelp(name string) {
	switch name {
	case "replicate":
		replicateHelp()
	case "demo", "version", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", name)
		usage()
		os.Exit(2)
	}
}

func replicateHelp() {
	fmt.Print(`usage: mevwatch replicate

Reads one JSON document from standard input, simulates one Raft follower
appending an ordered sequence of replication requests in-process, and writes
one JSON document to standard output. No network is used and state only lives
for this invocation.

Input fields:
  currentTerm     number  follower's current term (non-negative)
  committedIndex  number  highest committed log index (0..len(log))
  log             array   entries with consecutive indexes starting at 1
  applyKV         boolean optional; when true, committed commands are applied
                          to a key/value table (default false, commands stay
                          uninterpreted strings)
  requests        array   replication requests applied in order

Log entry fields:
  index   number  1-based consecutive index
  term    number  positive term, non-decreasing along the log,
                  never greater than currentTerm
  command string  replicated command

Request fields:
  term          number  leader's term
  prevLogIndex  number  index of the log entry immediately before new entries
  prevLogTerm   number  its term; index 0 with term 0 marks the log origin
                        (a sentinel, not a real entry)
  entries       array   entries to append, may be empty; when non-empty
                        the entry indexes must be positive, consecutive
                        from prevLogIndex+1, and every position must fit
                        the platform integer range; their terms must be
                        positive, non-decreasing within the batch and no
                        greater than the request term, and the first
                        entry's term must be no lower than prevLogTerm
                        (see Processing rules)
  leaderCommit  number  leader's committed index

Processing rules:
  - A request with a lower term is rejected and changes nothing. This
    stale-term rejection takes precedence: a request whose term is below
    the current term is rejected as stale even when its first entry's
    term is also below prevLogTerm.
  - When the request term is at least the current term and every other
    field is valid, a non-empty entries batch must also have its first
    entry's term no lower than the request's declared prevLogTerm. Equal
    is legal, and entries need not carry the leader's current term. The
    comparison uses the declared prevLogTerm alone: even when that term
    also mismatches the local log, a first entry below it is rejected as
    "invalid request: entry terms are not non-decreasing", keeps no
    higher term and carries no conflict hint. Empty entries have no first
    entry, so this restriction does not apply and the request proceeds
    with the ordinary prev-log matching rules below.
  - A valid request with a higher term first updates currentTerm, then
    the prev-log and log merge are checked; the term update survives a
    later prefix-mismatch rejection.
  - A missing prevLogIndex or a differing prevLogTerm rejects the request
    without touching the log or committed index. Index 0 only matches term 0.
    The rejection carries a conflict hint (see results[].conflict below).
  - After a prefix match, missing positions are appended; existing positions
    with equal term and command are kept; a different term replaces that entry
    and its suffix.
  - Same index and term but a different command, or overwriting a committed
    entry, rejects the whole request atomically.
  - A fully matching shorter request never deletes a local tail; repeated
    requests create no duplicate entries.
  - On success committedIndex advances to min(leaderCommit, last acknowledged
    index = prevLogIndex + len(entries)) but never moves backward.
  - Real entry indexes must be positive and consecutive from prevLogIndex+1,
    and prevLogIndex+1 through the last entry's position must all be
    representable: if the next or any later position exceeds the platform
    integer maximum (even when a supplied negative index numerically equals
    the wrapped-around position), the whole request is a field error rejected
    as non-consecutive entries. Empty entries require no next position, and a
    non-empty request whose last entry lands exactly on the maximum is legal;
    such requests are still subject to the ordinary prev-log mismatch rules.

Key/value application (only when applyKV is true):
  - The table starts empty for this invocation. The committed prefix of the
    initial log is applied first in index order; after each request only newly
    committed, not-yet-applied entries are applied, so unchanged commit
    positions, empty-entry heartbeats and repeated requests never re-apply.
  - Commands are case-sensitive with exactly one ordinary space after the
    command name; neither end of the command is trimmed:
      set <key>=<value>   write or overwrite a key; the first '=' after the
                          key separates the value, which is kept verbatim and
                          may be empty or contain spaces, CJK text and '='
      delete <key>        delete a key; deleting a missing key still succeeds
                          and the position counts as applied
      incr <key>=<delta>  add delta to the key's current integer value; a
                          missing key counts as 0 and is created. Both the
                          current value and delta must be signed 64-bit
                          decimal integers: an optional '-' sign and ASCII
                          digits only (leading zeros allowed; no '+' sign,
                          whitespace, decimals, exponents or non-ASCII digits;
                          empty is not an integer). On success the key holds
                          the canonical decimal form (no leading zeros, zero
                          is "0"); a zero delta still writes the canonical
                          form and counts as applied
  - Keys must be non-empty and contain no whitespace or '='. Every other
    command shape is a format error.
  - Uncommitted entries are never applied: their format errors stay invisible
    and a replaced uncommitted suffix leaves no trace in the table.
  - On the first format error in a committed command, previously applied
    results are kept, the applied index stops before the failing entry, and
    no later entry is applied for the rest of the invocation. An incr whose
    current value is not an integer, whose delta is not an integer, or whose
    sum overflows the signed 64-bit range fails the same way: the table is
    left unchanged and the reason tells the three cases apart. Replication
    itself is unaffected: later requests still change log, term and commit
    position, and apply failure never turns an accepted replication into a
    rejection nor alters a rejection reason.

Output fields:
  results              array of per-request results, in input order
    results[].accepted        boolean success/rejection
    results[].reason          "ok" or a specific rejection reason
    results[].term            current term after handling the request
    results[].committedIndex  committed index after handling the request
    results[].conflict        only on a prev-log-mismatch rejection:
                              {"index", "term"} suggesting where to resend
                              from. When prevLogIndex is beyond the local
                              log, index is the last local index plus one
                              and term is 0 (empty log: index 1). When the
                              index exists but its term differs, term is the
                              local term there and index is the first index
                              of that term in the full local log (committed
                              entries included). Index 0 with a non-zero
                              term yields {"index": 1, "term": 0}. The hint
                              describes the local log as checked by this
                              request and changes nothing.
  finalTerm            final current term
  finalCommittedIndex  final committed index
  finalLog             complete log after all requests

Extra output fields when applyKV is true:
  results[].appliedIndex  highest applied log index after the request
                          (0 = nothing applied)
  results[].applyError    null, or {"index", "reason"} for the first
                          committed command that failed to apply (malformed
                          command, or an incr with a non-integer current
                          value, a non-integer delta, or an overflowing sum)
  finalAppliedIndex       highest applied log index at the end
  finalKV                 final key/value table ({} when empty); incr results
                          are stored as canonical decimal strings
  finalApplyError         null, or {"index", "reason"}

A request violating a field rule is recorded as one rejection without changing
any state (including its higher term), and processing continues with the next
request. Invalid initial state or unparseable input JSON ends the command with
a non-zero exit code and an error message on standard error. So does an
explicit null written for any recognized numeric field (currentTerm,
committedIndex, log entry index/term, request term/prevLogIndex/prevLogTerm/
leaderCommit, entry index/term, matched case-insensitively): the whole input
is rejected as a field type error naming the field location (e.g.
requests[1].leaderCommit), instead of silently treating the null as zero.
The check covers every occurrence of a duplicated field name, so a null written
before or after the other value ({"currentTerm":null,"currentTerm":1}) is still
rejected, and when log, requests or entries appears more than once (even with
different casing) a numeric null inside any of those arrays cannot be masked by
a later array. Duplicate keys themselves are not forbidden: when no occurrence
carries a numeric null the usual last-wins JSON reading rules apply. When log,
requests or entries (matched case-insensitively) appears more than once, the
last array replaces the earlier one wholesale: only the elements the last array
actually gives are kept (a shorter last array drops the old tail, a null last
occurrence empties it), and each element is interpreted on its own. An omitted
index or term defaults to 0, an omitted command to the empty string and an
omitted entries array to no entries; a later element never inherits the term,
index, commit position, command or entries of the same-position earlier one, so
a later initial-log element that omits index or term ends the run as an invalid
initial state. Omitting a field that appears only once still applies its
default, 0 keeps its ordinary meaning, and nulls in array fields themselves or
in unknown keys are handled as before. Unrecognized fields are ignored
wherever they appear (root, request, log entry, or nested inside each other),
including numbers of any magnitude such as 1e400; they never take part in
follower state and never appear in the output. The same oversized numbers
written to a recognized numeric field are still rejected as a field type
error.
`)
}

func runDemo() {
	swaps := []mevwatch.Swap{
		{TxHash: "0xfront", Pool: "pool-1", Trader: "bot-a", In: 500, Out: 480, GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "pool-1", Trader: "user-1", In: 200, Out: 188, GasPrice: 12, Index: 1},
		{TxHash: "0xback", Pool: "pool-1", Trader: "bot-a", In: 480, Out: 505, GasPrice: 80, Index: 2},
	}
	findings := mevwatch.Detect(swaps, "0xvictim")
	for _, finding := range mevwatch.Rank(findings) {
		fmt.Printf("tx=%s kind=%s severity=%d evidence=%v\n", finding.TxHash, finding.Kind, finding.Severity, finding.Evidence)
	}
	fmt.Printf("swaps=%d findings=%d\n", len(swaps), len(findings))
}
