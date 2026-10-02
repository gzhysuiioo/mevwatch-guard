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
  entries       array   entries to append, must be consecutive from
                        prevLogIndex+1, may be empty
  leaderCommit  number  leader's committed index

Processing rules:
  - A request with a lower term is rejected and changes nothing.
  - A request with a higher term first updates currentTerm, then the log is
    checked; the term update survives a later prefix-mismatch rejection.
  - A missing prevLogIndex or a differing prevLogTerm rejects the request
    without touching the log or committed index. Index 0 only matches term 0.
  - After a prefix match, missing positions are appended; existing positions
    with equal term and command are kept; a different term replaces that entry
    and its suffix.
  - Same index and term but a different command, or overwriting a committed
    entry, rejects the whole request atomically.
  - A fully matching shorter request never deletes a local tail; repeated
    requests create no duplicate entries.
  - On success committedIndex advances to min(leaderCommit, last acknowledged
    index = prevLogIndex + len(entries)) but never moves backward.

Output fields:
  results              array of per-request results, in input order
    results[].accepted        boolean success/rejection
    results[].reason          "ok" or a specific rejection reason
    results[].term            current term after handling the request
    results[].committedIndex  committed index after handling the request
  finalTerm            final current term
  finalCommittedIndex  final committed index
  finalLog             complete log after all requests

A request violating a field rule is recorded as one rejection without changing
any state (including its higher term), and processing continues with the next
request. Invalid initial state or unparseable input JSON ends the command with
a non-zero exit code and an error message on standard error.
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
