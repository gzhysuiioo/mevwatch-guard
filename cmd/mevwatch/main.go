// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"encoding/json"
	"fmt"
	"io"
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
		runReplicate()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`usage: mevwatch [demo|version|replicate|help]

commands:
  demo       run the built-in detection demo (default when no command is given)
  version    print the version
  replicate  simulate Raft follower log replication from stdin JSON to stdout JSON
  help       show this help

replicate:
  The follower keeps state only for this invocation; nothing is persisted or
  networked. Input is one JSON document on stdin:

    {
      "initial_state": {
        "current_term": int,      // nonnegative
        "commit_index": int,      // nonnegative, not above the log length
        "log": [                  // entries with contiguous indexes from 1
          {"index": int, "term": int, "command": "string"}
        ]
      },
      "requests": [               // applied in order; may be empty
        {
          "leader_term": int,      // nonnegative
          "prev_log_index": int,   // nonnegative; 0 is the log origin
          "prev_log_term": int,    // nonnegative; index 0 only matches term 0
          "entries": [            // contiguous from prev_log_index+1; may be []
            {"term": int, "command": "string"}
          ],
          "leader_commit": int     // nonnegative
        }
      ]
    }

  Real entries have positive, non-decreasing terms that never exceed the
  current term (initial log) or the leader term (request entries).

  Output is one JSON document on stdout:

    {
      "results": [
        {
          "ok": bool,            // whether the request was accepted
          "reason": "string",    // machine code, see below
          "message": "string",   // human-readable detail
          "term": int,           // term after processing this request
          "commit_index": int    // commit index after processing this request
        }
      ],
      "term": int,               // final term
      "commit_index": int,       // final commit index
      "log": [                   // final complete log
        {"index": int, "term": int, "command": "string"}
      ]
    }

  Reason codes:
    ok                     request applied
    lower_term             leader term below current term; state untouched
    invalid_request        request violates field rules; state untouched,
                           including the term
    prev_log_missing       prev_log_index is beyond the local log
    prev_log_term_mismatch local entry at prev_log_index has a different term
                           (or index 0 is paired with a nonzero term)
    command_mismatch       same index and term but different command
    committed_overwrite    resolving a term conflict would overwrite a
                           committed entry

  Semantics:
    - Lower-term requests are rejected with no state change.
    - Higher-term requests update the term before log checks, so a prefix
      mismatch still leaves the term update in place.
    - A missing or term-divergent prev log rejects without touching the log
      or commit index; index 0 only matches term 0.
    - After prefix match, identical entries are kept, new indexes are
      appended, and a different term at an existing index replaces that entry
      and its suffix. Same term with a different command, or any overwrite of
      a committed entry, rejects the whole request atomically: log and commit
      index stay unchanged even when appendable content was already found.
    - A fully matching short request does not delete extra local tail; a
      repeated request does not duplicate entries.
    - On success the commit index advances to min(leader_commit, last
      confirmed index), never backwards. An empty batch confirms only
      prev_log_index, so kept local tail is not committed.

  Invalid initial state or unparseable JSON exits nonzero with an error on
  stderr; identical input always yields identical output.
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

func runReplicate() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("读取标准输入失败: %v", err)
	}
	var in mevwatch.ReplicateInput
	if err := json.Unmarshal(data, &in); err != nil {
		fatal("JSON 解析失败: %v", err)
	}
	out, err := mevwatch.Replicate(in)
	if err != nil {
		fatal("初始状态非法: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fatal("输出失败: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
