// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"encoding/json"
	"errors"
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
		fmt.Println("mevwatch 0.2.0")
	case "replay":
		runReplay(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: mevwatch [demo|version|help]")
	fmt.Println("       mevwatch replay <input-file> <archive-dir>")
	fmt.Println("       mevwatch report <archive-dir> <chainId> <blockHash>")
}

// fatal prints an error to stderr and exits with a non-zero status.
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func runReplay(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch replay <input-file> <archive-dir>")
		os.Exit(2)
	}
	inputPath, archiveDir := args[0], args[1]

	input, err := os.Open(inputPath)
	if err != nil {
		fatal("replay: %v", err)
	}
	defer input.Close()

	reports, err := mevwatch.OpenArchive(archiveDir).Replay(input)
	if err != nil {
		fatal("replay: %v", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	for _, report := range reports {
		if err := encoder.Encode(report); err != nil {
			fatal("replay: %v", err)
		}
	}
}

func runReport(args []string) {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch report <archive-dir> <chainId> <blockHash>")
		os.Exit(2)
	}
	archiveDir, chainID, blockHash := args[0], args[1], args[2]

	report, err := mevwatch.OpenArchive(archiveDir).Report(chainID, blockHash)
	if err != nil {
		if errors.Is(err, mevwatch.ErrNotFound) {
			fatal("report: unknown block chainId=%q blockHash=%q", chainID, blockHash)
		}
		fatal("report: %v", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fatal("report: %v", err)
	}
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
