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
