// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"encoding/json"
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
	case "replay":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch replay <input-file> <archive-dir>")
			os.Exit(2)
		}
		reports, err := mevwatch.ReplayFile(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "replay: %v\n", err)
			os.Exit(1)
		}
		for _, report := range reports {
			writeReport(report)
		}
	case "report":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch report <archive-dir> <chainId> <blockHash>")
			os.Exit(2)
		}
		report, err := mevwatch.Query(os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
			os.Exit(1)
		}
		writeReport(report)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: mevwatch [command]")
	fmt.Println("  demo                                     run the built-in sandwich demo (default)")
	fmt.Println("  version                                  print version")
	fmt.Println("  replay <input-file> <archive-dir>        import line-delimited blocks into the archive")
	fmt.Println("  report <archive-dir> <chainId> <hash>    print the archived block report")
}

func writeReport(report mevwatch.Report) {
	raw, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(raw))
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
