// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
		runVersion()
	case "replay":
		runReplay()
	case "report":
		runReport()
	case "compare":
		runCompare()
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
	fmt.Println("  version register <archive> <json|@file>  register a rule version")
	fmt.Println("  version list <archive>                   list versions and the enabled one")
	fmt.Println("  version enable <archive> <id>            enable a version")
	fmt.Println("  replay <input> <archive> [--version id]  import line-delimited blocks into the archive")
	fmt.Println("  report <archive> <chainId> <hash>        print the archived block report")
	fmt.Println("  compare <archive> <chainId> <hash> <id>  compare archived vs version conclusions")
}

func runVersion() {
	if len(os.Args) < 3 {
		fmt.Println("mevwatch 0.1.0")
		return
	}
	switch os.Args[2] {
	case "register":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch version register <archive-dir> <json-or-@file>")
			os.Exit(2)
		}
		data, err := readVersionArg(os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "version register: %v\n", err)
			os.Exit(1)
		}
		v, err := mevwatch.ParseVersionJSON(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "version register: %v\n", err)
			os.Exit(1)
		}
		if err := mevwatch.RegisterVersion(os.Args[3], v); err != nil {
			fmt.Fprintf(os.Stderr, "version register: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(v.ID)
	case "list":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch version list <archive-dir>")
			os.Exit(2)
		}
		versions, err := mevwatch.ListVersions(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "version list: %v\n", err)
			os.Exit(1)
		}
		enabled, err := mevwatch.EnabledVersion(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "version list: %v\n", err)
			os.Exit(1)
		}
		out := map[string]interface{}{"enabled": enabled, "versions": versions}
		raw, err := json.Marshal(out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "enable":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch version enable <archive-dir> <version-id>")
			os.Exit(2)
		}
		if err := mevwatch.EnableVersion(os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintf(os.Stderr, "version enable: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(os.Args[4])
	default:
		fmt.Fprintf(os.Stderr, "unknown version command %q\n", os.Args[2])
		os.Exit(2)
	}
}

// readVersionArg returns the raw JSON: inline, or read from a file when the
// argument is prefixed with '@'.
func readVersionArg(arg string) ([]byte, error) {
	if strings.HasPrefix(arg, "@") {
		return os.ReadFile(arg[1:])
	}
	return []byte(arg), nil
}

func runReplay() {
	var versionID string
	var positional []string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--version" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "replay: --version requires an argument")
				os.Exit(2)
			}
			versionID = args[i+1]
			i++
			continue
		}
		positional = append(positional, args[i])
	}
	if len(positional) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch replay <input-file> <archive-dir> [--version <id>]")
		os.Exit(2)
	}
	reports, err := mevwatch.ReplayFileWithVersion(positional[0], positional[1], versionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		os.Exit(1)
	}
	for _, report := range reports {
		writeReport(report)
	}
}

func runReport() {
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
}

func runCompare() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch compare <archive-dir> <chainId> <blockHash> <version-id>")
		os.Exit(2)
	}
	comp, err := mevwatch.Compare(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		os.Exit(1)
	}
	writeComparison(comp)
}

func writeReport(report mevwatch.Report) {
	raw, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(raw))
}

func writeComparison(comp mevwatch.VersionComparison) {
	raw, err := json.Marshal(comp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode comparison: %v\n", err)
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
