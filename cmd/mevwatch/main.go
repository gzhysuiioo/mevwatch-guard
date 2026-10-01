// Command mevwatch is the MEV 与链上风险监控系统 entry point.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
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
		fmt.Println("mevwatch 0.1.0")
	case "replay":
		runReplay(os.Args[2:])
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
		writeJSON(report)
	case "rules":
		runRules(os.Args[2:])
	case "alerts":
		runAlerts(os.Args[2:])
	case "suppress":
		runSuppress(os.Args[2:])
	case "compare":
		if len(os.Args) != 6 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch compare <archive-dir> <chainId> <blockHash> <version-id>")
			os.Exit(2)
		}
		result, err := mevwatch.Compare(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		if err != nil {
			fmt.Fprintf(os.Stderr, "compare: %v\n", err)
			os.Exit(1)
		}
		writeJSON(result)
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
	fmt.Println("  replay [--version <id>] <input> <dir>    import line-delimited blocks into the archive")
	fmt.Println("  report <archive-dir> <chainId> <hash>    print the archived block report")
	fmt.Println("  rules list <archive-dir>                 list rule versions and the enabled one")
	fmt.Println("  rules show <archive-dir> <version-id>    print one version's full parameters")
	fmt.Println("  rules register <archive-dir> <spec-file> register a rule version ('-' reads stdin)")
	fmt.Println("  rules enable <archive-dir> <version-id>  enable a registered version for later replays")
	fmt.Println("  alerts generate <archive-dir> <chainId> <start> <end> <minSeverity> <channel>")
	fmt.Println("                                           generate alerts from archived conclusions")
	fmt.Println("  alerts query <archive-dir> <chainId> <channel> <start> <end>")
	fmt.Println("                                           query processing history by chain, channel and height")
	fmt.Println("  suppress register <archive-dir> <spec-file>")
	fmt.Println("                                           register a suppression condition ('-' reads stdin)")
	fmt.Println("  suppress list <archive-dir>              list registered suppression conditions")
	fmt.Println("  compare <archive-dir> <chainId> <hash> <version-id>")
	fmt.Println("                                           re-judge an archived block under a version and diff")
}

func runReplay(args []string) {
	versionID := ""
	rest := args
	if len(rest) >= 1 && strings.HasPrefix(rest[0], "--version=") {
		versionID = strings.TrimPrefix(rest[0], "--version=")
		rest = rest[1:]
	} else if len(rest) >= 2 && rest[0] == "--version" {
		versionID = rest[1]
		rest = rest[2:]
	}
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch replay [--version <id>] <input-file> <archive-dir>")
		os.Exit(2)
	}
	var reports []mevwatch.Report
	var err error
	if versionID != "" {
		reports, err = mevwatch.ReplayFileWithVersion(rest[0], rest[1], versionID)
	} else {
		reports, err = mevwatch.ReplayFile(rest[0], rest[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		os.Exit(1)
	}
	for _, report := range reports {
		writeJSON(report)
	}
}

func runRules(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch rules <list|show|register|enable> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch rules list <archive-dir>")
			os.Exit(2)
		}
		versions, enabled, err := mevwatch.ListVersions(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules list: %v\n", err)
			os.Exit(1)
		}
		writeJSON(struct {
			Enabled  string                 `json:"enabled"`
			Versions []mevwatch.RuleVersion `json:"versions"`
		}{Enabled: enabled, Versions: versions})
	case "show":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch rules show <archive-dir> <version-id>")
			os.Exit(2)
		}
		version, err := mevwatch.GetVersion(args[1], args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules show: %v\n", err)
			os.Exit(1)
		}
		writeJSON(version)
	case "register":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch rules register <archive-dir> <spec-file>")
			os.Exit(2)
		}
		var raw []byte
		var err error
		if args[2] == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(args[2])
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules register: %v\n", err)
			os.Exit(1)
		}
		version, created, err := mevwatch.RegisterVersion(args[1], raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules register: %v\n", err)
			os.Exit(1)
		}
		writeJSON(struct {
			Created bool                 `json:"created"`
			Version mevwatch.RuleVersion `json:"version"`
		}{Created: created, Version: version})
	case "enable":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch rules enable <archive-dir> <version-id>")
			os.Exit(2)
		}
		version, err := mevwatch.EnableVersion(args[1], args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules enable: %v\n", err)
			os.Exit(1)
		}
		writeJSON(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown rules subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func runAlerts(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch alerts <generate|query> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "generate":
		if len(args) != 7 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch alerts generate <archive-dir> <chainId> <start> <end> <minSeverity> <channel>")
			os.Exit(2)
		}
		start, err := strconv.ParseInt(args[3], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts generate: invalid start height %q: %v\n", args[3], err)
			os.Exit(1)
		}
		end, err := strconv.ParseInt(args[4], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts generate: invalid end height %q: %v\n", args[4], err)
			os.Exit(1)
		}
		minSeverity, err := strconv.Atoi(args[5])
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts generate: invalid minSeverity %q: %v\n", args[5], err)
			os.Exit(1)
		}
		alerts, err := mevwatch.GenerateAlerts(args[1], args[2], start, end, minSeverity, args[6])
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts generate: %v\n", err)
			os.Exit(1)
		}
		writeJSON(alerts)
	case "query":
		if len(args) != 6 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch alerts query <archive-dir> <chainId> <channel> <start> <end>")
			os.Exit(2)
		}
		start, err := strconv.ParseInt(args[4], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts query: invalid start height %q: %v\n", args[4], err)
			os.Exit(1)
		}
		end, err := strconv.ParseInt(args[5], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts query: invalid end height %q: %v\n", args[5], err)
			os.Exit(1)
		}
		alerts, err := mevwatch.QueryAlerts(args[1], args[2], args[3], start, end)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alerts query: %v\n", err)
			os.Exit(1)
		}
		writeJSON(alerts)
	default:
		fmt.Fprintf(os.Stderr, "unknown alerts subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func runSuppress(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: mevwatch suppress <register|list> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "register":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch suppress register <archive-dir> <spec-file>")
			os.Exit(2)
		}
		var raw []byte
		var err error
		if args[2] == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(args[2])
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "suppress register: %v\n", err)
			os.Exit(1)
		}
		s, created, err := mevwatch.RegisterSuppression(args[1], raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "suppress register: %v\n", err)
			os.Exit(1)
		}
		writeJSON(struct {
			Created     bool                 `json:"created"`
			Suppression mevwatch.Suppression `json:"suppression"`
		}{Created: created, Suppression: s})
	case "list":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: mevwatch suppress list <archive-dir>")
			os.Exit(2)
		}
		conditions, err := mevwatch.ListSuppressions(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "suppress list: %v\n", err)
			os.Exit(1)
		}
		writeJSON(conditions)
	default:
		fmt.Fprintf(os.Stderr, "unknown suppress subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func writeJSON(v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
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
