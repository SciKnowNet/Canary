package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/SciKnowNet/canary/internal/secretscan"
)

func main() {
	var (
		target      = flag.String("path", ".", "File or directory to scan")
		format      = flag.String("format", "table", "Output format: table | json | summary")
		minSeverity = flag.String("severity", "LOW", "Minimum severity to report: LOW | MEDIUM | HIGH | CRITICAL")
		noRedact    = flag.Bool("no-redact", false, "Show full secret values (use with care)")
		skipDirs    = flag.String("skip-dirs", "", "Comma-separated extra directories to skip")
		allowPaths  = flag.String("allow-paths", "", "Comma-separated path substrings to ignore")
	)
	flag.Parse()

	cfg := secretscan.Config{}
	if *skipDirs != "" {
		cfg.SkipDirs = strings.Split(*skipDirs, ",")
	}
	if *allowPaths != "" {
		cfg.AllowPaths = strings.Split(*allowPaths, ",")
	}

	sc := secretscan.New(cfg)

	info, err := os.Stat(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var findings []secretscan.Finding
	if info.IsDir() {
		findings, err = sc.ScanDir(*target)
	} else {
		findings, err = sc.ScanFile(*target)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	findings = filterBySeverity(findings, secretscan.Severity(strings.ToUpper(*minSeverity)))
	sort.Slice(findings, func(i, j int) bool {
		si, sj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	switch *format {
	case "json":
		printJSON(findings, *noRedact)
	case "summary":
		printSummary(findings)
	default:
		printTable(findings, *noRedact)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}

func printTable(findings []secretscan.Finding, noRedact bool) {
	if len(findings) == 0 {
		fmt.Println("✅  No secrets detected.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tRULE\tFILE\tLINE\tSECRET\tENTROPY")
	fmt.Fprintln(w, "--------\t----\t----\t----\t------\t-------")
	for _, f := range findings {
		secret := f.Redacted()
		if noRedact {
			secret = f.Secret
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%.2f\n",
			f.Severity, f.RuleID, f.File, f.Line, secret, f.Entropy)
	}
	_ = w.Flush()
	fmt.Printf("\n%d finding(s) detected.\n", len(findings))
}

func printJSON(findings []secretscan.Finding, noRedact bool) {
	out := make([]map[string]any, len(findings))
	for i, f := range findings {
		secret := f.Redacted()
		if noRedact {
			secret = f.Secret
		}
		out[i] = map[string]any{
			"rule_id":     f.RuleID,
			"description": f.Description,
			"severity":    f.Severity,
			"file":        f.File,
			"line":        f.Line,
			"column":      f.Column,
			"secret":      secret,
			"entropy":     f.Entropy,
			"tags":        f.Tags,
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func printSummary(findings []secretscan.Finding) {
	if len(findings) == 0 {
		fmt.Println("✅  No secrets detected.")
		return
	}
	bySev := map[secretscan.Severity]int{}
	byRule := map[string]int{}
	for _, f := range findings {
		bySev[f.Severity]++
		byRule[f.RuleID]++
	}
	fmt.Printf("Total findings: %d\n\n", len(findings))
	for _, sev := range []secretscan.Severity{
		secretscan.SeverityCritical, secretscan.SeverityHigh,
		secretscan.SeverityMedium, secretscan.SeverityLow,
	} {
		if n := bySev[sev]; n > 0 {
			fmt.Printf("  %-10s %d\n", sev, n)
		}
	}
	fmt.Println("\nBy rule:")
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		fmt.Printf("  %-40s %d\n", r, byRule[r])
	}
}

func filterBySeverity(findings []secretscan.Finding, min secretscan.Severity) []secretscan.Finding {
	minRank := severityRank(min)
	var out []secretscan.Finding
	for _, f := range findings {
		if severityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func severityRank(s secretscan.Severity) int {
	switch s {
	case secretscan.SeverityCritical:
		return 4
	case secretscan.SeverityHigh:
		return 3
	case secretscan.SeverityMedium:
		return 2
	default:
		return 1
	}
}
