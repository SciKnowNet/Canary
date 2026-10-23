package secretscan

import "fmt"

// Severity classifies how critical a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding represents a detected secret in a file or commit.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Match       string   `json:"match"`   // the full matched line (redacted in output)
	Secret      string   `json:"secret"`  // the extracted secret value
	Entropy     float64  `json:"entropy"` // Shannon entropy of the secret
	Commit      string   `json:"commit,omitempty"`
	Author      string   `json:"author,omitempty"`
	Date        string   `json:"date,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func (f Finding) String() string {
	loc := fmt.Sprintf("%s:%d", f.File, f.Line)
	if f.Commit != "" {
		loc = fmt.Sprintf("%s (%s)", loc, f.Commit[:8])
	}
	return fmt.Sprintf("[%s] %s — %s (entropy: %.2f)", f.Severity, f.RuleID, loc, f.Entropy)
}

// Redacted returns the secret with most characters replaced by *.
func (f Finding) Redacted() string {
	s := f.Secret
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-3:]
}
