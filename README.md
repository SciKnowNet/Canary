# Canary

**Canary** is a fast, zero-dependency secret scanner written in Go. It scans files and directories for hardcoded secrets — API keys, tokens, private keys, passwords, and connection strings — before they reach production or get committed to version control.

## Features

- **50+ built-in detection rules** covering AWS, GitHub, GitLab, Google, OpenAI, Anthropic, Stripe, Slack, Cloudflare, Twilio, SendGrid, databases, and more
- **Shannon entropy analysis** to reduce false positives on generic patterns
- **Allowlist patterns** per rule to suppress known safe values (placeholders, examples, template variables)
- **Concurrent directory scanning** using a configurable worker pool
- **Three output formats**: human-readable table, JSON, and summary
- **Severity filtering**: report only findings above a minimum level (LOW / MEDIUM / HIGH / CRITICAL)
- **Path and directory exclusions**: skip `node_modules`, `.git`, `vendor`, or any custom paths
- **Embeddable as a library**: import `internal/secretscan` in your own Go tools or CI pipelines

## Installation

### From source

```bash
git clone https://github.com/SciKnowNet/Canary.git
cd Canary
go build -o canary .
```

### With `go install`

```bash
go install github.com/SciKnowNet/Canary@latest
```

## Usage

```
canary [flags]
```

| Flag             | Default     | Description                                                            |
| ---------------- | ----------- | ---------------------------------------------------------------------- |
| `-path`        | `.`       | File or directory to scan                                              |
| `-format`      | `table`   | Output format:`table`, `json`, or `summary`                      |
| `-severity`    | `LOW`     | Minimum severity to report:`LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `-no-redact`   | `false`   | Show full secret values (use with care)                                |
| `-skip-dirs`   | _(empty)_ | Comma-separated extra directory names to skip                          |
| `-allow-paths` | _(empty)_ | Comma-separated path substrings that are never flagged                 |

### Examples

Scan the current directory and print a table:

```bash
canary
```

Scan a specific directory, show only HIGH and above:

```bash
canary -path ./src -severity HIGH
```

Output results as JSON (useful for CI pipelines):

```bash
canary -path ./src -format json
```

Print a count summary grouped by severity and rule:

```bash
canary -format summary
```

Skip extra directories and ignore test fixtures:

```bash
canary -skip-dirs dist,coverage -allow-paths testdata/
```

Show full (un-redacted) secret values:

```bash
canary -path ./config -no-redact
```

## Output formats

### table _(default)_

```
SEVERITY    RULE               FILE             LINE  SECRET        ENTROPY
--------    ----               ----             ----  ------        -------
CRITICAL    aws-access-key-id  config/.env      12    AKI***xyz     3.91
HIGH        github-pat         scripts/push.sh  5     ghp***abc     4.12

2 finding(s) detected.
```

### json

```json
[
  {
    "rule_id": "aws-access-key-id",
    "description": "AWS Access Key ID",
    "severity": "CRITICAL",
    "file": "config/.env",
    "line": 12,
    "column": 1,
    "secret": "AKI***xyz",
    "entropy": 3.91,
    "tags": ["aws", "cloud"]
  }
]
```

### summary

```
Total findings: 2

  CRITICAL   1
  HIGH       1

By rule:
  aws-access-key-id                        1
  github-pat                               1
```

## Exit codes

| Code  | Meaning                                                       |
| ----- | ------------------------------------------------------------- |
| `0` | Scan completed, no findings                                   |
| `1` | Scan completed with at least one finding (or a runtime error) |

This makes Canary easy to use as a CI gate: a non-zero exit code fails the build.

## Built-in rules

| Category   | Rules                                                              |
| ---------- | ------------------------------------------------------------------ |
| AWS        | Access Key ID, Secret Access Key, MWS Key                          |
| GitHub     | Classic PAT, Fine-Grained PAT, OAuth, App Token, Refresh Token     |
| GitLab     | Personal Access Token                                              |
| Google     | API Key, OAuth Client Secret, Service Account JSON                 |
| AI / LLM   | OpenAI (v1 & project keys), Anthropic, OpenRouter                  |
| Stripe     | Secret Key, Restricted Key, Test Key                               |
| Slack      | Bot Token, User Token, Workspace Token, Webhook URL                |
| Cloudflare | API Token, Global API Key                                          |
| Twilio     | Account SID, Auth Token                                            |
| Messaging  | SendGrid, Mailgun                                                  |
| Hosting    | Heroku, Vercel, Supabase                                           |
| Data       | Databricks                                                         |
| Databases  | PostgreSQL, MySQL, MongoDB connection strings                      |
| Packages   | npm, PyPI, crates.io, LuaRocks, RubyGems, Maven Central, Open VSX  |
| Crypto     | RSA, EC, OpenSSH, PGP private keys                                 |
| Auth       | JWT                                                                |
| Generic    | API key/secret assignments, hardcoded passwords, hardcoded secrets |

## Using Canary as a library

```go
import "github.com/SciKnowNet/canary/internal/secretscan"

sc := secretscan.New(secretscan.Config{
    SkipDirs:   []string{"testdata"},
    AllowPaths: []string{"fixtures/"},
})

findings, err := sc.ScanDir("./src")
if err != nil {
    log.Fatal(err)
}

for _, f := range findings {
    fmt.Println(f) // [CRITICAL] aws-access-key-id — src/config.go:42 (entropy: 3.91)
}
```

### Config options

```go
type Config struct {
    Rules         []*Rule  // override the default rule set
    MaxFileSizeKB int64    // skip files larger than this (default: 5 MB)
    Concurrency   int      // worker goroutines (default: 8)
    SkipDirs      []string // directory names to skip
    SkipExts      []string // file extensions to skip
    AllowPaths    []string // path substrings that are never flagged
}
```

### Scanning in-memory bytes

```go
findings := sc.ScanBytes("virtual/path.go", []byte(`secret = "sk-live_abc123..."`))
```

## CI integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    go install github.com/SciKnowNet/canary@latest
    canary -path . -severity HIGH -format json
```

### Pre-commit hook

```bash
#!/bin/sh
canary -path . -severity MEDIUM
```

Save as `.git/hooks/pre-commit` and make it executable (`chmod +x`).

## Project structure

```
canary/
├── main.go                  # CLI entrypoint: flags, formatting, exit codes
└── internal/
    └── secretscan/
        ├── scanner.go       # Scanner, Config, directory/file walking
        ├── rules.go         # Rule type and all built-in detection rules
        ├── finding.go       # Finding type, Severity constants, Redacted()
        └── entropy.go       # Shannon entropy helpers and charset checks
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
