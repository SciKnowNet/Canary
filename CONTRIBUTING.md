# Contributing to Canary

Thank you for taking the time to contribute! All contributions are welcome — bug reports, new detection rules, documentation improvements, and code changes.

## Getting started

1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/canary.git
   cd canary
   ```

2. Verify everything builds and tests pass:
   ```bash
   go build ./...
   go test ./...
   ```

## Adding a detection rule

Rules live in [`internal/secretscan/rules.go`](internal/secretscan/rules.go). Each rule is a `Rule` struct:

```go
{
    ID:               "provider-token-type",   // unique kebab-case identifier
    Description:      "Human-readable label",
    Severity:         SeverityHigh,            // CRITICAL | HIGH | MEDIUM | LOW
    Regex:            regexp.MustCompile(`...`),
    SecretGroup:      1,                       // capture group index for the secret (0 = full match)
    Keywords:         []string{"prefix"},      // fast pre-filter; at least one must appear in the line
    EntropyThreshold: EntropyThresholdBase64,  // optional; omit if not needed
    Tags:             []string{"provider"},
    Allowlist:        []*regexp.Regexp{        // optional patterns that suppress the finding
        regexp.MustCompile(`(?i)example|placeholder`),
    },
},
```

**Guidelines for rules:**

- Use a `Keywords` list to avoid running the regex on every line. Keywords are matched against the lowercased line.
- Set `EntropyThreshold` for generic patterns (e.g. `password =`) to reduce false positives.
- Add an `Allowlist` for common example values (`example`, `placeholder`, `changeme`, template variables like `${VAR}`).
- Use a named capture group (`SecretGroup`) to extract only the secret, not surrounding context.
- Test your regex at [regex101.com](https://regex101.com) (Go flavor) before submitting.

## Reporting a bug

Open an issue and include:

- A minimal reproducer (file content that triggers the false positive / miss).
- The rule ID involved, if known.
- The output of `canary -no-redact -format json` (with real secrets removed).

## Pull request checklist

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes (or new tests are added for the change)
- [ ] `go vet ./...` reports no issues
- [ ] New rules include at least one keyword and a brief comment if the pattern is not obvious
- [ ] Commit messages are clear and reference an issue when applicable

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep functions small and focused.
- Avoid external dependencies — the project intentionally has none.

## License

By contributing you agree that your changes will be licensed under the [MIT License](LICENSE).
