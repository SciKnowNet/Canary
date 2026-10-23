package secretscan

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config controls scanner behaviour.
type Config struct {
	Rules         []*Rule
	MaxFileSizeKB int64    // files larger than this are skipped (0 = 5 MB default)
	Concurrency   int      // goroutines for file scanning (0 = NumCPU)
	SkipDirs      []string // directory names to skip (e.g. ".git", "vendor")
	SkipExts      []string // file extensions to skip (e.g. ".png", ".exe")
	AllowPaths    []string // path substrings that are never flagged (e.g. "testdata/")
}

func (c *Config) defaults() {
	if c.MaxFileSizeKB == 0 {
		c.MaxFileSizeKB = 5 * 1024
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if len(c.SkipDirs) == 0 {
		c.SkipDirs = defaultSkipDirs
	}
	if len(c.SkipExts) == 0 {
		c.SkipExts = defaultSkipExts
	}
	if len(c.Rules) == 0 {
		c.Rules = DefaultRules()
	}
}

var defaultSkipDirs = []string{
	".git", "node_modules", "vendor", ".cache", "dist", "build",
	"__pycache__", ".tox", ".mypy_cache", "target", ".idea", ".vscode",
}

var defaultSkipExts = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
	".mp4", ".mp3", ".mov", ".avi", ".wav",
	".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
	".exe", ".dll", ".so", ".dylib", ".bin",
	".pdf", ".docx", ".xlsx", ".pptx",
	".lock", // go.sum, package-lock.json — too noisy
	".sum",
}

// Scanner scans files for secrets.
type Scanner struct {
	cfg Config
}

// New creates a Scanner with the given configuration.
func New(cfg Config) *Scanner {
	cfg.defaults()
	return &Scanner{cfg: cfg}
}

// ScanFile scans a single file and returns all findings.
func (s *Scanner) ScanFile(path string) ([]Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > s.cfg.MaxFileSizeKB*1024 {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// skip binary files
	if isBinary(data) {
		return nil, nil
	}

	return s.scanBytes(path, data), nil
}

// ScanDir recursively scans a directory and returns all findings.
func (s *Scanner) ScanDir(root string) ([]Finding, error) {
	type work struct{ path string }

	paths := make(chan work, 512)
	results := make(chan []Finding, 512)

	// producer: walk the tree
	go func() {
		defer close(paths)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if s.shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if s.shouldSkipFile(path, d) {
				return nil
			}
			if s.isAllowedPath(path) {
				return nil
			}
			paths <- work{path}
			return nil
		})
	}()

	// workers
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range paths {
				findings, _ := s.ScanFile(w.path)
				if len(findings) > 0 {
					results <- findings
				}
			}
		}()
	}

	// close results when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	var all []Finding
	for batch := range results {
		all = append(all, batch...)
	}
	return all, nil
}

// ScanBytes scans an in-memory buffer as if it were the given file path.
func (s *Scanner) ScanBytes(path string, data []byte) []Finding {
	return s.scanBytes(path, data)
}

// ── internal ─────────────────────────────────────────────────────────────────

func (s *Scanner) scanBytes(path string, data []byte) []Finding {
	var findings []Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		lower := strings.ToLower(line)

		for _, rule := range s.cfg.Rules {
			if !keywordMatch(lower, rule.Keywords) {
				continue
			}
			fullMatch, secret, ok := rule.match(line)
			if !ok || secret == "" {
				continue
			}
			col := strings.Index(line, fullMatch)
			if col < 0 {
				col = 0
			}
			findings = append(findings, Finding{
				RuleID:      rule.ID,
				Description: rule.Description,
				Severity:    rule.Severity,
				File:        path,
				Line:        lineNum,
				Column:      col + 1,
				Match:       line,
				Secret:      secret,
				Entropy:     ShannonEntropy(secret),
				Tags:        rule.Tags,
			})
		}
	}
	return findings
}

func (s *Scanner) shouldSkipDir(name string) bool {
	for _, skip := range s.cfg.SkipDirs {
		if name == skip {
			return true
		}
	}
	return false
}

func (s *Scanner) shouldSkipFile(path string, d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil {
		return true
	}
	if info.Size() > s.cfg.MaxFileSizeKB*1024 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, skip := range s.cfg.SkipExts {
		if ext == skip {
			return true
		}
	}
	return false
}

func (s *Scanner) isAllowedPath(path string) bool {
	for _, allow := range s.cfg.AllowPaths {
		if strings.Contains(path, allow) {
			return true
		}
	}
	return false
}

// keywordMatch returns true when at least one keyword appears in the lowercased line.
// An empty keyword list means "always scan this line".
func keywordMatch(lower string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isBinary reports whether data looks like a binary file.
// Uses the same heuristic as git: if the first 8 KB contains a NUL byte it's binary.
func isBinary(data []byte) bool {
	check := data
	if len(check) > 8192 {
		check = check[:8192]
	}
	return bytes.ContainsRune(check, 0)
}
