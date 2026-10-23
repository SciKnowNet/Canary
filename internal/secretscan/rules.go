package secretscan

import "regexp"

// Rule defines a single secret detection pattern.
type Rule struct {
	ID               string
	Description      string
	Severity         Severity
	Regex            *regexp.Regexp
	SecretGroup      int     // capture group index that holds the actual secret
	Keywords         []string // fast pre-filter: at least one must appear in the line (lowercased)
	EntropyThreshold float64  // 0 = no entropy check required
	Tags             []string
	Allowlist        []*regexp.Regexp // matches that should be ignored
}

// match returns the full match and the secret group value, or ("","") if no match.
func (r *Rule) match(line string) (fullMatch, secret string, ok bool) {
	m := r.Regex.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	full := m[0]
	sec := m[0]
	if r.SecretGroup > 0 && r.SecretGroup < len(m) {
		sec = m[r.SecretGroup]
	}
	// entropy gate
	if r.EntropyThreshold > 0 && !IsHighEntropy(sec, r.EntropyThreshold) {
		return "", "", false
	}
	// allowlist
	for _, al := range r.Allowlist {
		if al.MatchString(line) {
			return "", "", false
		}
	}
	return full, sec, true
}

// DefaultRules returns the full built-in rule set.
func DefaultRules() []*Rule {
	return []*Rule{

		// ── AWS ──────────────────────────────────────────────────────────────
		{
			ID:          "aws-access-key-id",
			Description: "AWS Access Key ID",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`(?:^|[^A-Z0-9])(AKIA[A-Z0-9]{16})(?:[^A-Z0-9]|$)`),
			SecretGroup: 1,
			Keywords:    []string{"akia"},
			Tags:        []string{"aws", "cloud"},
		},
		{
			ID:          "aws-secret-access-key",
			Description: "AWS Secret Access Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`(?i)(?:aws[_\-\s.]?secret[_\-\s.]?(?:access[_\-\s.]?)?key|AWS_SECRET)[^\S\r\n]*[=:][^\S\r\n]*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"aws_secret", "aws secret"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"aws", "cloud"},
		},
		{
			ID:          "aws-mws-key",
			Description: "AWS MWS Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			Keywords:    []string{"amzn.mws."},
			Tags:        []string{"aws"},
		},

		// ── GitHub ───────────────────────────────────────────────────────────
		{
			ID:          "github-pat",
			Description: "GitHub Personal Access Token (classic)",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Keywords:    []string{"ghp_"},
			Tags:        []string{"github", "vcs"},
		},
		{
			ID:          "github-fine-grained-pat",
			Description: "GitHub Fine-Grained Personal Access Token",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
			Keywords:    []string{"github_pat_"},
			Tags:        []string{"github", "vcs"},
		},
		{
			ID:          "github-oauth",
			Description: "GitHub OAuth Access Token",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
			Keywords:    []string{"gho_"},
			Tags:        []string{"github"},
		},
		{
			ID:          "github-app-token",
			Description: "GitHub App Token",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`(?:ghu|ghs)_[A-Za-z0-9]{36}`),
			Keywords:    []string{"ghu_", "ghs_"},
			Tags:        []string{"github"},
		},
		{
			ID:          "github-refresh-token",
			Description: "GitHub Refresh Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`ghr_[A-Za-z0-9]{76}`),
			Keywords:    []string{"ghr_"},
			Tags:        []string{"github"},
		},

		// ── GitLab ───────────────────────────────────────────────────────────
		{
			ID:          "gitlab-pat",
			Description: "GitLab Personal Access Token",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20}`),
			Keywords:    []string{"glpat-"},
			Tags:        []string{"gitlab", "vcs"},
		},

		// ── Google ───────────────────────────────────────────────────────────
		{
			ID:          "google-api-key",
			Description: "Google API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Keywords:    []string{"aiza"},
			Tags:        []string{"google", "cloud"},
		},
		{
			ID:          "google-oauth",
			Description: "Google OAuth Client Secret",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`GOCSPX-[A-Za-z0-9_\-]{28}`),
			Keywords:    []string{"gocspx-"},
			Tags:        []string{"google"},
		},
		{
			ID:          "google-service-account",
			Description: "Google Service Account JSON",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
			Keywords:    []string{"service_account"},
			Tags:        []string{"google", "cloud"},
		},

		// ── OpenAI / Anthropic / OpenRouter ──────────────────────────────────
		{
			ID:          "openai-api-key",
			Description: "OpenAI API Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
			Keywords:    []string{"sk-"},
			Tags:        []string{"openai", "ai"},
		},
		{
			ID:          "openai-api-key-v2",
			Description: "OpenAI API Key (project)",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{50,150}`),
			Keywords:    []string{"sk-proj-"},
			Tags:        []string{"openai", "ai"},
		},
		{
			ID:          "anthropic-api-key",
			Description: "Anthropic API Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sk-ant-(?:api03-)?[A-Za-z0-9_\-]{93,}`),
			Keywords:    []string{"sk-ant-"},
			Tags:        []string{"anthropic", "ai"},
		},
		{
			ID:          "openrouter-api-key",
			Description: "OpenRouter API Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sk-or-v1-[A-Za-z0-9]{64}`),
			Keywords:    []string{"sk-or-"},
			Tags:        []string{"openrouter", "ai"},
		},

		// ── Stripe ───────────────────────────────────────────────────────────
		{
			ID:          "stripe-secret-key",
			Description: "Stripe Secret Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			Keywords:    []string{"sk_live_"},
			Tags:        []string{"stripe", "payment"},
		},
		{
			ID:          "stripe-restricted-key",
			Description: "Stripe Restricted Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`),
			Keywords:    []string{"rk_live_"},
			Tags:        []string{"stripe", "payment"},
		},
		{
			ID:          "stripe-test-key",
			Description: "Stripe Test Key",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
			Keywords:    []string{"sk_test_"},
			Tags:        []string{"stripe", "payment"},
		},

		// ── Slack ────────────────────────────────────────────────────────────
		{
			ID:          "slack-bot-token",
			Description: "Slack Bot Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			Keywords:    []string{"xoxb-"},
			Tags:        []string{"slack"},
		},
		{
			ID:          "slack-user-token",
			Description: "Slack User Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}`),
			Keywords:    []string{"xoxp-"},
			Tags:        []string{"slack"},
		},
		{
			ID:          "slack-workspace-token",
			Description: "Slack Workspace Access Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`xoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}`),
			Keywords:    []string{"xoxa-"},
			Tags:        []string{"slack"},
		},
		{
			ID:          "slack-webhook",
			Description: "Slack Incoming Webhook",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}`),
			Keywords:    []string{"hooks.slack.com"},
			Tags:        []string{"slack"},
		},

		// ── Cloudflare ───────────────────────────────────────────────────────
		{
			ID:          "cloudflare-api-token",
			Description: "Cloudflare API Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)cloudflare[^\n]{0,30}[=:]\s*['"]?([A-Za-z0-9_\-]{40})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"cloudflare"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"cloudflare"},
		},
		{
			ID:          "cloudflare-global-api-key",
			Description: "Cloudflare Global API Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`(?i)cloudflare[^\n]{0,30}(?:global|api)[^\n]{0,20}[=:]\s*['"]?([a-f0-9]{37})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"cloudflare"},
			Tags:        []string{"cloudflare"},
		},

		// ── Twilio ───────────────────────────────────────────────────────────
		{
			ID:          "twilio-account-sid",
			Description: "Twilio Account SID",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`AC[a-z0-9]{32}`),
			Keywords:    []string{"twilio", "ac"},
			Tags:        []string{"twilio"},
		},
		{
			ID:          "twilio-auth-token",
			Description: "Twilio Auth Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)twilio[^\n]{0,30}[=:]\s*['"]?([a-z0-9]{32})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"twilio"},
			EntropyThreshold: EntropyThresholdHex,
			Tags:        []string{"twilio"},
		},

		// ── SendGrid ─────────────────────────────────────────────────────────
		{
			ID:          "sendgrid-api-key",
			Description: "SendGrid API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
			Keywords:    []string{"sg."},
			Tags:        []string{"sendgrid", "email"},
		},

		// ── Mailgun ──────────────────────────────────────────────────────────
		{
			ID:          "mailgun-api-key",
			Description: "Mailgun API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
			Keywords:    []string{"mailgun", "key-"},
			Tags:        []string{"mailgun", "email"},
		},

		// ── Heroku ───────────────────────────────────────────────────────────
		{
			ID:          "heroku-api-key",
			Description: "Heroku API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)heroku[^\n]{0,30}[=:]\s*['"]?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"heroku"},
			Tags:        []string{"heroku"},
		},

		// ── Databricks / GitHub Actions ───────────────────────────────────
		{
			ID:          "databricks-token",
			Description: "Databricks API Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`dapi[a-h0-9]{32}`),
			Keywords:    []string{"dapi"},
			Tags:        []string{"databricks"},
		},

		// ── Private Keys ─────────────────────────────────────────────────────
		{
			ID:          "private-key-rsa",
			Description: "RSA Private Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			Keywords:    []string{"begin rsa private key"},
			Tags:        []string{"key", "pki"},
		},
		{
			ID:          "private-key-ec",
			Description: "EC Private Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			Keywords:    []string{"begin ec private key"},
			Tags:        []string{"key", "pki"},
		},
		{
			ID:          "private-key-openssh",
			Description: "OpenSSH Private Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			Keywords:    []string{"begin openssh private key"},
			Tags:        []string{"key", "ssh"},
		},
		{
			ID:          "private-key-pgp",
			Description: "PGP Private Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			Keywords:    []string{"begin pgp private key"},
			Tags:        []string{"key", "pgp"},
		},

		// ── JWT ───────────────────────────────────────────────────────────────
		{
			ID:          "jwt",
			Description: "JSON Web Token",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
			Keywords:    []string{"ey"},
			Tags:        []string{"jwt", "auth"},
			Allowlist: []*regexp.Regexp{
				// ignore obviously fake/example JWTs
				regexp.MustCompile(`example|placeholder|your[_\-]?jwt|<jwt>`),
			},
		},

		// ── Generic high-entropy secrets ─────────────────────────────────────
		{
			ID:          "generic-api-key",
			Description: "Generic API Key Assignment",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)[^\S\r\n]*[=:][^\S\r\n]*['"]([A-Za-z0-9_\-+/]{20,64})['"]`),
			SecretGroup: 1,
			Keywords:    []string{"api_key", "apikey", "api_secret", "access_token", "auth_token"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"generic"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:your[_\-]?api[_\-]?key|example|placeholder|xxxx|1234|test)`),
			},
		},
		{
			ID:          "generic-password",
			Description: "Hardcoded Password Assignment",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)[^\S\r\n]*[=:][^\S\r\n]*['"]([^'"]{8,})['"]`),
			SecretGroup: 1,
			Keywords:    []string{"password", "passwd", "pwd"},
			EntropyThreshold: 3.0,
			Tags:        []string{"generic", "password"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:your[_\-]?password|example|placeholder|changeme|change_me|<password>|\$\{|%s|%v|\{\{)`),
			},
		},
		{
			ID:          "generic-secret",
			Description: "Hardcoded Secret Assignment",
			Severity:    SeverityMedium,
			Regex:       regexp.MustCompile(`(?i)(?:secret[_\-]?key|app[_\-]?secret|client[_\-]?secret|jwt[_\-]?secret)[^\S\r\n]*[=:][^\S\r\n]*['"]([^'"]{16,})['"]`),
			SecretGroup: 1,
			Keywords:    []string{"secret_key", "app_secret", "client_secret", "jwt_secret"},
			EntropyThreshold: 3.2,
			Tags:        []string{"generic"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:your[_\-\s]?secret|example|placeholder|changeme|\$\{|%s|\{\{)`),
			},
		},

		// ── Database connection strings ───────────────────────────────────────
		{
			ID:          "postgres-connection-string",
			Description: "PostgreSQL Connection String with credentials",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`postgres(?:ql)?://[^:]+:([^@\s'"]{6,})@[^\s'"]+`),
			SecretGroup: 1,
			Keywords:    []string{"postgres://", "postgresql://"},
			Tags:        []string{"database", "postgres"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:password|passwd|example|localhost|127\.0\.0\.1).*(?:password|passwd|example)`),
			},
		},
		{
			ID:          "mysql-connection-string",
			Description: "MySQL Connection String with credentials",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`mysql://[^:]+:([^@\s'"]{6,})@[^\s'"]+`),
			SecretGroup: 1,
			Keywords:    []string{"mysql://"},
			Tags:        []string{"database", "mysql"},
		},
		{
			ID:          "mongodb-connection-string",
			Description: "MongoDB Connection String with credentials",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`mongodb(?:\+srv)?://[^:]+:([^@\s'"]{6,})@[^\s'"]+`),
			SecretGroup: 1,
			Keywords:    []string{"mongodb://", "mongodb+srv://"},
			Tags:        []string{"database", "mongodb"},
		},

		// ── npm / PyPI tokens ─────────────────────────────────────────────────
		{
			ID:          "npm-token",
			Description: "npm Access Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?:npm_|//registry\.npmjs\.org/:_authToken=)([A-Za-z0-9_\-]{36,})`),
			SecretGroup: 1,
			Keywords:    []string{"npm_", "_authtoken"},
			Tags:        []string{"npm", "package"},
		},
		{
			ID:          "pypi-token",
			Description: "PyPI API Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{70,}`),
			Keywords:    []string{"pypi-"},
			Tags:        []string{"pypi", "package"},
		},

		// ── Vercel / Netlify / Supabase / PlanetScale ─────────────────────────
		{
			ID:          "vercel-token",
			Description: "Vercel Access Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)vercel[^\n]{0,30}[=:]\s*['"]?([A-Za-z0-9]{24})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"vercel"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"vercel"},
		},
		{
			ID:          "supabase-service-role-key",
			Description: "Supabase Service Role Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`sbp_[A-Za-z0-9]{40}`),
			Keywords:    []string{"sbp_"},
			Tags:        []string{"supabase"},
		},

		// ── crates.io ─────────────────────────────────────────────────────────
		{
			// Matches the token field in ~/.cargo/credentials.toml and CI env vars.
			// New asymmetric tokens (2023+) start with "cio"; classic tokens are
			// arbitrary alphanumeric strings detected via context + entropy.
			ID:          "cratesio-api-token",
			Description: "crates.io API Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)(?:cargo[_\-\s.]?(?:registry[_\-\s.]?)?token|crates[_\-\s.]?(?:io[_\-\s.]?)?(?:api[_\-\s.]?)?(?:token|key)|CARGO_REGISTRY_TOKEN)[^\S\r\n]*[=:][^\S\r\n]*['"]?([A-Za-z0-9_\-]{32,})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"cargo", "crates"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"cratesio", "rust", "package"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:example|placeholder|your[_\-]?token|\$\{|\{\{|%s)`),
			},
		},
		{
			// Explicit prefix for new asymmetric crates.io tokens.
			ID:          "cratesio-asymmetric-token",
			Description: "crates.io Asymmetric API Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`cio[a-zA-Z0-9]{50,}`),
			Keywords:    []string{"cio"},
			Tags:        []string{"cratesio", "rust", "package"},
		},

		// ── LuaRocks ──────────────────────────────────────────────────────────
		{
			// Appears in ~/.luarocks/upload_config.lua and CI pipelines.
			ID:          "luarocks-api-key",
			Description: "LuaRocks API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)(?:luarocks[^\n]{0,30})?key\s*=\s*['"]([A-Za-z0-9]{40,})['"]`),
			SecretGroup: 1,
			Keywords:    []string{"luarocks"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"luarocks", "lua", "package"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:example|placeholder|your[_\-]?key|\$\{|\{\{)`),
			},
		},

		// ── Maven Central / Sonatype OSSRH ────────────────────────────────────
		{
			// Sonatype user tokens in settings.xml / CI: <password>TOKEN</password>
			// when the username is a Sonatype token identity (starts with a digit
			// and contains only alphanumeric + hyphen chars, 20–40 chars).
			ID:          "sonatype-ossrh-token",
			Description: "Sonatype OSSRH / Maven Central User Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)(?:sonatype|ossrh|maven[_\-\s.]?central)[^\n]{0,60}(?:password|token)[^\n]{0,30}[>=:]\s*['"]?([A-Za-z0-9+/]{20,60}=*)['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"sonatype", "ossrh", "maven"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"maven", "sonatype", "java", "package"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:example|placeholder|\$\{|\{\{|%s)`),
			},
		},
		{
			// Catches the <password> block inside a <server> block that also
			// references sonatype/ossrh — common Maven settings.xml pattern.
			ID:          "maven-settings-password",
			Description: "Maven settings.xml Hardcoded Password (Sonatype context)",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`<password>([A-Za-z0-9+/=_\-]{20,})</password>`),
			SecretGroup: 1,
			Keywords:    []string{"<password>", "sonatype", "ossrh"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"maven", "xml", "package"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:example|placeholder|\$\{)`),
			},
		},

		// ── RubyGems ──────────────────────────────────────────────────────────
		{
			// ~/.gem/credentials stores: rubygems_api_key: <hex48>
			// The key is always lowercase hex, exactly 48 chars in the classic format.
			ID:          "rubygems-api-key",
			Description: "RubyGems API Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`rubygems_api_key[:\s=]+['"]?([a-f0-9]{48})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"rubygems_api_key"},
			Tags:        []string{"rubygems", "ruby", "package"},
		},
		{
			// New RubyGems token format (2024+): rg_ prefix.
			ID:          "rubygems-api-key-v2",
			Description: "RubyGems API Key (rg_ prefix)",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`rg_[A-Za-z0-9]{48,}`),
			Keywords:    []string{"rg_"},
			Tags:        []string{"rubygems", "ruby", "package"},
		},
		{
			// Catches GEM_HOST_API_KEY env var and inline assignments.
			ID:          "rubygems-env-key",
			Description: "RubyGems GEM_HOST_API_KEY",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`GEM_HOST_API_KEY[^\S\r\n]*[=:][^\S\r\n]*['"]?([A-Za-z0-9+/=]{30,})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"gem_host_api_key"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"rubygems", "ruby", "package"},
		},

		// ── Open VSX ──────────────────────────────────────────────────────────
		{
			// Personal access tokens used by the ovsx CLI to publish extensions.
			// Stored as OVSX_PAT env var or passed via --pat flag.
			// Typical format: UUID v4 or a long alphanumeric string issued by
			// open-vsx.org / Eclipse Foundation identity service.
			ID:          "openvsx-pat",
			Description: "Open VSX Personal Access Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)(?:ovsx[_\-\s.]?(?:token|pat|api[_\-\s.]?key)|OVSX_PAT)[^\S\r\n]*[=:][^\S\r\n]*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
			SecretGroup: 1,
			Keywords:    []string{"ovsx", "openvsx", "open_vsx", "open-vsx"},
			EntropyThreshold: EntropyThresholdBase64,
			Tags:        []string{"openvsx", "vscode", "package"},
			Allowlist: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(?:example|placeholder|your[_\-]?token|\$\{|\{\{)`),
			},
		},
	}
}
