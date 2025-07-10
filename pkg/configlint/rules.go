package configlint

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/renovate"
	"github.com/dprotaso/go-yit"
	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"gopkg.in/yaml.v3"

	"golang.org/x/exp/slices"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/versions"
)

var (
	reValidSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reValidSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	reValidSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	// Be stricter than Go to promote consistency and avoid homograph attacks
	reValidHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9\.\-]+\.[a-z]{2,6}$`)

	forbiddenRepositories = []string{
		"https://packages.wolfi.dev/os",
	}

	forbiddenKeyrings = []string{
		"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
	}

	// Used for comparing hosts between configs
	seenHosts = map[string]bool{}
	// The minimum edit distance between two hostnames
	minhostEditDistance = 2
	// Exceptions to the above rule
	hostEditDistanceExceptions = map[string]string{
		"www.libssh.org": "www.libssh2.org",
	}

	// Detect background processes (commands ending with '&' or '& sleep ...') or daemonized commands
	reBackgroundProcess = regexp.MustCompile(`(?:^|[^&])&(?:\s*$|\s+sleep\b)`) // matches 'cmd &' or 'cmd & sleep'
	reDaemonProcess     = regexp.MustCompile(`.*(?:` + strings.Join(daemonFlags, "|") + `).*`)
	// Detect output redirection in shell commands
	reOutputRedirect = regexp.MustCompile(strings.Join(redirPatterns, "|"))
)

var (
	daemonFlags = []string{
		`(?:^|\s)--daemon\b`,
		`(?:^|\s)--daemonize\b`,
		`(?:^|\s)--detach\b`,
		`(?:^|\s)-daemon\b`,
	}

	redirPatterns = []string{
		`>\s*\S+`,
		`>>\s*\S+`,
		`2>\s*\S+`,
		`2>>\s*\S+`,
		`&>\s*\S+`,
		`&>>\s*\S+`,
		`>\s*\S+.*2>&1`,
		`2>&1.*>\s*\S+`,
		`>\s*/dev/null`,
		`2>\s*/dev/null`,
		`&>\s*/dev/null`,
		`\d+>&\d+`,
	}
)

const gitCheckout = "git-checkout"

// AllRules is a list of all available rules to evaluate.
func AllRules(l *Linter) Rules { //nolint:gocyclo
	return Rules{
		{
			Name:        "forbidden-repository-used",
			Description: "do not specify a forbidden repository",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, repo := range config.Environment.Contents.BuildRepositories {
					if slices.Contains(forbiddenRepositories, repo) {
						return fmt.Errorf("forbidden repository %s is used", repo)
					}
				}
				for _, repo := range config.Environment.Contents.RuntimeRepositories {
					if slices.Contains(forbiddenRepositories, repo) {
						return fmt.Errorf("forbidden repository %s is used", repo)
					}
				}
				return nil
			},
		},
		{
			Name:        "forbidden-keyring-used",
			Description: "do not specify a forbidden keyring",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, keyring := range config.Environment.Contents.Keyring {
					if slices.Contains(forbiddenKeyrings, keyring) {
						return fmt.Errorf("forbidden keyring %s is used", keyring)
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-copyright-header",
			Description: "every package should have a valid copyright header",
			Severity:    SeverityInfo,
			LintFunc: func(config config.Configuration) error {
				if len(config.Package.Copyright) == 0 {
					return fmt.Errorf("copyright header is missing")
				}
				for _, c := range config.Package.Copyright {
					if c.License == "" {
						return fmt.Errorf("license is missing")
					}
				}
				return nil
			},
		},
		{
			Name:        "contains-epoch",
			Description: "every package should have an epoch",
			Severity:    SeverityError,
			LintFunc: func(_ config.Configuration) error {
				var node yaml.Node
				fileInfo, err := os.Stat(l.options.Path)
				if err != nil {
					return err
				}

				if fileInfo.IsDir() {
					return nil
				}

				yamlData, err := os.ReadFile(l.options.Path)
				if err != nil {
					return err
				}

				err = yaml.Unmarshal(yamlData, &node)
				if err != nil {
					return err
				}

				if node.Content == nil {
					return fmt.Errorf("config %s has no yaml content", l.options.Path)
				}

				pkg, err := renovate.NodeFromMapping(node.Content[0], "package")
				if err != nil {
					return err
				}

				if pkg == nil {
					return fmt.Errorf("config %s has no package content", l.options.Path)
				}

				err = containsKey(pkg, "epoch")
				if err != nil {
					return fmt.Errorf("config %s has no package.epoch", l.options.Path)
				}

				return nil
			},
		},
		{
			Name:        "valid-pipeline-fetch-uri",
			Description: "every fetch pipeline should have a valid uri",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					uri, err := extractURI(p)
					if err != nil {
						return err
					}
					if uri == "" {
						continue
					}
					u, err := url.ParseRequestURI(uri)
					if err != nil {
						return fmt.Errorf("uri is invalid URL structure")
					}
					if !reValidHostname.MatchString(u.Host) {
						return fmt.Errorf("uri hostname %q is invalid", u.Host)
					}
				}
				return nil
			},
		},
		{
			Name:        "uri-mimic",
			Description: "every config should use a consistent hostname",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					uri := p.With["uri"]
					if uri == "" {
						continue
					}
					u, err := url.ParseRequestURI(uri)
					if err != nil {
						return nil
					}
					host := u.Host
					if seenHosts[host] {
						continue
					}
					for k := range seenHosts {
						dist := levenshtein.DistanceForStrings([]rune(host), []rune(k), levenshtein.DefaultOptions)
						if hostEditDistanceExceptions[host] == k || hostEditDistanceExceptions[k] == host {
							continue
						}
						if dist <= minhostEditDistance {
							return fmt.Errorf("%q too similar to %q", host, k)
						}

						hostParts := strings.Split(host, ".")
						kParts := strings.Split(k, ".")
						if strings.Join(hostParts[:len(hostParts)-1], ".") == strings.Join(kParts[:len(kParts)-1], ".") {
							return fmt.Errorf("%q shares components with %q", host, k)
						}
					}
					seenHosts[host] = true
				}
				return nil
			},
		},

		{
			Name:        "valid-pipeline-fetch-digest",
			Description: "every fetch pipeline should have a valid digest",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "fetch" {
						hashGiven := false
						if sha256, ok := p.With["expected-sha256"]; ok {
							if !reValidSHA256.MatchString(sha256) {
								return fmt.Errorf("expected-sha256 is not valid SHA256")
							}
							hashGiven = true
						}
						if sha512, ok := p.With["expected-sha512"]; ok {
							if !reValidSHA512.MatchString(sha512) {
								return fmt.Errorf("expected-sha512 is not valid SHA512")
							}
							hashGiven = true
						}
						if !hashGiven {
							return fmt.Errorf("expected-sha256 or expected-sha512 is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "no-repeated-deps",
			Description: "no repeated dependencies",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				seen := map[string]struct{}{}
				for _, p := range config.Environment.Contents.Packages {
					if _, ok := seen[p]; ok {
						return fmt.Errorf("package %s is duplicated in environment", p)
					}
					seen[p] = struct{}{}
				}
				return nil
			},
		},
		{
			Name:        "bad-template-var",
			Description: "bad template variable",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				badTemplateVars := []string{
					"$pkgdir",
					"$pkgver",
					"$pkgname",
					"$srcdir",
				}

				hasBadVar := func(runs string) error {
					for _, badVar := range badTemplateVars {
						if strings.Contains(runs, badVar) {
							return fmt.Errorf("package contains likely incorrect template var %s", badVar)
						}
					}
					return nil
				}

				for _, s := range config.Pipeline {
					if err := hasBadVar(s.Runs); err != nil {
						return err
					}
				}

				for _, subPkg := range config.Subpackages {
					for _, subPipeline := range subPkg.Pipeline {
						if err := hasBadVar(subPipeline.Runs); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "bad-version",
			Description: "version is malformed",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				version := config.Package.Version
				if err := versions.ValidateWithoutEpoch(version); err != nil {
					return fmt.Errorf("invalid version %s, could not parse", version)
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-git-checkout-commit",
			Description: "every git-checkout pipeline should have a valid expected-commit",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout {
						if commit, ok := p.With["expected-commit"]; ok {
							if !reValidSHA1.MatchString(commit) {
								return fmt.Errorf("expected-commit is not valid SHA1")
							}
						} else {
							return fmt.Errorf("expected-commit is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-git-checkout-tag",
			Description: "every git-checkout pipeline should have a tag",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout {
						if _, ok := p.With["tag"]; !ok {
							return fmt.Errorf("tag is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "check-when-version-changes",
			Description: "check comments to make sure they are updated when version changes",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				re := regexp.MustCompile(`# CHECK-WHEN-VERSION-CHANGES: (.+)`)
				checkString := func(s string) error {
					match := re.FindStringSubmatch(s)
					if len(match) == 0 {
						return nil
					}
					for _, m := range match[1:] {
						if m != config.Package.Version {
							return fmt.Errorf("version in comment: %s does not match version in package: %s, check that it can be updated and update the comment", m, config.Package.Version)
						}
					}
					return nil
				}
				for _, p := range config.Pipeline {
					if err := checkString(p.Runs); err != nil {
						return err
					}
				}
				for _, subPkg := range config.Subpackages {
					for _, subPipeline := range subPkg.Pipeline {
						if err := checkString(subPipeline.Runs); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "tagged-repository-in-environment-repos",
			Description: "remove tagged repositories like @local from the repositories block",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, repo := range config.Environment.Contents.BuildRepositories {
					if repo[0] == '@' {
						return fmt.Errorf("repository %q is tagged", repo)
					}
				}
				for _, repo := range config.Environment.Contents.RuntimeRepositories {
					if repo[0] == '@' {
						return fmt.Errorf("repository %q is tagged", repo)
					}
				}
				return nil
			},
		},
		{
			Name:        "git-checkout-must-use-github-updates",
			Description: "when using git-checkout, must use github/git updates so we can get the expected-commit",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout && strings.HasPrefix(p.With["repository"], "https://github.com/") {
						if config.Update.Enabled && config.Update.GitHubMonitor == nil && config.Update.GitMonitor == nil {
							return fmt.Errorf("configure update.github/update.git when using git-checkout")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-spdx-license",
			Description: "every package should have a valid SPDX license",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, c := range config.Package.Copyright {
					switch c.License {
					case "custom", "PROPRIETARY":
						continue
					}
					if valid, _ := spdxexp.ValidateLicenses([]string{c.License}); !valid {
						return fmt.Errorf("license %q is not valid SPDX license", c.License)
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-package-or-subpackage-test",
			Description: "every package should have a valid main or subpackage test",
			Severity:    SeverityInfo,
			LintFunc: func(c config.Configuration) error {
				if c.Test != nil && len(c.Test.Pipeline) > 0 {
					return nil
				}
				for _, sp := range c.Subpackages {
					if sp.Test != nil && len(sp.Test.Pipeline) > 0 {
						return nil
					}
				}
				return fmt.Errorf("no main package or subpackage test found")
			},
		},
		{
			Name:        "update-disabled-reason",
			Description: "packages with auto-update disabled should have a reason",
			Severity:    SeverityWarning,
			LintFunc: func(c config.Configuration) error {
				cfg := c.Update
				if cfg.Enabled {
					return nil
				}
				if !cfg.Enabled && cfg.ExcludeReason != "" {
					return nil
				}
				return fmt.Errorf("auto-update is disabled but no reason is provided")
			},
		},
		{
			Name:        "background-process-without-redirect",
			Description: "test steps should redirect output when running background processes",
			Severity:    SeverityWarning,
			LintFunc: func(c config.Configuration) error {
				checkSteps := func(steps []config.Pipeline) error {
					for _, s := range steps {
						if s.Runs == "" {
							continue
						}
						lines := strings.Split(s.Runs, "\n")
						for i, line := range lines {
							checkLine := line
							if strings.Contains(line, "&") && i+1 < len(lines) {
								checkLine += "\n" + lines[i+1]
							}
							needsRedirect := reBackgroundProcess.MatchString(checkLine) || reDaemonProcess.MatchString(line)
							if needsRedirect && !reOutputRedirect.MatchString(line) {
								return fmt.Errorf("background process missing output redirect: %s", strings.TrimSpace(line))
							}
						}
					}
					return nil
				}
				if c.Test != nil {
					if err := checkSteps(c.Test.Pipeline); err != nil {
						return err
					}
				}
				for _, sp := range c.Subpackages {
					if sp.Test != nil {
						if err := checkSteps(sp.Test.Pipeline); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-update-schedule",
			Description: "update schedule config should contain a valid period",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				if config.Update.Schedule == nil {
					return nil
				}
				_, err := config.Update.Schedule.GetScheduleMessage()
				return err
			},
		},
	}
}

func containsKey(parentNode *yaml.Node, key string) error {
	it := yit.FromNode(parentNode).
		ValuesForMap(yit.WithValue(key), yit.All)

	if _, ok := it(); ok {
		return nil
	}

	return fmt.Errorf("key '%s' not found in mapping", key)
}

func extractURI(p config.Pipeline) (string, error) {
	if p.Uses == "fetch" {
		uri, ok := p.With["uri"]
		if !ok {
			return "", fmt.Errorf("uri is missing in fetch pipeline")
		}
		return uri, nil
	}

	if p.Uses == "git-checkout" {
		repo, ok := p.With["repository"]
		if !ok {
			return "", fmt.Errorf("repository is missing in git-checkout pipeline")
		}
		return repo, nil
	}

	return "", nil
}
