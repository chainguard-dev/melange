// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linters

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
)

/*
Rules:
- Rule A: At least one source must use templates (e.g., ${{package.version}})
- Rule B: Fetch URLs with hardcoded package versions should use version templates
- Rule C: Git tags with hardcoded versions should use version templates
- Rule D: Git branches/refs require expected-commit for reproducibility

Supports version transforms: ${{package.version | replace: ".", "_"}} and ${{vars.version}}
*/

// Holds git checkout reference information for Rule D validation
type gitRefInfo struct {
	Branch         string
	Ref            string
	Tag            string
	ExpectedCommit string
}

// Holds compiled regex patterns for a specific package
type packagePatterns struct {
	exactVersionURL   *regexp.Regexp
	anyVersionURL     *regexp.Regexp
	exactVersionTag   *regexp.Regexp
	packageVersionTag *regexp.Regexp
}

// Holds extracted pipeline data
type sourceData struct {
	fetchURLs   []string
	gitTags     []string
	gitBranches []gitRefInfo
}

// Handles validation logic with pre-compiled patterns
type validator struct {
	pkg      packageInfo
	patterns *packagePatterns
}

// Holds package metadata
type packageInfo struct {
	name    string
	version string
}

var (
	anyTemplateRegex     = regexp.MustCompile(`\$\{\{[^}]+\}\}`)
	versionTemplateRegex = regexp.MustCompile(`\$\{\{\s*(package\.(version|full-version)|vars\.[^}]*\bversion\b[^}]*)[^}]*\}\}`)
	shaRegex             = regexp.MustCompile(`^[0-9a-fA-F]{12,40}$`)
)

func (s sourceData) isEmpty() bool {
	return len(s.fetchURLs) == 0 && len(s.gitTags) == 0 && len(s.gitBranches) == 0
}

// Creates compiled regex patterns for package-specific validation
func buildPackagePatterns(packageName, packageVersion string) *packagePatterns {
	if packageName == "" || packageVersion == "" {
		return nil
	}

	escName := regexp.QuoteMeta(packageName)
	escVer := regexp.QuoteMeta(packageVersion)

	return &packagePatterns{
		exactVersionURL: regexp.MustCompile(
			`(?:^|/)` + escName +
				`(?:[-_]v?` + escVer + `(?:\.tar\.(?:gz|bz2|xz)|\.zip|\.tgz|\.tbz2|\.txz)` +
				`|/v?` + escVer + `/)`),
		anyVersionURL: regexp.MustCompile(
			`(?:^|/)` + escName +
				`(?:[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?` +
				`|/v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?/)`),
		exactVersionTag:   regexp.MustCompile(`^v?` + escVer + `$`),
		packageVersionTag: regexp.MustCompile(`^` + escName + `[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?$`),
	}
}

// Fetch sources and git data from raw YAML before template substitution
func extractRawPipelineData(root *yaml.Node) sourceData {
	var fetchSources []string
	var gitTags []string
	var gitBranchRefs []gitRefInfo

	if root == nil {
		return sourceData{
			fetchURLs:   fetchSources,
			gitTags:     gitTags,
			gitBranches: gitBranchRefs,
		}
	}

	// Unwrap DocumentNode to get content
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}

	findValue := func(mapping *yaml.Node, key string) *yaml.Node {
		if mapping.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i < len(mapping.Content); i += 2 {
			if i+1 < len(mapping.Content) && mapping.Content[i].Value == key {
				return mapping.Content[i+1]
			}
		}
		return nil
	}

	getString := func(mapping *yaml.Node, key string) string {
		if node := findValue(mapping, key); node != nil && node.Kind == yaml.ScalarNode {
			return node.Value
		}
		return ""
	}

	var processPipelines func(*yaml.Node)
	processPipelines = func(pipelineSeq *yaml.Node) {
		if pipelineSeq == nil || pipelineSeq.Kind != yaml.SequenceNode {
			return
		}

		for _, step := range pipelineSeq.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}

			uses := getString(step, "uses")
			withNode := findValue(step, "with")

			if uses == "fetch" && withNode != nil {
				if uri := getString(withNode, "uri"); uri != "" {
					fetchSources = append(fetchSources, uri)
				}
			}

			if uses == "git-checkout" && withNode != nil {
				if tag := getString(withNode, "tag"); tag != "" {
					gitTags = append(gitTags, tag)
				}

				branch := getString(withNode, "branch")
				ref := getString(withNode, "ref")
				if branch != "" || ref != "" {
					gitBranchRefs = append(gitBranchRefs, gitRefInfo{
						Branch:         branch,
						Ref:            ref,
						Tag:            getString(withNode, "tag"),
						ExpectedCommit: getString(withNode, "expected-commit"),
					})
				}
			}

			if nestedPipeline := findValue(step, "pipeline"); nestedPipeline != nil {
				processPipelines(nestedPipeline)
			}
		}
	}

	if root.Kind == yaml.MappingNode {
		if mainPipeline := findValue(root, "pipeline"); mainPipeline != nil {
			processPipelines(mainPipeline)
		}

		if subpackages := findValue(root, "subpackages"); subpackages != nil && subpackages.Kind == yaml.SequenceNode {
			for _, subpkg := range subpackages.Content {
				if subPipeline := findValue(subpkg, "pipeline"); subPipeline != nil {
					processPipelines(subPipeline)
				}
			}
		}
	}

	return sourceData{
		fetchURLs:   fetchSources,
		gitTags:     gitTags,
		gitBranches: gitBranchRefs,
	}
}

// Creates a validator with compiled patterns for the package
func newValidator(pkg packageInfo) *validator {
	return &validator{
		pkg:      pkg,
		patterns: buildPackagePatterns(pkg.name, pkg.version),
	}
}

// Validates that package sources use proper templating to avoid version drift.
func FetchTemplatingLinter(_ context.Context, cfg *config.Configuration, _ string, _ fs.FS) error {
	if cfg == nil {
		return nil
	}

	sources := extractRawPipelineData(cfg.Root())
	if sources.isEmpty() {
		return nil
	}

	pkg := packageInfo{
		name:    strings.TrimSpace(cfg.Package.Name),
		version: strings.TrimSpace(cfg.Package.Version),
	}

	validator := newValidator(pkg)
	return validator.validateAll(sources)
}

// Runs all validation rules and returns formatted errors
func (v *validator) validateAll(sources sourceData) error {

	// Rule A: Template requirement
	if err := v.validateRuleA(sources); err != nil {
		return err
	}

	// Rules B, C, D: Collect all other issues
	var allIssues []string
	allIssues = append(allIssues, v.validateRuleB(sources.fetchURLs)...)
	allIssues = append(allIssues, v.validateRuleC(sources.gitTags)...)
	allIssues = append(allIssues, v.validateRuleD(sources.gitBranches)...)

	return v.formatErrors(allIssues)
}

// Checks that at least one source uses templates
func (v *validator) validateRuleA(sources sourceData) error {
	// Rule A: Only count version-bearing sources (fetch URLs and git tags, not branches/refs)
	versionBearingSources := len(sources.fetchURLs) + len(sources.gitTags)
	if versionBearingSources == 0 {
		return nil
	}

	hasAnyTemplate := false
	hasVersionAwareTemplate := false
	var untemplatedSources []string

	// Check fetch URLs
	for _, uri := range sources.fetchURLs {
		if anyTemplateRegex.MatchString(uri) {
			hasAnyTemplate = true
		}
		if versionTemplateRegex.MatchString(uri) {
			hasVersionAwareTemplate = true
		} else {
			untemplatedSources = append(untemplatedSources, fmt.Sprintf("fetch URL: %s", uri))
		}
	}

	// Check git tags
	for _, tag := range sources.gitTags {
		if anyTemplateRegex.MatchString(tag) {
			hasAnyTemplate = true
		}
		if versionTemplateRegex.MatchString(tag) {
			hasVersionAwareTemplate = true
		} else {
			untemplatedSources = append(untemplatedSources, fmt.Sprintf("git tag: %s", tag))
		}
	}

	// Count templated refs for Rule A
	for _, gitData := range sources.gitBranches {
		if gitData.Ref != "" && versionTemplateRegex.MatchString(gitData.Ref) {
			hasAnyTemplate = true
			hasVersionAwareTemplate = true
		}
	}

	// Apply Rule A
	ruleAFails := false
	if versionBearingSources == 1 {
		ruleAFails = !hasAnyTemplate
	} else {
		ruleAFails = !hasVersionAwareTemplate && !hasAnyTemplate
	}

	if ruleAFails {
		return v.formatRuleAError(versionBearingSources, untemplatedSources)
	}
	return nil
}

// Creates Rule A error messages
func (v *validator) formatRuleAError(versionBearingSources int, untemplatedSources []string) error {
	var message string
	switch {
	case versionBearingSources == 1 && len(untemplatedSources) > 0:
		message = fmt.Sprintf("source lacks templated variables: %s\nConsider using ${{package.version}} to ensure URL updates with version changes", untemplatedSources[0])
	case len(untemplatedSources) > 0:
		message = fmt.Sprintf("no templated variables found in any sources:\n- %s\nAt least one origin should use templates like ${{package.version}} to avoid version drift", strings.Join(untemplatedSources, "\n- "))
	default:
		message = "no templated variables found in any fetch URLs or git tags; at least one origin should be parameterized (preferably on version) to avoid drift"
	}
	return fmt.Errorf("%s", message)
}

// Checks fetch URLs for hardcoded versions
func (v *validator) validateRuleB(fetchURLs []string) []string {
	if v.patterns == nil {
		return nil
	}

	var issues []string
	for _, uri := range fetchURLs {
		if versionTemplateRegex.MatchString(uri) {
			continue
		}

		if v.patterns.exactVersionURL.MatchString(uri) {
			issues = append(issues, fmt.Sprintf("fetch URL contains hardcoded package version '%s' for '%s': %s", v.pkg.version, v.pkg.name, uri))
		} else if v.patterns.anyVersionURL.MatchString(uri) {
			issues = append(issues, fmt.Sprintf("fetch URL contains '%s' with hardcoded version (may be out of sync with package.version): %s", v.pkg.name, uri))
		}
	}
	return issues
}

// Checks git tags for hardcoded versions
func (v *validator) validateRuleC(gitTags []string) []string {
	if v.patterns == nil {
		return nil
	}

	var issues []string
	for _, tag := range gitTags {
		if versionTemplateRegex.MatchString(tag) {
			continue
		}

		if v.patterns.exactVersionTag.MatchString(tag) {
			issues = append(issues, fmt.Sprintf("git tag contains hardcoded package version '%s': %s", v.pkg.version, tag))
		} else if v.patterns.packageVersionTag.MatchString(tag) {
			issues = append(issues, fmt.Sprintf("git tag contains '%s' with hardcoded version (may be out of sync with package.version): %s", v.pkg.name, tag))
		}
	}
	return issues
}

// Checks git branches/refs for expected-commit requirement
func (v *validator) validateRuleD(gitBranches []gitRefInfo) []string {
	var issues []string

	for _, gitData := range gitBranches {
		if gitData.Tag == "" && (gitData.Branch != "" || gitData.Ref != "") && gitData.ExpectedCommit == "" {
			// Skip if ref is already a commit SHA
			if gitData.Ref != "" && shaRegex.MatchString(gitData.Ref) {
				continue
			}

			branchOrRef := gitData.Branch
			if branchOrRef == "" {
				branchOrRef = gitData.Ref
			}
			issues = append(issues, fmt.Sprintf("git-checkout branch/ref '%s' requires expected-commit for reproducibility", branchOrRef))
		}
	}
	return issues
}

// Formats validation errors consistently
func (v *validator) formatErrors(allIssues []string) error {
	if len(allIssues) == 0 {
		return nil
	}

	if len(allIssues) == 1 {
		return fmt.Errorf("%s; check whether this should be derived from ${{package.version}} (or a transform)", allIssues[0])
	}

	message := "multiple fetch/git issues found:\n- " + strings.Join(allIssues, "\n- ")
	message += "\nFor version issues: check whether these should be derived from ${{package.version}} (or a transform)"
	return fmt.Errorf("%s", message)
}
