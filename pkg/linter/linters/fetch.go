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

	"chainguard.dev/melange/pkg/config"
	"gopkg.in/yaml.v3"
)

/*
Rules:
- Rule A: At least one source must use templates (e.g., ${{package.version}})
- Rule B: Fetch URLs with hardcoded package versions should use version templates
- Rule C: Git tags with hardcoded versions should use version templates
- Rule D: Git branches/refs require expected-commit for reproducibility

Supports version transforms: ${{package.version | replace: ".", "_"}} and ${{vars.version}}
*/

// gitRefInfo holds git checkout reference information for Rule D validation
type gitRefInfo struct {
	Branch         string
	Ref            string
	Tag            string
	ExpectedCommit string
}

var (
	anyTemplateRegex     = regexp.MustCompile(`\$\{\{[^}]+\}\}`)
	versionTemplateRegex = regexp.MustCompile(`\$\{\{\s*(package\.(version|full-version)|vars\.[^}]*\bversion\b[^}]*)[^}]*\}\}`)
)

// Extracts fetch sources and git data from raw YAML before template substitution
func extractRawPipelineData(root *yaml.Node) ([]string, []string, []gitRefInfo) {
	var fetchSources []string
	var gitTags []string
	var gitBranchRefs []gitRefInfo

	if root == nil {
		return fetchSources, gitTags, gitBranchRefs
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

	return fetchSources, gitTags, gitBranchRefs
}

// Validates that package sources use proper templating to avoid version drift.
func FetchTemplatingLinter(_ context.Context, cfg *config.Configuration, _ string, _ fs.FS) error {
	if cfg == nil {
		return nil
	}

	fetchSources, gitTags, gitBranchRefs := extractRawPipelineData(cfg.Root())

	totalSources := len(fetchSources) + len(gitTags) + len(gitBranchRefs)
	if totalSources == 0 {
		return nil
	}

	// Rule A: Only count version-bearing sources (fetch URLs and git tags, not branches/refs)
	versionBearingSources := len(fetchSources) + len(gitTags)
	if versionBearingSources > 0 {
		hasAnyTemplate := false
		hasVersionAwareTemplate := false
		var untemplatedSources []string

		for _, uri := range fetchSources {
			if anyTemplateRegex.MatchString(uri) {
				hasAnyTemplate = true
			}
			if versionTemplateRegex.MatchString(uri) {
				hasVersionAwareTemplate = true
			} else {
				untemplatedSources = append(untemplatedSources, fmt.Sprintf("fetch URL: %s", uri))
			}
		}

		for _, tag := range gitTags {
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
		for _, gitData := range gitBranchRefs {
			if gitData.Ref != "" && versionTemplateRegex.MatchString(gitData.Ref) {
				hasAnyTemplate = true
				hasVersionAwareTemplate = true
			}
		}

		ruleAFails := false
		if versionBearingSources == 1 {
			ruleAFails = !hasAnyTemplate
		} else {
			ruleAFails = !hasVersionAwareTemplate && !hasAnyTemplate
		}

		if ruleAFails {
			var message string
			if versionBearingSources == 1 && len(untemplatedSources) > 0 {
				message = fmt.Sprintf("source lacks templated variables: %s\nConsider using ${{package.version}} to ensure URL updates with version changes", untemplatedSources[0])
			} else if len(untemplatedSources) > 0 {
				message = fmt.Sprintf("no templated variables found in any sources:\n- %s\nAt least one origin should use templates like ${{package.version}} to avoid version drift", strings.Join(untemplatedSources, "\n- "))
			} else {
				message = "no templated variables found in any fetch URLs or git tags; at least one origin should be parameterized (preferably on version) to avoid drift"
			}
			return fmt.Errorf(message)
		}
	}

	var ruleBIssues []string
	packageName := strings.TrimSpace(cfg.Package.Name)
	packageVersion := strings.TrimSpace(cfg.Package.Version)

	// Skip Rule B if package version is empty
	if packageVersion == "" {
		packageName = ""
	}

	var pkgExactVersionRegex *regexp.Regexp
	if packageName != "" && packageVersion != "" {
		escName := regexp.QuoteMeta(packageName)
		escVer := regexp.QuoteMeta(packageVersion)
		pkgExactVersionRegex = regexp.MustCompile(
			`(?:^|/)` + escName +
				`(?:[-_]v?` + escVer + `(?:\.tar\.(?:gz|bz2|xz)|\.zip|\.tgz|\.tbz2|\.txz)` +
				`|/v?` + escVer + `/)`)
	}

	var pkgAnyVersionRegex *regexp.Regexp
	if packageName != "" {
		escName := regexp.QuoteMeta(packageName)
		pkgAnyVersionRegex = regexp.MustCompile(
			`(?:^|/)` + escName +
				`(?:[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?` +
				`|/v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?/)`)
	}

	for _, uri := range fetchSources {
		if versionTemplateRegex.MatchString(uri) {
			continue
		}

		if pkgExactVersionRegex != nil && pkgExactVersionRegex.MatchString(uri) {
			ruleBIssues = append(ruleBIssues, fmt.Sprintf("fetch URL contains hardcoded package version '%s' for '%s': %s", packageVersion, packageName, uri))
		} else if pkgAnyVersionRegex != nil && pkgAnyVersionRegex.MatchString(uri) {
			ruleBIssues = append(ruleBIssues, fmt.Sprintf("fetch URL contains '%s' with hardcoded version (may be out of sync with package.version): %s", packageName, uri))
		}
	}

	var ruleCIssues []string

	var tagExactVersionRegex *regexp.Regexp
	var tagPackageVersionRegex *regexp.Regexp

	if packageVersion != "" {
		escVer := regexp.QuoteMeta(packageVersion)
		tagExactVersionRegex = regexp.MustCompile(`^v?` + escVer + `$`)
	}

	if packageName != "" {
		escName := regexp.QuoteMeta(packageName)
		tagPackageVersionRegex = regexp.MustCompile(`^` + escName + `[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?$`)
	}

	for _, tag := range gitTags {
		if versionTemplateRegex.MatchString(tag) {
			continue
		}

		if tagExactVersionRegex != nil && tagExactVersionRegex.MatchString(tag) {
			ruleCIssues = append(ruleCIssues, fmt.Sprintf("git tag contains hardcoded package version '%s': %s", packageVersion, tag))
		} else if tagPackageVersionRegex != nil && tagPackageVersionRegex.MatchString(tag) {
			ruleCIssues = append(ruleCIssues, fmt.Sprintf("git tag contains '%s' with hardcoded version (may be out of sync with package.version): %s", packageName, tag))
		}
	}

	var ruleDIssues []string

	shaRegex := regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

	for _, gitData := range gitBranchRefs {
		if gitData.Tag == "" && (gitData.Branch != "" || gitData.Ref != "") && gitData.ExpectedCommit == "" {
			// Skip if ref is already a commit SHA
			if gitData.Ref != "" && shaRegex.MatchString(gitData.Ref) {
				continue
			}

			branchOrRef := gitData.Branch
			if branchOrRef == "" {
				branchOrRef = gitData.Ref
			}
			ruleDIssues = append(ruleDIssues, fmt.Sprintf("git-checkout branch/ref '%s' requires expected-commit for reproducibility", branchOrRef))
		}
	}

	var allIssues []string
	allIssues = append(allIssues, ruleBIssues...)
	allIssues = append(allIssues, ruleCIssues...)
	allIssues = append(allIssues, ruleDIssues...)

	if len(allIssues) > 0 {
		hasVersionIssues := len(ruleBIssues) > 0 || len(ruleCIssues) > 0
		hasReproducibilityIssues := len(ruleDIssues) > 0

		if len(allIssues) == 1 {
			if hasReproducibilityIssues && !hasVersionIssues {
				return fmt.Errorf("%s", allIssues[0])
			}
			return fmt.Errorf("%s; check whether this should be derived from ${{package.version}} (or a transform)", allIssues[0])
		}

		message := "multiple fetch/git issues found:\n- " + strings.Join(allIssues, "\n- ")
		if hasVersionIssues {
			message += "\nFor version issues: check whether these should be derived from ${{package.version}} (or a transform)"
		}
		return fmt.Errorf(message)
	}

	return nil
}
