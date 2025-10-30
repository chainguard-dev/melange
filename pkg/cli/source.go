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

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/source"
)

func sourceCmd() *cobra.Command {
	var outputDir string
	var sourceDir string

	cmd := &cobra.Command{
		Use:   "source",
		Short: "Manage melange source code",
		Long:  `Commands for managing source code from melange configurations.`,
	}

	// Shared flags for all source subcommands
	cmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./source", "output directory for extracted source")
	cmd.PersistentFlags().StringVar(&sourceDir, "source-dir", "", "directory where patches and other sources are located (defaults to ./package-name/)")

	// Add subcommands
	cmd.AddCommand(sourceGetCmd(&outputDir, &sourceDir))
	cmd.AddCommand(sourcePopCmd(&outputDir, &sourceDir))

	return cmd
}

func sourceGetCmd(outputDir *string, sourceDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [config.yaml]",
		Short: "Extract source code from melange configuration",
		Long: `Extract source code by cloning git repositories from melange configuration.

This command parses a melange configuration file and extracts sources to the given directory
Currently only supports git-checkout.
`,
		Example: `  melange source get vim.yaml -o ./src`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			buildConfigPath := args[0]

			cfg, err := config.ParseConfiguration(ctx, buildConfigPath)
			if err != nil {
				return fmt.Errorf("failed to parse melange config: %w", err)
			}

			// Look for git-checkout and patch pipelines
			gitCheckoutIndex := -1
			var patches string

			// First pass: find git-checkout step
			for i, step := range cfg.Pipeline {
				if step.Uses == "git-checkout" {
					gitCheckoutIndex = i
					break
				}
			}

			if gitCheckoutIndex == -1 {
				return fmt.Errorf("no git-checkout pipeline found in configuration")
			}

			// Second pass: find patch steps that come after git-checkout
			for i := gitCheckoutIndex + 1; i < len(cfg.Pipeline); i++ {
				step := cfg.Pipeline[i]
				if step.Uses == "patch" {
					if patchList := step.With["patches"]; patchList != "" {
						patches = patchList
						break // Only process first patch step
					}
				}
			}

			// Now perform the git checkout with patches
			step := cfg.Pipeline[gitCheckoutIndex]
			log.Infof("Found git-checkout step")

			// Construct destination: outputDir/packageName
			destination := fmt.Sprintf("%s/%s", *outputDir, cfg.Package.Name)

			// Default sourceDir to package-name subdirectory in config file's directory
			// This matches melange build behavior: --source-dir ./package-name/
			srcDir := *sourceDir
			if srcDir == "" {
				srcDir = filepath.Join(filepath.Dir(buildConfigPath), cfg.Package.Name)
			}

			// Make sourceDir absolute since git commands will run from the cloned repo
			absSourceDir, err := filepath.Abs(srcDir)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for source-dir: %w", err)
			}

			opts := &source.GitCheckoutOptions{
				Repository:     step.With["repository"],
				Destination:    destination,
				ExpectedCommit: step.With["expected-commit"],
				CherryPicks:    step.With["cherry-picks"],
				Patches:        patches,
				WorkspaceDir:   absSourceDir,
			}

			if err := source.GitCheckout(ctx, opts); err != nil {
				return fmt.Errorf("failed to checkout source: %w", err)
			}

			log.Infof("Successfully extracted source to %s", *outputDir)
			return nil
		},
	}

	return cmd
}

func sourcePopCmd(outputDir *string, sourceDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pop [config.yaml]",
		Short: "Generate patches from modified source and update melange configuration",
		Long: `Generate git format-patch patches from commits made on top of the expected-commit
and update the melange configuration to use git-am pipeline instead of patch pipeline.

This command:
1. Reads the expected-commit from git-checkout pipeline
2. Generates patches from expected-commit..HEAD in the cloned source
3. Writes patches to the source directory
4. Updates the YAML to replace 'patch' with 'git-am' pipeline
`,
		Example: `  melange source pop apk-tools.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			buildConfigPath := args[0]

			cfg, err := config.ParseConfiguration(ctx, buildConfigPath)
			if err != nil {
				return fmt.Errorf("failed to parse melange config: %w", err)
			}

			// Find git-checkout step to get expected-commit
			var expectedCommit string
			for _, step := range cfg.Pipeline {
				if step.Uses == "git-checkout" {
					expectedCommit = step.With["expected-commit"]
					break
				}
			}

			if expectedCommit == "" {
				return fmt.Errorf("no expected-commit found in git-checkout pipeline")
			}

			// Default sourceDir to package-name subdirectory in config file's directory
			srcDir := *sourceDir
			if srcDir == "" {
				srcDir = filepath.Join(filepath.Dir(buildConfigPath), cfg.Package.Name)
			}

			// Make sourceDir absolute
			absSrcDir, err := filepath.Abs(srcDir)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for source-dir: %w", err)
			}

			// Cloned source location
			clonedSource := filepath.Join(*outputDir, cfg.Package.Name)
			absClonedSource, err := filepath.Abs(clonedSource)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for cloned source: %w", err)
			}

			log.Infof("Generating patches from %s in %s", expectedCommit, absClonedSource)

			// Generate patches using git format-patch
			formatPatchCmd := exec.CommandContext(ctx, "git", "format-patch", "-o", absSrcDir, expectedCommit+"..HEAD")
			formatPatchCmd.Dir = absClonedSource
			output, err := formatPatchCmd.Output()
			if err != nil {
				return fmt.Errorf("failed to generate patches: %w", err)
			}

			// Parse the patch filenames from git format-patch output
			patchLines := strings.Split(strings.TrimSpace(string(output)), "\n")
			var patchFiles []string
			for _, line := range patchLines {
				if line != "" {
					// Extract just the filename
					patchFiles = append(patchFiles, filepath.Base(line))
				}
			}

			if len(patchFiles) == 0 {
				return fmt.Errorf("no patches generated - no commits found after %s", expectedCommit)
			}

			log.Infof("Generated %d patches: %v", len(patchFiles), patchFiles)

			// Read the original YAML file
			yamlData, err := os.ReadFile(buildConfigPath)
			if err != nil {
				return fmt.Errorf("failed to read YAML file: %w", err)
			}

			// Parse as generic YAML to preserve structure and comments
			var doc yaml.Node
			if err := yaml.Unmarshal(yamlData, &doc); err != nil {
				return fmt.Errorf("failed to parse YAML: %w", err)
			}

			// Update the pipeline: remove 'patch' steps and add 'git-am' step
			if err := updatePipelineWithGitAm(&doc, patchFiles); err != nil {
				return fmt.Errorf("failed to update pipeline: %w", err)
			}

			// Write back the updated YAML
			updatedYaml, err := yaml.Marshal(&doc)
			if err != nil {
				return fmt.Errorf("failed to marshal YAML: %w", err)
			}

			// #nosec G306 these are melange yaml files
			if err := os.WriteFile(buildConfigPath, updatedYaml, 0o644); err != nil {
				return fmt.Errorf("failed to write updated YAML: %w", err)
			}

			// Try to run yam to fix formatting
			yamCmd := exec.CommandContext(ctx, "yam", buildConfigPath)
			if err := yamCmd.Run(); err != nil {
				log.Warnf("Failed to run yam for formatting (continuing anyway): %v", err)
			} else {
				log.Infof("Formatted YAML with yam")
			}

			log.Infof("Updated %s with git-am pipeline using %d patches", buildConfigPath, len(patchFiles))
			return nil
		},
	}

	return cmd
}

// updatePipelineWithGitAm finds the pipeline array in the YAML node tree,
// and replaces any 'patch' pipeline step with a 'git-am' step with the given patches.
// If no patch step exists, inserts git-am after git-checkout.
func updatePipelineWithGitAm(doc *yaml.Node, patchFiles []string) error {
	// Navigate to the pipeline array
	// doc.Content[0] is the document node
	// doc.Content[0].Content contains key-value pairs of the root map

	if len(doc.Content) == 0 || len(doc.Content[0].Content) == 0 {
		return fmt.Errorf("invalid YAML structure")
	}

	rootMap := doc.Content[0]
	var pipelineNode *yaml.Node

	// Find the 'pipeline' key
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "pipeline" {
			pipelineNode = rootMap.Content[i+1]
			break
		}
	}

	if pipelineNode == nil {
		return fmt.Errorf("no pipeline found in YAML")
	}

	// Create git-am step
	gitAmStep := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "uses"},
			{Kind: yaml.ScalarNode, Value: "git-am"},
			{Kind: yaml.ScalarNode, Value: "with"},
			{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "patches"},
					{Kind: yaml.ScalarNode, Value: strings.Join(patchFiles, " ")},
				},
			},
		},
	}

	// Try to replace 'uses: patch' step with 'uses: git-am' step in place
	replacedAny := false
	for i, step := range pipelineNode.Content {
		// Check if this step has 'uses: patch'
		for j := 0; j < len(step.Content); j += 2 {
			if step.Content[j].Value == "uses" && step.Content[j+1].Value == "patch" {
				// Replace this step with git-am step
				pipelineNode.Content[i] = gitAmStep
				replacedAny = true
				break
			}
		}
	}

	// If no patch step found, insert git-am after git-checkout
	if !replacedAny {
		var newContent []*yaml.Node
		for _, step := range pipelineNode.Content {
			newContent = append(newContent, step)
			// Check if this is git-checkout step
			for j := 0; j < len(step.Content); j += 2 {
				if step.Content[j].Value == "uses" && step.Content[j+1].Value == "git-checkout" {
					// Insert git-am step right after
					newContent = append(newContent, gitAmStep)
					break
				}
			}
		}
		pipelineNode.Content = newContent
	}

	return nil
}
