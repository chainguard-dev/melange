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
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

func sourceCmd() *cobra.Command {
	var outputDir string
	var sourceDir string

	cmd := &cobra.Command{
		Use:   "source [config.yaml]",
		Short: "Extract source code from melange configuration",
		Long: `Extract source code by cloning git repositories from melange configuration.

This command parses a melange configuration file and extracts sources to the given directory
Currently only supports git-checkout.
`,
		Example: `  melange source vim.yaml -o ./src`,
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
			destination := fmt.Sprintf("%s/%s", outputDir, cfg.Package.Name)

			// Default sourceDir to package-name subdirectory in config file's directory
			// This matches melange build behavior: --source-dir ./package-name/
			if sourceDir == "" {
				sourceDir = filepath.Join(filepath.Dir(buildConfigPath), cfg.Package.Name)
			}

			// Make sourceDir absolute since git commands will run from the cloned repo
			absSourceDir, err := filepath.Abs(sourceDir)
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

			log.Infof("Successfully extracted source to %s", outputDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "./source", "output directory for extracted source")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory where patches and other sources are located (defaults to ./package-name/)")

	return cmd
}
