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

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

func sourceCmd() *cobra.Command {
	var outputDir string

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

			// Look for git-checkout pipelines - only process the first one
			foundGit := false
			for _, step := range cfg.Pipeline {
				if step.Uses == "git-checkout" {
					log.Infof("Found git-checkout step")

					// Construct destination: outputDir/packageName
					destination := fmt.Sprintf("%s/%s", outputDir, cfg.Package.Name)

					opts := &source.GitCheckoutOptions{
						Repository:     step.With["repository"],
						Destination:    destination,
						ExpectedCommit: step.With["expected-commit"],
						CherryPicks:    step.With["cherry-picks"],
					}

					if err := source.GitCheckout(ctx, opts); err != nil {
						return fmt.Errorf("failed to checkout source: %w", err)
					}

					foundGit = true
					break // Only process first git-checkout
				}
			}

			if !foundGit {
				return fmt.Errorf("no git-checkout pipeline found in configuration")
			}

			log.Infof("Successfully extracted source to %s", outputDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "./source", "output directory for extracted source")

	return cmd
}
