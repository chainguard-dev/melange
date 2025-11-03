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
	"path/filepath"

	"github.com/spf13/cobra"

	apkofs "chainguard.dev/apko/pkg/apk/fs"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/copyright"
	"chainguard.dev/melange/pkg/source"
)

func licenseCheck() *cobra.Command {
	var workDir string
	var fix bool
	var format string
	cmd := &cobra.Command{
		Use:     "license-check file",
		Short:   "Gather and check licensing data",
		Long:    `Check a melange source, source tree or APK for license data correctness.`,
		Example: `  melange license-check vim.yaml`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if workDir == "" {
				// Create a temporary directory for the workdir if no workdir given
				tmpDir, err := os.MkdirTemp("", "melange-license-check")
				if err != nil {
					return fmt.Errorf("failed to create temporary directory: %w", err)
				}
				defer os.RemoveAll(tmpDir)
				workDir = tmpDir
			}

			sourceDir := args[0]
			var cfg *config.Configuration
			var err error
			e := filepath.Ext(args[0])
			if e == ".apk" || e == ".yaml" {
				cfg, err = source.FetchSourceFromMelange(ctx, args[0], workDir)
				if err != nil {
					return err
				}
				sourceDir = workDir
			}

			// Turn sourceDir to an absolute path
			sourceDir, err = filepath.Abs(sourceDir)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for source directory: %w", err)
			}
			sourceFS := apkofs.DirFS(ctx, sourceDir)
			detectedLicenses, diffs, err := license.LicenseCheck(ctx, cfg, sourceFS)
			if err != nil {
				return err
			}

			if fix {
				// Attempt to fix the license issues in the melange yaml file
				var rc *renovate.Context
				rc, err = renovate.New(renovate.WithConfig(args[0]))
				if err != nil {
					return err
				}

				copyrightRenovator := copyright.New(
					ctx,
					copyright.WithLicenses(detectedLicenses),
					copyright.WithDiffs(diffs),
					copyright.WithFormat(format),
				)
				err = rc.Renovate(cmd.Context(), copyrightRenovator)
			}

			return err
		},
	}

	cmd.Flags().StringVar(&workDir, "workdir", "", "path to the working directory, e.g. where the source will be extracted to")
	cmd.Flags().BoolVar(&fix, "fix", false, "fix license issues in the melange yaml file")
	cmd.Flags().StringVar(&format, "format", "flat", "license fix strategy format: 'simple' or 'flat'")

	return cmd
}
