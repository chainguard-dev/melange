// Copyright 2023 Chainguard, Inc.
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
	"errors"
	"runtime"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"

	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/linter"
)

func lint() *cobra.Command {
	var lintRequire, lintWarn []string
	var outDir string
	var persistLintResults bool
	cmd := &cobra.Command{
		Use:     "lint",
		Short:   "EXPERIMENTAL COMMAND - Lints an APK, checking for problems and errors",
		Long:    `Lint is an EXPERIMENTAL COMMAND - Lints an APK file, checking for problems and errors.`,
		Example: `  melange lint [--enable=foo[,bar]] [--disable=baz] [--persist-lint-results] [--out-dir=./output] foo.apk`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			g, ctx := errgroup.WithContext(ctx)
			g.SetLimit(runtime.GOMAXPROCS(0))

			log := clog.FromContext(ctx)
			log.Infof("Required checks: %v", lintRequire)
			log.Infof("Warning checks: %v", lintWarn)

			// Only pass outputDir if persistence is enabled
			outputDir := ""
			if persistLintResults {
				outputDir = outDir
			}

			errs := []error{}
			var mu sync.Mutex
			for _, pkg := range args {
				g.Go(func() error {
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := linter.LintAPK(ctx, pkg, lintRequire, lintWarn, outputDir); err != nil {
						mu.Lock()
						defer mu.Unlock()
						errs = append(errs, err)
					}
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return err
			}
			return errors.Join(errs...)
		},
	}

	cmd.Flags().StringSliceVar(&lintRequire, "lint-require", linter.DefaultRequiredLinters(), "linters that must pass")
	cmd.Flags().StringSliceVar(&lintWarn, "lint-warn", linter.DefaultWarnLinters(), "linters that will generate warnings")
	cmd.Flags().BoolVar(&persistLintResults, "persist-lint-results", false, "persist lint results to JSON files in packages/{arch}/ directory")
	cmd.Flags().StringVar(&outDir, "out-dir", "packages", "directory where lint results JSON files will be saved (requires --persist-lint-results)")

	_ = cmd.Flags().Bool("fail-on-lint-warning", false, "DEPRECATED: DO NOT USE")
	_ = cmd.Flags().MarkDeprecated("fail-on-lint-warning", "use --lint-require and --lint-warn instead")

	return cmd
}
