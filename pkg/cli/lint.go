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
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/linter"
	linter_defaults "chainguard.dev/melange/pkg/linter/defaults"
)

type LintOpts struct {
	linters []string
}

func Lint() *cobra.Command {
	o := LintOpts{}

	var enabled, disabled []string

	cmd := &cobra.Command{
		Use:     "lint",
		Short:   "EXPERIMENTAL COMMAND - Lints an APK, checking for problems and errors",
		Long:    `Lint is an EXPERIMENTAL COMMAND - Lints an APK file, checking for problems and errors.`,
		Example: `  melange lint [--enable=foo[,bar]] [--disable=baz] foo.apk`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Cheap and dirty way to handle duplicates
			linterSet := map[string]struct{}{}

			// Get all default linters, ignoring disabled ones
			for _, e := range linter_defaults.DefaultLinters {
				if !slices.Contains(disabled, e) {
					linterSet[e] = struct{}{}
				}
			}

			// Enable non-default lints
			for _, e := range enabled {
				if !slices.Contains(disabled, e) {
					linterSet[e] = struct{}{}
				}
			}

			// Collect
			linters := []string{}
			for e := range linterSet {
				linters = append(linters, e)
			}

			badLints := linter.CheckValidLinters(linters)
			if len(badLints) > 0 {
				return fmt.Errorf("Unknwon linter(s): %s", strings.Join(badLints, ", "))
			}

			o.linters = linters

			return o.RunAllE(ctx, args...)
		},
	}

	cmd.Flags().StringSliceVar(&enabled, "enabled", []string{}, "enable additional, non-default lints, `--disabled` overrides this")
	cmd.Flags().StringSliceVar(&disabled, "disabled", []string{}, "disable linters enabled by default or passed in `--enabled`")

	return cmd
}

func (o LintOpts) RunAllE(ctx context.Context, pkgs ...string) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, pkg := range pkgs {
		p := pkg

		g.Go(func() error {
			return o.run(ctx, p)
		})
	}
	return g.Wait()
}

func (o LintOpts) run(ctx context.Context, pkg string) error {
	fmt.Printf("Linting apk: %s", pkg)

	var innerErr error
	err := linter.LintApk(ctx, pkg, func(err error) {
		innerErr = err
	}, o.linters)
	if err != nil {
		return fmt.Errorf("package linter error: %w", err)
	} else if innerErr != nil {
		fmt.Printf("package linter warning: %v", innerErr)
	}
	return nil
}
