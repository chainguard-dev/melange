// Copyright 2022 Chainguard, Inc.
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
	"github.com/spf13/cobra"

	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/bump"
)

func bumpCmd() *cobra.Command {
	var expectedCommit string
	cmd := &cobra.Command{
		Use:     "bump",
		Short:   "Update a Melange YAML file to reflect a new package version",
		Long:    `Update a Melange YAML file to reflect a new package version.`,
		Example: `  melange bump <config.yaml> <1.2.3.4>`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rc, err := renovate.New(renovate.WithConfig(args[0]))
			if err != nil {
				return err
			}

			bumpRenovator := bump.New(ctx,
				bump.WithTargetVersion(args[1]),
				bump.WithExpectedCommit(expectedCommit),
			)
			return rc.Renovate(cmd.Context(), bumpRenovator)
		},
	}
	cmd.Flags().StringVar(&expectedCommit, "expected-commit", "", "optional flag to update the expected-commit value of a git-checkout pipeline")
	return cmd
}
