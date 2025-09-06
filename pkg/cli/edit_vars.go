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
	"chainguard.dev/melange/pkg/renovate/edit_vars"
)

func editVarsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "edit-vars",
		Short:   "Edit the variables in a Melange YAML file",
		Long:    `Edit the variables in a Melange YAML file.`,
		Example: `  melange edit-vars <config.yaml> "key1=value1 key2=value2"`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rc, err := renovate.New(renovate.WithConfig(args[0]))
			if err != nil {
				return err
			}

			editVarsRenovator := edit_vars.New(ctx,
				edit_vars.WithVariables(args[1]),
			)

			return rc.Renovate(cmd.Context(), editVarsRenovator)
		},
	}
	return cmd
}
