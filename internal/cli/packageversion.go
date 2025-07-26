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
	"github.com/spf13/cobra"
)

func packageVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package-version",
		Short: "Report the target package for a YAML configuration file",
		Long: `Report the target package for a YAML configuration file.
		Equivalent to running:

			melange query config.yaml '{{ .Package.Name }}-{{ .Package.Version }}-r{{ .Package.Epoch }}'

		`,
		Example: `  melange package-version [config.yaml]`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return QueryCmd(cmd.Context(), args[0], "{{ .Package.Name }}-{{ .Package.Version }}-r{{ .Package.Epoch }}")
		},
	}

	return cmd
}
