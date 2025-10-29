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
	"os"
	"text/template"

	"github.com/spf13/cobra"

	"chainguard.dev/melange/pkg/config"
)

func query() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query a Melange YAML file for information",
		Long: `Query a Melange YAML file for information.
		Uses templates with go templates syntax to query the YAML file.`,
		Example: `  melange query config.yaml "{{ .Package.Name }}-{{ .Package.Version }}-{{ .Package.Epoch }}"`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return QueryCmd(cmd.Context(), args[0], args[1])
		},
	}

	return cmd
}

func QueryCmd(ctx context.Context, configFile, pattern string) error {
	config, err := config.ParseConfiguration(ctx, configFile)
	if err != nil {
		return err
	}
	tmpl, err := template.New("query").Parse(pattern)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}
	err = tmpl.Execute(os.Stdout, config)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}
	return nil
}
