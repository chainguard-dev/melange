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

	"chainguard.dev/melange/pkg/source"
)

func fetchSource() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fetch-source file target-directory",
		Short:   "Download package source code",
		Long:    `Download the selected package's source code via the melange metadata.`,
		Example: `  melange fetch-source vim.apk sources/`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			destDir := args[1]
			// Create destDir if it doesn't exist
			if _, err := os.Stat(destDir); os.IsNotExist(err) {
				if err := os.MkdirAll(destDir, 0755); err != nil {
					return fmt.Errorf("failed to create destination directory: %w", err)
				}
			}

			var err error
			e := filepath.Ext(args[0])
			if e == ".apk" || e == ".yaml" {
				_, err = source.FetchSourceFromMelange(ctx, args[0], args[1])
			} else {
				err = fmt.Errorf("unsupported file type: %s", e)
			}

			return err
		},
	}

	return cmd
}
