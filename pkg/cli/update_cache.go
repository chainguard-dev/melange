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
	"chainguard.dev/melange/pkg/renovate/cache"
)

func updateCache() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:     "update-cache",
		Short:   "Update a source artifact cache",
		Long:    `Update a source artifact cache.`,
		Example: `  melange update-cache --cache-dir <cache-dir> <config.yaml>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			rctx, err := renovate.New(renovate.WithConfig(args[0]))
			if err != nil {
				return err
			}

			rc := renovate.RenovationContext{Context: rctx}

			cacheRenovator := cache.New(
				cache.WithCacheDir(cacheDir),
			)

			if err := rc.LoadConfig(ctx); err != nil {
				return err
			}
			return cacheRenovator(ctx, &rc)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "/var/cache/melange", "directory used for cached inputs")

	return cmd
}
