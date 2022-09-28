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
	"context"
	"github.com/spf13/cobra/doc"
	"log"

	"github.com/spf13/cobra"

	"chainguard.dev/melange/internal/index"
)

func Index() *cobra.Command {
	var apkIndexFilename string
	cmd := &cobra.Command{
		Use:     "index",
		Short:   "Creates a repository index from a list of package files",
		Long:    `Creates a repository index from a list of package files.`,
		Example: `  melange index -o APKINDEX.tar.gz *.apk`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return IndexCmd(cmd.Context(), apkIndexFilename, args)
		},
	}
	cmd.Flags().StringVarP(&apkIndexFilename, "output", "o", "APKINDEX.tar.gz", "Output generated index to FILE")
	err := doc.GenMarkdownTree(cmd, "./docs/")

	if err != nil {
		log.Fatal(err)
	}
	return cmd
}

func IndexCmd(ctx context.Context, apkIndexFilename string, apkFiles []string) error {
	return index.Index(log.Default(), apkIndexFilename, apkFiles)
}
