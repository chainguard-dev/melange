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
	"fmt"
	"io"
	"log"
	"os"

	// nolint:gosec

	"github.com/spf13/cobra"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
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
	return cmd
}

func IndexCmd(ctx context.Context, apkIndexFilename string, apkFiles []string) error {
	packages := []*apkrepo.Package{}
	for _, apkFile := range apkFiles {
		log.Printf("processing package %s", apkFile)
		f, err := os.Open(apkFile)
		if err != nil {
			return fmt.Errorf("failed to open package %s: %w", apkFile, err)
		}
		pkg, err := apkrepo.ParsePackage(f)
		if err != nil {
			return fmt.Errorf("failed to parse package %s: %w", apkFile, err)
		}
		packages = append(packages, pkg)
	}
	index := &apkrepo.ApkIndex{
		Packages: packages,
	}
	log.Printf("generating index at %s", apkIndexFilename)
	archive, err := apkrepo.ArchiveFromIndex(index)
	if err != nil {
		return err
	}
	outFile, err := os.Create(apkIndexFilename)
	if err != nil {
		return err
	}
	defer outFile.Close()
	_, err = io.Copy(outFile, archive)
	return err
}
