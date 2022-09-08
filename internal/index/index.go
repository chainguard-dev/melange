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

package index

import (
	"fmt"
	"io"
	"log"
	"os"

	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
)

// TODO: solidify this API and move into pkg/
func Index(logger *log.Logger, apkIndexFilename string, apkFiles []string) error {
	packages := []*apkrepo.Package{}
	for _, apkFile := range apkFiles {
		logger.Printf("processing package %s", apkFile)
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
	logger.Printf("generating index at %s", apkIndexFilename)
	archive, err := apkrepo.ArchiveFromIndex(index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}
	outFile, err := os.Create(apkIndexFilename)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer outFile.Close()
	if _, err = io.Copy(outFile, archive); err != nil {
		return fmt.Errorf("failed to write contents to archive file: %w", err)
	}
	return nil
}
