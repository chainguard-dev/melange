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

package sbom

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/release-utils/hash"
)

type generatorImplementation interface {
	GenerateDocument(*Spec) (*bom, error)
	ScanFiles(*Spec, *bom) error
	ScanLicenses(*Spec, *bom) error
	ReadDependencyData(*Spec, *bom, string) error
	WriteSBOM(*Spec, *bom) error
}

type defaultGeneratorImplementation struct{}

func (di *defaultGeneratorImplementation) GenerateDocument(spec *Spec) (*bom, error) {
	return &bom{
		Packages: []pkg{},
		Files:    []file{},
	}, nil
}

// ScanFiles reads the files to be packaged in the apk and
// extracts the required data for the SBOM.
func (di *defaultGeneratorImplementation) ScanFiles(spec *Spec, doc *bom) error {
	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return fmt.Errorf("getting absolute directory path: %w", err)
	}
	fileList, err := getDirectoryTree(dirPath)
	if err != nil {
		return fmt.Errorf("building directory tree: %w", err)
	}

	// logrus.Debugf("Scanning %d files and adding them to the SPDX package", len(fileList))

	dirPackage := pkg{
		FilesAnalyzed: true,
	}

	g, _ := errgroup.WithContext(context.Background())
	files := sync.Map{}
	for _, path := range fileList {
		path := path
		g.Go(func() error {
			f := file{
				Name:          path,
				Checksum:      []map[string]string{},
				Relationships: []relationship{},
			}

			// Hash the file contents
			for algo, fn := range map[string]func(string) (string, error){
				"SHA1":   hash.SHA1ForFile,
				"SHA256": hash.SHA256ForFile,
				"SHA512": hash.SHA512ForFile,
			} {
				csum, err := fn(path)
				if err != nil {
					return fmt.Errorf("hashing %s file %s: %w", algo, path, err)
				}
				f.Checksum = append(f.Checksum, map[string]string{algo: csum})
			}

			files.Store(path, f)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Add files into the package
	files.Range(func(key, f any) bool {
		dirPackage.Relationships = append(dirPackage.Relationships, relationship{
			Source: &dirPackage,
			Target: &f,
			Type:   "CONTAINS",
		})
		return true
	})
	doc.Packages = append(doc.Packages, dirPackage)
	return nil
}

func (di *defaultGeneratorImplementation) ScanLicenses(spec *Spec, doc *bom) error {
	return nil
}

func (di *defaultGeneratorImplementation) ReadDependencyData(spec *Spec, doc *bom, language string) error {
	return nil
}

func (di *defaultGeneratorImplementation) WriteSBOM(spec *Spec, doc *bom) error {
	return nil
}

// getDirectoryTree reads a directory and returns a list of strings of all files init
func getDirectoryTree(dirPath string) ([]string, error) {
	fileList := []string{}

	if err := fs.WalkDir(os.DirFS(dirPath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if d.Type() == os.ModeSymlink {
			return nil
		}

		fileList = append(fileList, path)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("buiding directory tree: %w", err)
	}
	return fileList, nil
}
