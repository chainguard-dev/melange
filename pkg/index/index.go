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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/korovkin/limiter"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
	"go.opentelemetry.io/otel"
)

type Index struct {
	PackageFiles       []string
	IndexFile          string
	SourceIndexFile    string
	MergeIndexFileFlag bool
	SigningKey         string
	ExpectedArch       string
	Index              apkrepo.ApkIndex
}

type Option func(*Index) error

func WithMergeIndexFileFlag(mergeFlag bool) Option {
	return func(idx *Index) error {
		idx.MergeIndexFileFlag = mergeFlag
		return nil
	}
}

func WithIndexFile(indexFile string) Option {
	return func(idx *Index) error {
		idx.IndexFile = indexFile
		idx.SourceIndexFile = indexFile
		return nil
	}
}

func WithSourceIndexFile(indexFile string) Option {
	return func(idx *Index) error {
		idx.SourceIndexFile = indexFile
		return nil
	}
}

func WithPackageFiles(packageFiles []string) Option {
	return func(idx *Index) error {
		idx.PackageFiles = append(idx.PackageFiles, packageFiles...)
		return nil
	}
}

func WithPackageDir(packageDir string) Option {
	return func(idx *Index) error {
		files, err := os.ReadDir(packageDir)
		if err != nil {
			return fmt.Errorf("unable to list packages: %w", err)
		}
		apkFiles := []string{}
		for _, file := range files {
			n := filepath.Join(packageDir, file.Name())
			if !file.IsDir() && strings.HasSuffix(n, ".apk") {
				apkFiles = append(apkFiles, n)
			}
		}

		idx.PackageFiles = append(idx.PackageFiles, apkFiles...)
		return nil
	}
}

func WithSigningKey(signingKey string) Option {
	return func(idx *Index) error {
		idx.SigningKey = signingKey
		return nil
	}
}

// WithExpectedArch sets the expected package architecture.  Any packages with
// an unexpected architecture will not be indexed.
func WithExpectedArch(expectedArch string) Option {
	return func(idx *Index) error {
		idx.ExpectedArch = expectedArch
		return nil
	}
}

func New(opts ...Option) (*Index, error) {
	idx := Index{
		PackageFiles: []string{},
	}

	for _, opt := range opts {
		if err := opt(&idx); err != nil {
			return nil, err
		}
	}

	return &idx, nil
}

func (idx *Index) LoadIndex(sourceFile string) error {
	f, err := os.Open(sourceFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}
	defer f.Close()

	index, err := apkrepo.IndexFromArchive(f)
	if err != nil {
		return fmt.Errorf("failed to read apkindex from archive file: %w", err)
	}

	idx.Index.Description = index.Description
	idx.Index.Packages = append(idx.Index.Packages, index.Packages...)

	log.Printf("loaded %d/%d packages from index %s", len(idx.Index.Packages), len(index.Packages), sourceFile)

	return nil
}

func (idx *Index) UpdateIndex() error {
	packages := make([]*apkrepo.Package, len(idx.PackageFiles))
	var mtx sync.Mutex

	g := limiter.NewConcurrencyLimiterForIO(limiter.DefaultConcurrencyLimitIO)

	for i, apkFile := range idx.PackageFiles {
		i, apkFile := i, apkFile // capture the loop variables
		if _, err := g.Execute(func() {
			log.Printf("processing package %s", apkFile)
			f, err := os.Open(apkFile)
			if err != nil {
				// nolint:errcheck
				g.FirstErrorStore(fmt.Errorf("failed to open package %s: %w", apkFile, err))
				return
			}
			defer f.Close()
			pkg, err := apkrepo.ParsePackage(f)
			if err != nil {
				// nolint:errcheck
				g.FirstErrorStore(fmt.Errorf("failed to parse package %s: %w", apkFile, err))
				return
			}

			if idx.ExpectedArch != "" && pkg.Arch != idx.ExpectedArch {
				log.Printf("WARNING: %s-%s: found unexpected architecture %s, expecting %s",
					pkg.Name, pkg.Version, pkg.Arch, idx.ExpectedArch)
				return
			}

			mtx.Lock()
			packages[i] = pkg
			mtx.Unlock()
		}); err != nil {
			return fmt.Errorf("executing processor function: %w", err)
		}
	}
	if err := g.WaitAndClose(); err != nil {
		return err
	}

	if err := g.FirstErrorGet(); err != nil {
		return err
	}

	if idx.MergeIndexFileFlag {
		if err := idx.LoadIndex(idx.SourceIndexFile); err != nil {
			return err
		}
	}

	for _, pkg := range packages {
		found := false

		for _, p := range idx.Index.Packages {
			if pkg.Name == p.Name && pkg.Version == p.Version {
				found = true
				p = pkg
			}
		}

		if !found {
			idx.Index.Packages = append(idx.Index.Packages, pkg)
		}
	}

	pkgNames := make([]string, 0, len(packages))
	for _, p := range packages {
		if p != nil {
			pkgNames = append(pkgNames, fmt.Sprintf("%s-%s", p.Name, p.Version))
		}
	}

	log.Printf("updating index at %s with new packages: %v", idx.IndexFile, pkgNames)

	return nil
}

func (idx *Index) GenerateIndex(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "GenerateIndex")
	defer span.End()

	if err := idx.UpdateIndex(); err != nil {
		return fmt.Errorf("updating index: %w", err)
	}

	if err := idx.WriteArchiveIndex(ctx, idx.IndexFile); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}

	return nil
}

func (idx *Index) WriteArchiveIndex(ctx context.Context, destinationFile string) error {
	archive, err := apkrepo.ArchiveFromIndex(&idx.Index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}
	outFile, err := os.Create(destinationFile)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer outFile.Close()
	if _, err = io.Copy(outFile, archive); err != nil {
		return fmt.Errorf("failed to write contents to archive file: %w", err)
	}

	if idx.SigningKey != "" {
		log.Printf("signing apk index at %s", idx.IndexFile)
		if err := sign.SignIndex(ctx, nil, idx.SigningKey, idx.IndexFile); err != nil {
			return fmt.Errorf("failed to sign apk index: %w", err)
		}
	}

	return nil
}

func (idx *Index) WriteJSONIndex(destinationFile string) error {
	outFile, err := os.Create(destinationFile)
	if err != nil {
		return fmt.Errorf("failed to create index JSON file: %w", err)
	}
	defer outFile.Close()

	jsonData, err := json.MarshalIndent(idx.Index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to write index as JSON: %w", err)
	}

	if _, err := outFile.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write index as JSON: %w", err)
	}

	return nil
}
