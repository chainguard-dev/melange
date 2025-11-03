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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/sign"
)

type Index struct {
	PackageFiles       []string
	IndexFile          string
	SourceIndexFile    string
	MergeIndexFileFlag bool
	SigningKey         string
	ExpectedArch       string
	Index              apk.APKIndex
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

func (idx *Index) LoadIndex(ctx context.Context, sourceFile string) error {
	log := clog.FromContext(ctx)
	f, err := os.Open(sourceFile) // #nosec G304 - User-specified APK index file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}
	defer f.Close()

	index, err := apk.IndexFromArchive(f)
	if err != nil {
		return fmt.Errorf("failed to read apkindex from archive file: %w", err)
	}

	idx.Index.Description = index.Description
	idx.Index.Packages = append(idx.Index.Packages, index.Packages...)

	log.Infof("loaded %d/%d packages from index %s", len(idx.Index.Packages), len(index.Packages), sourceFile)

	return nil
}

func (idx *Index) UpdateIndex(ctx context.Context) error {
	log := clog.FromContext(ctx)
	packages := make([]*apk.Package, len(idx.PackageFiles))
	var g errgroup.Group
	g.SetLimit(4)
	for i, apkFile := range idx.PackageFiles {
		g.Go(func() error {
			log.Infof("processing package %s", apkFile)
			f, err := os.Open(apkFile) // #nosec G304 - User-specified APK package file
			if err != nil {
				return fmt.Errorf("failed to open package %s: %w", apkFile, err)
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				return err
			}

			// stat.Size() returns int64 but file sizes are always non-negative
			size := uint64(0)
			if stat.Size() > 0 {
				size = uint64(stat.Size()) // #nosec G115 - file sizes are always positive
			}
			pkg, err := apk.ParsePackage(ctx, f, size)
			if err != nil {
				return fmt.Errorf("failed to parse package %s: %w", apkFile, err)
			}

			if idx.ExpectedArch != "" && pkg.Arch != idx.ExpectedArch {
				log.Warnf("%s-%s: found unexpected architecture %s, expecting %s",
					pkg.Name, pkg.Version, pkg.Arch, idx.ExpectedArch)
				return nil
			}

			packages[i] = pkg

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if idx.MergeIndexFileFlag {
		if err := idx.LoadIndex(ctx, idx.SourceIndexFile); err != nil {
			return err
		}
	}

	for _, pkg := range packages {
		found := false

		for i, p := range idx.Index.Packages {
			if pkg.Name == p.Name && pkg.Version == p.Version {
				found = true
				idx.Index.Packages[i] = pkg
				break
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

	log.Infof("updating index at %s with new packages: %v", idx.IndexFile, pkgNames)

	return nil
}

func (idx *Index) GenerateIndex(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "GenerateIndex")
	defer span.End()

	if err := idx.UpdateIndex(ctx); err != nil {
		return fmt.Errorf("updating index: %w", err)
	}

	if err := idx.WriteArchiveIndex(ctx, idx.IndexFile); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}

	return nil
}

func (idx *Index) WriteArchiveIndex(ctx context.Context, destinationFile string) error {
	log := clog.FromContext(ctx)
	archive, err := apk.ArchiveFromIndex(&idx.Index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}
	outFile, err := os.Create(destinationFile) // #nosec G304 - Writing APK index to output directory
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer outFile.Close()
	if _, err = io.Copy(outFile, archive); err != nil {
		return fmt.Errorf("failed to write contents to archive file: %w", err)
	}

	if idx.SigningKey != "" {
		log.Infof("signing apk index at %s", idx.IndexFile)
		if err := sign.SignIndex(ctx, idx.SigningKey, idx.IndexFile); err != nil {
			return fmt.Errorf("failed to sign apk index: %w", err)
		}
	}

	return nil
}
