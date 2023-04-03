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
	"path/filepath"
	"strings"
	"sync"

	"github.com/korovkin/limiter"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"

	"chainguard.dev/melange/internal/sign"
)

type Context struct {
	PackageFiles       []string
	IndexFile          string
	MergeIndexFileFlag bool
	SigningKey         string
	Logger             *log.Logger
	ExpectedArch       string
}

type Option func(*Context) error

func WithMergeIndexFileFlag(mergeFlag bool) Option {
	return func(ctx *Context) error {
		ctx.MergeIndexFileFlag = mergeFlag
		return nil
	}
}

func WithIndexFile(indexFile string) Option {
	return func(ctx *Context) error {
		ctx.IndexFile = indexFile
		return nil
	}
}

func WithPackageFiles(packageFiles []string) Option {
	return func(ctx *Context) error {
		ctx.PackageFiles = append(ctx.PackageFiles, packageFiles...)
		return nil
	}
}

func WithPackageDir(packageDir string) Option {
	return func(ctx *Context) error {
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

		ctx.PackageFiles = append(ctx.PackageFiles, apkFiles...)
		return nil
	}
}

func WithSigningKey(signingKey string) Option {
	return func(ctx *Context) error {
		ctx.SigningKey = signingKey
		return nil
	}
}

// WithExpectedArch sets the expected package architecture.  Any packages with
// an unexpected architecture will not be indexed.
func WithExpectedArch(expectedArch string) Option {
	return func(ctx *Context) error {
		ctx.ExpectedArch = expectedArch
		return nil
	}
}

func New(opts ...Option) (*Context, error) {
	ctx := Context{
		PackageFiles: []string{},
		Logger:       log.New(log.Writer(), "melange: ", log.LstdFlags|log.Lmsgprefix),
	}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	return &ctx, nil
}

func (ctx *Context) GenerateIndex() error {
	packages := make([]*apkrepo.Package, len(ctx.PackageFiles))
	var mtx sync.Mutex

	g := limiter.NewConcurrencyLimiterForIO(limiter.DefaultConcurrencyLimitIO)

	for i, apkFile := range ctx.PackageFiles {
		i, apkFile := i, apkFile // capture the loop variables
		if _, err := g.Execute(func() {
			ctx.Logger.Printf("processing package %s", apkFile)
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

	var index *apkrepo.ApkIndex

	if ctx.MergeIndexFileFlag {
		originApkIndex, err := os.Open(ctx.IndexFile)
		if err == nil {
			index, err = apkrepo.IndexFromArchive(originApkIndex)
			if err != nil {
				return fmt.Errorf("failed to read apkindex from archive file: %w", err)
			}

			for _, pkg := range packages {
				found := false

				if ctx.ExpectedArch != "" && pkg.Arch != ctx.ExpectedArch {
					ctx.Logger.Printf("WARNING: %s-%s: found unexpected architecture %s, expecting %s",
						pkg.Name, pkg.Version, pkg.Arch, ctx.ExpectedArch)
					continue
				}

				for _, p := range index.Packages {
					if pkg.Name == p.Name && pkg.Version == p.Version {
						found = true
						p = pkg
					}
				}
				if !found {
					index.Packages = append(index.Packages, pkg)
				}
			}
		} else {
			// indexFile not exists, we just create a new one
			index = &apkrepo.ApkIndex{
				Packages: packages,
			}
		}
	} else {
		index = &apkrepo.ApkIndex{
			Packages: packages,
		}
	}

	pkgNames := make([]string, 0, len(packages))
	for _, p := range packages {
		pkgNames = append(pkgNames, fmt.Sprintf("%s-%s", p.Name, p.Version))
	}

	ctx.Logger.Printf("generating index at %s with new packages: %v", ctx.IndexFile, pkgNames)
	archive, err := apkrepo.ArchiveFromIndex(index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}
	outFile, err := os.Create(ctx.IndexFile)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer outFile.Close()
	if _, err = io.Copy(outFile, archive); err != nil {
		return fmt.Errorf("failed to write contents to archive file: %w", err)
	}

	if ctx.SigningKey != "" {
		ctx.Logger.Printf("signing apk index at %s", ctx.IndexFile)
		if err := sign.SignIndex(ctx.Logger, ctx.SigningKey, ctx.IndexFile); err != nil {
			return fmt.Errorf("failed to sign apk index: %w", err)
		}
	}

	return nil
}
