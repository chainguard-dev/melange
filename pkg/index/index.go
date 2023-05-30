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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	apko_log "chainguard.dev/apko/pkg/log"
	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/korovkin/limiter"
	"github.com/sirupsen/logrus"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
)

type Context struct {
	PackageFiles       []string
	IndexFile          string
	SourceIndexFile    string
	MergeIndexFileFlag bool
	SigningKey         string
	Logger             *logrus.Logger
	ExpectedArch       string
	Index              apkrepo.ApkIndex
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
		ctx.SourceIndexFile = indexFile
		return nil
	}
}

func WithSourceIndexFile(indexFile string) Option {
	return func(ctx *Context) error {
		ctx.SourceIndexFile = indexFile
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
		Logger: &logrus.Logger{
			Out:       os.Stderr,
			Formatter: &apko_log.Formatter{},
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.InfoLevel,
		},
	}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	return &ctx, nil
}

func (ctx *Context) LoadIndex(sourceFile string) error {
	f, err := os.Open(sourceFile)
	defer f.Close()

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	index, err := apkrepo.IndexFromArchive(f)
	if err != nil {
		return fmt.Errorf("failed to read apkindex from archive file: %w", err)
	}

	copy(ctx.Index.Packages, index.Packages)
	ctx.Index.Description = index.Description

	return nil
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

			if ctx.ExpectedArch != "" && pkg.Arch != ctx.ExpectedArch {
				ctx.Logger.Printf("WARNING: %s-%s: found unexpected architecture %s, expecting %s",
					pkg.Name, pkg.Version, pkg.Arch, ctx.ExpectedArch)
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

	if ctx.MergeIndexFileFlag {
		if err := ctx.LoadIndex(ctx.SourceIndexFile); err != nil {
			return err
		}
	}

	for _, pkg := range packages {
		found := false

		for _, p := range ctx.Index.Packages {
			if pkg.Name == p.Name && pkg.Version == p.Version {
				found = true
				p = pkg
			}
		}

		if !found {
			ctx.Index.Packages = append(ctx.Index.Packages, pkg)
		}
	}

	pkgNames := make([]string, 0, len(packages))
	for _, p := range packages {
		if p != nil {
			pkgNames = append(pkgNames, fmt.Sprintf("%s-%s", p.Name, p.Version))
		}
	}

	ctx.Logger.Printf("generating index at %s with new packages: %v", ctx.IndexFile, pkgNames)
	indexWriter := ctx.WriteArchiveIndex
	if err := indexWriter(&ctx.Index); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) WriteArchiveIndex(index *apkrepo.ApkIndex) error {
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
