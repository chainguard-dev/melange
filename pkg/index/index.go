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

	"chainguard.dev/melange/internal/sign"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
	"golang.org/x/sync/errgroup"
)

type Context struct {
	PackageFiles []string
	IndexFile    string
	SigningKey   string
	Logger       *log.Logger
}

type Option func(*Context) error

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

	var errg errgroup.Group

	for i, apkFile := range ctx.PackageFiles {
		i, apkFile := i, apkFile // capture the loop variables
		errg.Go(func() error {
			ctx.Logger.Printf("processing package %s", apkFile)
			f, err := os.Open(apkFile)
			if err != nil {
				return fmt.Errorf("failed to open package %s: %w", apkFile, err)
			}
			pkg, err := apkrepo.ParsePackage(f)
			if err != nil {
				return fmt.Errorf("failed to parse package %s: %w", apkFile, err)
			}
			packages[i] = pkg
			return nil
		})
	}
	if err := errg.Wait(); err != nil {
		return err
	}

	index := &apkrepo.ApkIndex{
		Packages: packages,
	}
	ctx.Logger.Printf("generating index at %s", ctx.IndexFile)
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
