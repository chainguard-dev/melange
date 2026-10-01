// Copyright 2025 Chainguard, Inc.
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

package linters

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

// NoArchLinter rejects compiled ELF files from architecture-independent packages.
func NoArchLinter(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	if cfg == nil || !cfg.Package.IsNoArch() {
		return nil
	}

	var paths []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() || IsIgnoredPath(path) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() < int64(len(ElfMagic)) {
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !IsObjectFileRegex.MatchString(ext) {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return nil
		}

		hdr := make([]byte, len(ElfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return nil
		}
		if bytes.Equal(ElfMagic, hdr) {
			paths = append(paths, path)
		}

		return nil
	})
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		return nil
	}

	word := "binary"
	if len(paths) != 1 {
		word = "binaries"
	}
	return types.NewStructuredError(
		fmt.Sprintf("%s is a noarch package but contains %d ELF %s", pkgname, len(paths), word),
		&types.PathListDetails{Paths: paths},
	)
}
