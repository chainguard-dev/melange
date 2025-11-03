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
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func UnsupportedArchLinter(_ context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	supported := []string{"aarch64", "arm64", "amd64", "x86_64", "x86-64"}

	archs := []string{
		"i386", "i686", "x86_32", "x86-32",
		"ppc64", "ppc64le", "powerpc",
		"s390x", "s390",
		"mips", "mipsel", "mips64",
		"riscv", "riscv64",
		"sparc", "sparc64",
		"ia64", "m68k",
	}

	var unsupportedFiles []types.UnsupportedArchInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		pathLower := strings.ToLower(path)
		dirLower := strings.ToLower(filepath.Dir(path))
		baseLower := strings.ToLower(filepath.Base(path))

		for _, arch := range archs {
			if strings.Contains(dirLower, "/"+arch+"/") || strings.Contains(dirLower, "/"+arch) && dirLower == strings.ToLower(filepath.Dir(path)) {
				unsupportedFiles = append(unsupportedFiles, types.UnsupportedArchInfo{
					Path: path,
					Arch: arch,
				})
				return nil
			}

			for _, sep := range []string{"-", "_", "."} {
				if strings.Contains(baseLower, sep+arch+sep) ||
					strings.Contains(baseLower, sep+arch+".") ||
					strings.HasSuffix(baseLower, sep+arch) {
					isSupported := false
					for _, s := range supported {
						if strings.Contains(pathLower, s) {
							isSupported = true
							break
						}
					}
					if !isSupported {
						unsupportedFiles = append(unsupportedFiles, types.UnsupportedArchInfo{
							Path: path,
							Arch: arch,
						})
						return nil
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	if len(unsupportedFiles) > 0 {
		details := &types.UnsupportedArchDetails{
			Files: unsupportedFiles,
		}

		message := fmt.Sprintf("%s contains %d unsupported architecture reference(s)", pkgname, len(unsupportedFiles))
		return types.NewStructuredError(message, details)
	}

	return nil
}
