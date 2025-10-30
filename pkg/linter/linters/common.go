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
	"io/fs"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/linter/types"
)

var (
	ElfMagic                 = []byte{'\x7f', 'E', 'L', 'F'}
	InfoRegex                = regexp.MustCompile(`^usr/(?:local/)?share/info/(?:dir|[^/]+\.info(?:\-[0-9]+)?(?:\.(?:gz|bz2|xz|lzma|Z))?)$`)
	IsCudaDriverLibRegex     = regexp.MustCompile(`^usr/lib/lib(cuda|nvidia-ml)\.so(\.[0-9]+)*$`)
	IsDocumentationFileRegex = regexp.MustCompile(`(?:READ(?:\.?ME)?|TODO|CREDITS|\.(?:md|docx?|rst|[0-9][a-z]))$`)
	IsObjectFileRegex        = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)
	IsSharedObjectFileRegex  = regexp.MustCompile(`\.so(?:\.[0-9]+)*$`)
	IsTempDirRegex           = regexp.MustCompile("^(var/)?(tmp|run)/")
	ManRegex                 = regexp.MustCompile(`^usr/(?:local/)?share/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$|^usr/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$`)
	PkgconfDirRegex          = regexp.MustCompile("^usr/(lib|share)/pkgconfig/")
)

// AllPaths walks the filesystem and collects all paths matching the predicate,
// returning a structured error if any paths are found.
func AllPaths(ctx context.Context, pkgname string, fsys fs.FS, predicate func(path string) bool, messageFunc func(pkgname string, paths []string) string) error {
	var matchedPaths []string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if predicate(path) {
			matchedPaths = append(matchedPaths, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(matchedPaths) > 0 {
		details := &types.PathListDetails{
			Paths: matchedPaths,
		}
		return types.NewStructuredError(messageFunc(pkgname, matchedPaths), details)
	}

	return nil
}

// Determine if a path should be ignored by a linter
func IsIgnoredPath(path string) bool {
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}
