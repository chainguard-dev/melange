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
	"slices"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func UsrmergeLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	paths := []string{}
	dirs := []string{"sbin", "bin", "usr/sbin", "lib", "lib64"}

	pathInDir := func(path string, dirs ...string) bool {
		for _, d := range dirs {
			if path == d || strings.HasPrefix(path, d+"/") {
				return true
			}
		}
		return false
	}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if IsIgnoredPath(path) {
			return filepath.SkipDir
		}

		// If it's not a directory of interest just skip the whole tree
		if path != "." && path != "usr" && !pathInDir(path, dirs...) {
			return filepath.SkipDir
		}

		if slices.Contains(dirs, path) {
			if d.IsDir() || d.Type().IsRegular() {
				paths = append(paths, path)
				return nil
			}
		}

		if pathInDir(path, dirs...) {
			paths = append(paths, path)
		}

		return nil
	})
	if err != nil {
		fmt.Print("Returned error?")
		return err
	}

	if len(paths) > 0 {
		details := &types.UsrMergeDetails{
			Paths: paths,
		}

		// Build human-readable message
		message := "Package contains paths in violation of usrmerge:"
		for _, path := range paths {
			message = strings.Join([]string{message, path}, "\n")
		}

		return types.NewStructuredError(message, details)
	}

	return nil
}
