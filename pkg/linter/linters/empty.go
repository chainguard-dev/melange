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

	"chainguard.dev/melange/pkg/config"
)

func EmptyLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	foundfile := false
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if IsIgnoredPath(path) {
			return nil
		}

		if d.IsDir() {
			// Ignore directories
			return nil
		}

		foundfile = true
		return fs.SkipAll
	})
	if err != nil {
		return err
	}

	// Nothing to do
	if foundfile {
		return nil
	}

	return fmt.Errorf("package is empty but no-provides is not set")
}
