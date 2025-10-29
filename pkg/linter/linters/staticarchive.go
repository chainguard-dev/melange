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
)

func StaticArchiveLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	// Static archives are expected in -dev/-static packages
	if strings.HasSuffix(pkgname, "-dev") || strings.HasSuffix(pkgname, "-static") {
		return nil
	}
	return AllPaths(ctx, pkgname, fsys,
		func(path string) bool { return filepath.Ext(path) == ".a" },
		func(pkgname string, paths []string) string {
			fileWord := "archive"
			if len(paths) > 1 {
				fileWord = "archives"
			}
			return fmt.Sprintf("%s contains %d static %s. Static archives bloat packages and should typically be in -dev packages or removed", pkgname, len(paths), fileWord)
		},
	)
}
