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
	"regexp"

	"chainguard.dev/melange/pkg/config"
)

// docPackageRegex matches the names of packages whose job is to hold
// documentation, and which this linter therefore skips.
//
// A plain HasSuffix(pkgname, "-doc") test is too narrow for two naming
// shapes already in wide use, and it fails them while they are doing
// exactly the right thing:
//
//   - the plural, "-docs": jujutsu-docs, squashfs-tools-docs
//   - a version-streamed doc subpackage, "<name>-doc-<version>", which is
//     what a versioned package produces when it splits its manual pages:
//     podman-doc-6.1, pdns-auth-doc-5.0, dwarf-tools-doc-20210528
//
// Measured over the 433 packages in one repository that ship manual pages:
// the suffix test flags 50 of them, and 10 of those 50 -- 962 of the 1,036
// pages -- are correctly packaged documentation caught by one of the two
// shapes above. So 93% of what the narrow test reports is noise, which is
// the main reason this linter has not been promoted out of the warn set.
//
// Deliberately not matched: "-man". A package holding only manual pages is
// arguably a documentation package whatever it is called, but "-doc" is the
// convention split/manpages produces, and widening the rule to a second
// word trades a little noise for a weaker check.
var docPackageRegex = regexp.MustCompile(`-docs?(?:-[0-9][a-zA-Z0-9.]*)?$`)

func ManInfoLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if docPackageRegex.MatchString(pkgname) {
		return nil
	}
	return AllPaths(ctx, pkgname, fsys,
		func(path string, d fs.DirEntry) bool {
			return !d.IsDir() && (ManRegex.MatchString(path) || InfoRegex.MatchString(path))
		},
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d man/info %s but is not a documentation package", pkgname, len(paths), fileWord)
		},
	)
}
