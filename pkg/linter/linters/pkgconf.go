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

func PkgconfTestLinter(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	// Check if the appropriate test is configured
	hasTest := false
	if cfg != nil {
		if cfg.Package.Name == pkgname {
			if cfg.Test != nil {
				for _, test := range cfg.Test.Pipeline {
					if test.Uses == "test/pkgconf" {
						hasTest = true
						break
					}
				}
			}
		} else {
			for _, p := range cfg.Subpackages {
				if p.Name == pkgname {
					if p.Test != nil {
						for _, test := range p.Test.Pipeline {
							if test.Uses == "test/pkgconf" {
								hasTest = true
								break
							}
						}
					}
					break
				}
			}
		}
	}

	// If test is configured, no need to check files
	if hasTest {
		return nil
	}

	// Collect all pkgconfig files
	return AllPaths(ctx, pkgname, fsys,
		func(path string) bool { return PkgconfDirRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			if cfg == nil {
				return fmt.Sprintf("%s contains pkgconfig files but missing .melange.yaml", pkgname)
			}
			return fmt.Sprintf("%s contains pkgconfig files but test/pkgconf is not configured", pkgname)
		},
	)
}
