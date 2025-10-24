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

func LddcheckTestLinter(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	// Check if the appropriate test is configured
	hasTest := false
	if cfg != nil {
		if cfg.Package.Name == pkgname {
			if cfg.Test != nil {
				for _, test := range cfg.Test.Pipeline {
					if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
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
							if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
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

	// Collect all shared object files
	return AllPaths(ctx, pkgname, fsys,
		func(path string) bool { return IsSharedObjectFileRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			if cfg == nil {
				return fmt.Sprintf("%s contains shared objects but missing .melange.yaml", pkgname)
			}
			return fmt.Sprintf("%s contains shared objects but test/ldd-check is not configured", pkgname)
		},
	)
}
