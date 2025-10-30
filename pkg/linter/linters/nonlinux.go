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

func NonLinuxLinter(_ context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	// Map of canonical platform name -> variants to detect in paths
	platforms := map[string][]string{
		"macos":   {"darwin", "macos", "mac_os", "mac-os", "osx", "os_x", "os-x"},
		"windows": {"windows", "win32", "win64"},
	}

	var references []types.NonLinuxReference

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		dirLower := strings.ToLower(filepath.Dir(path))
		baseLower := strings.ToLower(filepath.Base(path))

		// Check for platform references in the path
		for platform, variants := range platforms {
			for _, variant := range variants {
				if strings.Contains(dirLower, variant) || strings.Contains(baseLower, variant) {
					references = append(references, types.NonLinuxReference{
						Path:     path,
						Platform: platform,
					})
					return nil // Found a match for this file, move to next file
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	if len(references) > 0 {
		details := &types.NonLinuxDetails{
			References: references,
		}

		message := fmt.Sprintf("%s contains %d non-Linux reference(s)", pkgname, len(references))
		return types.NewStructuredError(message, details)
	}

	return nil
}
