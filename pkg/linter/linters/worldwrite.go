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
	"chainguard.dev/melange/pkg/linter/types"
)

func WorldWriteableLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var worldWriteableFiles []types.FilePermissionInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		if mode&0o002 != 0 {
			permissions := []string{"world-writable"}
			if mode&0o111 != 0 {
				permissions = append(permissions, "executable")
			}
			worldWriteableFiles = append(worldWriteableFiles, types.FilePermissionInfo{
				Path:        path,
				Mode:        perm,
				Permissions: permissions,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(worldWriteableFiles) > 0 {
		details := &types.WorldWriteableDetails{
			Files: worldWriteableFiles,
		}

		fileWord := "file"
		if len(worldWriteableFiles) > 1 {
			fileWord = "files"
		}
		message := fmt.Sprintf("%s contains %d world-writeable %s", pkgname, len(worldWriteableFiles), fileWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}
