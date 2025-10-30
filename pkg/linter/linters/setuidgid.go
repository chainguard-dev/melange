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
	"os"
	"strconv"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func modeToOctal(mode os.FileMode) string {
	perm := uint64(mode.Perm())

	if mode&os.ModeSetuid != 0 {
		perm |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		perm |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		perm |= 0o1000
	}

	return strconv.FormatUint(perm, 8)
}

func IsSetUIDOrGIDLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var specialPermFiles []types.FilePermissionInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		bits := mode & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		if bits != 0 {
			var parts []string
			if mode&fs.ModeSetuid != 0 {
				parts = append(parts, "setuid")
			}
			if mode&fs.ModeSetgid != 0 {
				parts = append(parts, "setgid")
			}
			if mode&fs.ModeSticky != 0 {
				parts = append(parts, "sticky")
			}
			specialPermFiles = append(specialPermFiles, types.FilePermissionInfo{
				Path:        path,
				Mode:        perm,
				Permissions: parts,
			})
		}

		return nil
	})
	if err != nil {
		return err
	}

	if len(specialPermFiles) > 0 {
		details := &types.SpecialPermissionsDetails{
			Files: specialPermFiles,
		}

		fileWord := "file"
		if len(specialPermFiles) > 1 {
			fileWord = "files"
		}
		message := fmt.Sprintf("%s contains %d %s with special permissions (setuid/setgid)", pkgname, len(specialPermFiles), fileWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}
