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

package linter

import (
	"fmt"
	"strings"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/linter/types"
)

// logStructuredDetails displays itemized details for structured errors
func logStructuredDetails(log *clog.Logger, details any) {
	if details == nil {
		return
	}

	switch d := details.(type) {
	case *types.DuplicateFilesDetails:
		for _, dup := range d.Duplicates {
			log.Warnf("    - %s (%d copies, %s wasted)", dup.Basename, dup.Count, dup.WastedSize)
		}
	case *types.NonLinuxDetails:
		for _, ref := range d.References {
			log.Warnf("    - %s (%s)", ref.Path, ref.Platform)
		}
	case *types.UnsupportedArchDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (%s)", file.Path, file.Arch)
		}
	case *types.BinaryArchDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s (%s)", bin.Path, bin.Arch)
		}
	case *types.SpecialPermissionsDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (mode: %s, %s)", file.Path, file.Mode, strings.Join(file.Permissions, "+"))
		}
	case *types.WorldWriteableDetails:
		for _, file := range d.Files {
			perms := ""
			if len(file.Permissions) > 0 {
				perms = fmt.Sprintf(" [%s]", strings.Join(file.Permissions, "+"))
			}
			log.Warnf("    - %s (mode: %s)%s", file.Path, file.Mode, perms)
		}
	case *types.UnstrippedBinaryDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s", bin)
		}
	case *types.PythonMultipleDetails:
		for _, pkg := range d.Packages {
			log.Warnf("    - %s", pkg)
		}
	case *types.PathListDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	case *types.UsrMergeDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	}
}
