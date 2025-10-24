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

func CudaDriverLibLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return AllPaths(ctx, pkgname, fsys,
		func(path string) bool { return IsCudaDriverLibRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			return fmt.Sprintf("%s contains CUDA driver-specific libraries", pkgname)
		},
	)
}
