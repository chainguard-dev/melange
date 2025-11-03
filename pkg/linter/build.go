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
	"context"
	"fmt"
	"path/filepath"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

// Lint the given build directory at the given path
// Lint results will be stored as JSON in the packages directory
func LintBuild(ctx context.Context, cfg *config.Configuration, packageName string, require, warn []string, fsys apkofs.FullFS, outputDir, arch string) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	// map of pkgname -> lint results
	results := make(map[string]*types.PackageLintResults)

	log := clog.FromContext(ctx)
	log.Infof("linting apk: %s", packageName)

	// Construct full package name with version and epoch
	var fullPackageName string
	if cfg != nil {
		fullPackageName = fmt.Sprintf("%s-%s-r%d", packageName, cfg.Package.Version, cfg.Package.Epoch)
	} else {
		fullPackageName = packageName
	}

	// Run warning linters - logs directly, ignores errors
	_ = lintPackageFS(ctx, cfg, packageName, fsys, warn, results, fullPackageName)

	// Run required linters - logs directly, returns errors
	lintErr := lintPackageFS(ctx, cfg, packageName, fsys, require, results, fullPackageName)

	// Save lint results to JSON file if there are any findings
	if outputDir != "" && len(results) > 0 {
		log.Infof("saving %d package lint result(s) to %s", len(results), filepath.Join(outputDir, arch))
		if err := saveLintResults(ctx, cfg, results, outputDir, arch); err != nil {
			log.Warnf("failed to save lint results: %v", err)
		}
	} else {
		log.Infof("no lint findings to persist for package %s", packageName)
	}

	return lintErr
}
