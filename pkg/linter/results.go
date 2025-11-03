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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

// saveLintResults saves the lint results to JSON files in the packages directory
func saveLintResults(ctx context.Context, cfg *config.Configuration, results map[string]*types.PackageLintResults, outputDir, arch string) error {
	log := clog.FromContext(ctx)

	// If cfg is nil, we can't determine version/epoch, so skip saving
	if cfg == nil {
		log.Warnf("skipping lint results persistence: configuration is nil")
		return nil
	}

	// Ensure the package directory exists
	packageDir := filepath.Join(outputDir, arch)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return fmt.Errorf("creating package directory: %w", err)
	}

	// Save results for each package
	for pkgName, pkgResults := range results {
		// Generate the filename: lint-{packagename}-{version}-r{epoch}.json
		filename := fmt.Sprintf("lint-%s-%s-r%d.json", pkgName, cfg.Package.Version, cfg.Package.Epoch)
		filepath := filepath.Join(packageDir, filename)

		// Marshal to JSON with indentation for readability
		jsonData, err := json.MarshalIndent(pkgResults, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling lint results for %s: %w", pkgName, err)
		}

		// Write to file
		// #nosec G306 - Lint results file should be world-readable
		if err := os.WriteFile(filepath, jsonData, 0o644); err != nil {
			return fmt.Errorf("writing lint results to %s: %w", filepath, err)
		}

		log.Infof("saved lint results to %s", filepath)
	}

	return nil
}
