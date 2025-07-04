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

package syft

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"chainguard.dev/melange/pkg/sbom"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func TestGoldenScans(t *testing.T) {
	// Test directories - each should have a corresponding .golden.json file
	// To add a new test:
	// 1. Create a new directory under testdata/ with test files
	// 2. Add the directory name to this list
	// 3. Run with UPDATE_GOLDEN=true to generate the golden file
	testDirs := []string{
		"go-module",
		"python", 
		"ruby",
		"node",
	}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			ctx := slogtest.Context(t)

			scanPath := filepath.Join("testdata", dir)
			goldenFile := filepath.Join("testdata", dir+".golden.json")

			scanner := NewScanner(scanPath)
			packages, err := scanner.Scan(ctx)
			require.NoError(t, err)

			// Generate golden file if it needs update
			if os.Getenv("UPDATE_GOLDEN") == "true" {
				generateGoldenFile(t, goldenFile, packages)
			}

			// Compare with golden file
			compareWithGolden(t, goldenFile, packages)
		})
	}
}

// generateGoldenFile creates a golden file from the scan results
func generateGoldenFile(t *testing.T, filename string, packages []sbom.Package) {
	// Sort packages for consistent output
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})

	// Convert to a simplified format for golden files
	type goldenPackage struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl,omitempty"`
		Licenses string `json:"licenses,omitempty"`
	}

	goldenPackages := make([]goldenPackage, 0, len(packages))
	for _, pkg := range packages {
		gp := goldenPackage{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Licenses: pkg.LicenseDeclared,
		}
		if pkg.PURL != nil {
			gp.PURL = pkg.PURL.String()
		}
		goldenPackages = append(goldenPackages, gp)
	}

	data, err := json.MarshalIndent(goldenPackages, "", "  ")
	require.NoError(t, err)

	err = os.MkdirAll(filepath.Dir(filename), 0755)
	require.NoError(t, err)

	err = os.WriteFile(filename, data, 0644)
	require.NoError(t, err)

	t.Logf("Generated golden file: %s", filename)
}

// compareWithGolden compares scan results with a golden file
func compareWithGolden(t *testing.T, filename string, packages []sbom.Package) {
	// Read golden file
	goldenData, err := os.ReadFile(filename)
	require.NoError(t, err)

	// Sort packages for consistent comparison
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})

	// Convert to JSON for comparison
	type goldenPackage struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl,omitempty"`
		Licenses string `json:"licenses,omitempty"`
	}

	actualPackages := make([]goldenPackage, 0, len(packages))
	for _, pkg := range packages {
		gp := goldenPackage{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Licenses: pkg.LicenseDeclared,
		}
		if pkg.PURL != nil {
			gp.PURL = pkg.PURL.String()
		}
		actualPackages = append(actualPackages, gp)
	}

	actualData, err := json.MarshalIndent(actualPackages, "", "  ")
	require.NoError(t, err)

	require.JSONEq(t, string(goldenData), string(actualData),
		"SBOM output differs from golden file. Run with UPDATE_GOLDEN=true to update.")
}
