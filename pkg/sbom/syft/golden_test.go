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

// goldenTestCase represents a test case for golden testing
type goldenTestCase struct {
	name       string
	scanPath   string
	goldenFile string
	// Minimum expected packages - we check at least these are found
	// This allows for some flexibility as Syft improves
	minExpectedPackages []expectedPackage
}

type expectedPackage struct {
	name    string
	version string
	purl    string
}

func TestGoldenScans(t *testing.T) {
	testCases := []goldenTestCase{
		{
			name:       "Go Module",
			scanPath:   "testdata/go-module",
			goldenFile: "testdata/go-module.golden.json",
			minExpectedPackages: []expectedPackage{
				{
					name:    "go-module:github.com/spf13/cobra",
					version: "v1.8.0",
					purl:    "pkg:golang/github.com/spf13/cobra@v1.8.0",
				},
				{
					name:    "go-module:github.com/sirupsen/logrus",
					version: "v1.9.3",
					purl:    "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
				},
			},
		},
		{
			name:       "Python",
			scanPath:   "testdata/python",
			goldenFile: "testdata/python.golden.json",
			minExpectedPackages: []expectedPackage{
				{
					name:    "python:requests",
					version: "2.31.0",
					purl:    "pkg:pypi/requests@2.31.0",
				},
				{
					name:    "python:flask",
					version: "3.0.0",
					purl:    "pkg:pypi/flask@3.0.0",
				},
				{
					name:    "python:numpy",
					version: "1.26.0",
					purl:    "pkg:pypi/numpy@1.26.0",
				},
				{
					name:    "python:pandas",
					version: "2.1.1",
					purl:    "pkg:pypi/pandas@2.1.1",
				},
			},
		},
		// Ruby and Node.js tests are commented out for now because Syft requires
		// Gemfile.lock and package-lock.json respectively to detect packages
		// {
		// 	name:       "Ruby",
		// 	scanPath:   "testdata/ruby",
		// 	goldenFile: "testdata/ruby.golden.json",
		// 	minExpectedPackages: []expectedPackage{
		// 		{
		// 			name:    "gem:sinatra",
		// 			version: "3.1.0",
		// 			purl:    "pkg:gem/sinatra@3.1.0",
		// 		},
		// 		{
		// 			name:    "gem:rails",
		// 			version: "7.1.0",
		// 			purl:    "pkg:gem/rails@7.1.0",
		// 		},
		// 	},
		// },
		// {
		// 	name:       "Node.js",
		// 	scanPath:   "testdata/node",
		// 	goldenFile: "testdata/node.golden.json",
		// 	minExpectedPackages: []expectedPackage{
		// 		{
		// 			name:    "npm:express",
		// 			version: "4.18.2",
		// 			purl:    "pkg:npm/express@4.18.2",
		// 		},
		// 		{
		// 			name:    "npm:lodash",
		// 			version: "4.17.21",
		// 			purl:    "pkg:npm/lodash@4.17.21",
		// 		},
		// 	},
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			
			scanner := NewScanner(tc.scanPath)
			packages, err := scanner.Scan(ctx)
			require.NoError(t, err)
			
			// Verify minimum expected packages
			for _, expected := range tc.minExpectedPackages {
				found := false
				for _, pkg := range packages {
					if pkg.Name == expected.name && pkg.Version == expected.version {
						found = true
						// Check PURL if expected
						if expected.purl != "" && pkg.PURL != nil {
							require.Equal(t, expected.purl, pkg.PURL.String())
						}
						break
					}
				}
				require.True(t, found, "Expected package not found: %s@%s", expected.name, expected.version)
			}
			
			// Generate golden file if it doesn't exist (with UPDATE_GOLDEN=true)
			if os.Getenv("UPDATE_GOLDEN") == "true" {
				generateGoldenFile(t, tc.goldenFile, packages)
			}
			
			// Compare with golden file if it exists
			if _, err := os.Stat(tc.goldenFile); err == nil {
				compareWithGolden(t, tc.goldenFile, packages)
			}
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