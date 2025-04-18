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

package license

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/melange/pkg/config"
)

func TestFindLicenseFiles(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "license_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFiles := []string{
		"LICENSE",
		"LICENSE.md",
		"COPYING",
		"COPYING.txt",
		"random.txt",
		"LICENSE-MIT.md",
		"README.md",
		"LICENSE-APACHE",
		"LICENSE.gemspec",
		"COPYRIGHT",
		"MIT-COPYING",
		"copyme",
		"COPY",
		"LICENSE.txt",
	}

	for _, name := range testFiles {
		filePath := filepath.Join(tempDir, name)
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp.Close()
	}

	tmpFS := apkofs.DirFS(tempDir)

	// Call function under test
	licenseFiles, err := FindLicenseFiles(tmpFS)
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
	}

	for _, file := range licenseFiles {
		t.Logf("Found license file: %s", file.Name)
	}

	// Verify the results
	// The order of the expected licenses is important, but not strictly checked
	expectedFiles := []string{
		"LICENSE",
		"LICENSE.md",
		"LICENSE.txt",
		"COPYING",
		"COPYRIGHT",
		"COPYING.txt",
		"LICENSE-APACHE",
		"LICENSE-MIT.md",
		"MIT-COPYING",
	}
	if len(licenseFiles) != len(expectedFiles) {
		t.Errorf("Expected %d license files, got %d", len(expectedFiles), len(licenseFiles))
	}

	var found bool
	for _, expected := range expectedFiles {
		found = false
		for _, l := range licenseFiles {
			if l.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license file %s not found", expected)
		}
	}
}
func TestIdentify(t *testing.T) {
	classifier, err := NewClassifier()
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}

	melangeClassifier := classifier.(*melangeClassifier)

	expectedLicenses := map[string]string{
		"LICENSE-APACHE":       "Apache-2.0",
		"LICENSE-BSD":          "BSD-3-Clause",
		"LICENSE-BSD-modified": "BSD-3-Clause",
		"LICENSE-GPLv2":        "GPL-2.0",
		"LICENSE-GPLv3":        "GPL-3.0",
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(testDataDir)
	err = fs.WalkDir(dataFS, ".", func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			t.Errorf("Error walking through testdata directory: %v", err)
			return err
		}
		if !info.IsDir() {
			filePath := path

			// Call function under test
			licenses, err := melangeClassifier.Identify(dataFS, filePath)
			if err != nil {
				t.Errorf("Identify returned an error for file %s: %v", filePath, err)
				return nil
			}

			t.Logf("Identified licenses for file %s: %v", filePath, licenses)

			// These licenses are mostly-100% matched, so only one license result should be expected
			if len(licenses) != 1 {
				t.Errorf("Expected one license detected for file %s, got %d", filePath, len(licenses))
			}

			expectedLicense, ok := expectedLicenses[info.Name()]
			if ok {
				if licenses[0].Name != expectedLicense {
					t.Errorf("Expected license %s for file %s, got %s", expectedLicense, filePath, licenses[0].Name)
				}
			} else {
				t.Logf("No expected license found for file %s", info.Name())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk through testdata directory: %v", err)
	}
}
func TestLicenseCheck(t *testing.T) {
	// Create a mock configuration
	cfg := &config.Configuration{
		Package: config.Package{
			Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: "LICENSE-APACHE"},
				{License: "MIT", LicensePath: "LICENSE-BSD"},
				{License: "GPL-2.0", LicensePath: "LICENSE-GPLv2"},
				{License: "GPL-3.0", LicensePath: "LICENSE-GPLv3"},
			},
		},
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(testDataDir)

	// Call function under test
	diffs, err := LicenseCheck(context.Background(), cfg, dataFS)
	if err != nil {
		t.Fatalf("LicenseCheck returned an error: %v", err)
	}

	// Expected differences
	expectedDiffs := []LicenseDiff{
		{
			Path:   "LICENSE-BSD",
			Is:     "MIT",
			Should: "BSD-3-Clause",
		},
	}

	// Verify the results
	if len(diffs) != len(expectedDiffs) {
		t.Errorf("Expected %d license differences, got %d", len(expectedDiffs), len(diffs))
	}

	for _, expected := range expectedDiffs {
		found := false
		for _, diff := range diffs {
			if diff.Path == expected.Path && diff.Is == expected.Is && diff.Should == expected.Should {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license difference %+v not found", expected)
		}
	}
}
func TestLicenseCheckWithOverrides(t *testing.T) {
	// Create a mock configuration with detection overrides
	// There is one correct override (BSD -> MIT) and one incorrect, where we say we expected MIT and overriding it to GPL-3.0
	cfg := &config.Configuration{
		Package: config.Package{
			Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: "LICENSE-APACHE"},
				{License: "MIT", LicensePath: "LICENSE-BSD", DetectionOverride: "BSD-3-Clause"},
				{License: "GPL-3.0", LicensePath: "LICENSE-GPLv2", DetectionOverride: "MIT"},
				{License: "GPL-3.0", LicensePath: "LICENSE-GPLv3"},
			},
		},
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(testDataDir)

	// Call function under test
	diffs, err := LicenseCheck(context.Background(), cfg, dataFS)
	if err != nil {
		t.Fatalf("LicenseCheck returned an error: %v", err)
	}

	// Expected differences
	expectedDiffs := []LicenseDiff{
		{
			Path:     "LICENSE-GPLv2",
			Is:       "GPL-3.0",
			Should:   "GPL-2.0",
			Override: "MIT",
		},
	}

	// Verify the results
	if len(diffs) != len(expectedDiffs) {
		t.Errorf("Expected %d license differences, got %d", len(expectedDiffs), len(diffs))
	}

	for _, expected := range expectedDiffs {
		found := false
		for _, diff := range diffs {
			if diff.Path == expected.Path && diff.Is == expected.Is && diff.Should == expected.Should && diff.Override == expected.Override {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license difference %+v not found", expected)
		}
	}
}
