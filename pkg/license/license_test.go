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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/config"
)

func TestFindLicenseFiles(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

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
		filePath := filepath.Join(tmpDir, name)
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp.Close()
	}

	tmpFS := apkofs.DirFS(t.Context(), tmpDir)

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

	testInoreFiles := []string{
		"node_modules/LICENSE",
		"node_modules/LICENSE.md",
		"venv/COPYING",
		"venv/COPYING.txt",
		"venv/random.txt",
		"env/LICENSE-MIT.md",
		"env/README.md",
		"env/LICENSE-APACHE",
		".virtualenv/LICENSE.gemspec",
		".virtualenv/COPYRIGHT",
		".virtualenv/MIT-COPYING",
		"node_modules/copyme",
		"node_modules/COPY",
		"node_modules/LICENSE.txt",
		"rust-src-1.86.0/rust-src/foo/LICENSE-MIT",
		"rustc-src-1.86.0/rust-src/foo/LICENSE-MIT",
	}

	tmpDir = t.TempDir()
	for _, name := range testInoreFiles {
		filePath := filepath.Join(tmpDir, name)
		err := os.MkdirAll(filepath.Join(tmpDir, filepath.Dir(name)), os.ModePerm)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp.Close()
	}

	tmpFS = apkofs.DirFS(t.Context(), tmpDir)

	// Call function under test
	licenseFiles, err = FindLicenseFiles(tmpFS)
	if len(licenseFiles) > 0 {
		t.Fatalf("Failed to test ignored files")
	}
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
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
		"COPYRIGHT":            "NOASSERTION",
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(t.Context(), testDataDir)
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
				{License: "GPL-2.0 OR GPL-3.0"},
			},
		},
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(t.Context(), testDataDir)

	// Create a buffer to capture log output
	var logBuf strings.Builder
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := clog.New(handler)
	ctx := clog.WithLogger(context.Background(), logger)

	// Call function under test
	_, diffs, err := LicenseCheck(ctx, cfg, dataFS)
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

	// Now also check the log output and make sure that "low-confidence" is present only for the low-confidence
	// licenses: LICENSE-BSD-modified and COPYRIGHT (the latter is not a valid license)
	found := false
	lines := strings.SplitSeq(logBuf.String(), "\n")
	for line := range lines {
		if strings.Contains(line, "low-confidence") {
			// Check if the line contains one of the expected licenses
			if !strings.Contains(line, "LICENSE-BSD-modified") && !strings.Contains(line, "COPYRIGHT") {
				t.Errorf("Unexpected log line with 'low-confidence': %s", line)
			}
			found = true
		}
	}
	if !found {
		t.Error("Expected log line with 'low-confidence' not found")
	}
}

func TestLicenseCheck_withOverrides(t *testing.T) {
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
	dataFS := apkofs.DirFS(t.Context(), testDataDir)

	// Call function under test
	_, diffs, err := LicenseCheck(context.Background(), cfg, dataFS)
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
