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

package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
)

// Helper function to create a mock .apk file with a .melange.yaml file inside
func createMockApk(apkFilePath string, addMelange bool) error {
	file, err := os.Create(apkFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Add a .melange.yaml file to the tarball if requested
	if addMelange {
		melangeYamlContent := "name: test-package\nversion: 1.0.0"
		header := &tar.Header{
			Name: ".melange.yaml",
			Mode: 0o600,
			Size: int64(len(melangeYamlContent)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write([]byte(melangeYamlContent)); err != nil {
			return err
		}
	}

	return nil
}

// TestExtractMelangeYamlFromTarball checks the extraction of .melange.yaml from a .apk file
func TestExtractMelangeYamlFromTarball(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Create a mock .apk file with a .melange.yaml file inside
	apkFilePath := filepath.Join(tmpDir, "test.apk")
	err := createMockApk(apkFilePath, true)
	if err != nil {
		t.Fatalf("Failed to create mock apk file: %v", err)
	}

	// Destination directory for extraction
	destDir := filepath.Join(tmpDir, "extracted")
	err = extractMelangeYamlFromTarball(apkFilePath, destDir)
	if err != nil {
		t.Fatalf("Failed to extract .melange.yaml: %v", err)
	}

	// Check if the .melange.yaml file exists in the destination directory
	extractedFilePath := filepath.Join(destDir, ".melange.yaml")
	if _, err := os.Stat(extractedFilePath); os.IsNotExist(err) {
		t.Fatalf(".melange.yaml file was not extracted")
	}
}

// TestExtractMelangeYamlFromTarballNoMelange checks the behavior when the .apk file does not contain a .melange.yaml file
func TestExtractMelangeYamlFromTarball_noMelange(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Create a mock .apk file without a .melange.yaml file inside
	apkFilePath := filepath.Join(tmpDir, "test.apk")
	err := createMockApk(apkFilePath, false)
	if err != nil {
		t.Fatalf("Failed to create mock apk file: %v", err)
	}

	// Destination directory for extraction
	destDir := filepath.Join(tmpDir, "extracted")
	err = extractMelangeYamlFromTarball(apkFilePath, destDir)
	if err == nil {
		t.Fatalf("Expected error when extracting .melange.yaml, but got none")
	}
}

// TestFetchSourceFromMelange tests the FetchSourceFromMelange function with a mocked step dispatcher
func TestFetchSourceFromMelange(t *testing.T) {
	// Mock the step dispatcher so the test stays hermetic (no network/git).
	stepsRun := []string{}
	originalSourceRunStep := sourceRunStep
	defer func() { sourceRunStep = originalSourceRunStep }()
	sourceRunStep = func(ctx context.Context, step config.Pipeline, sm *build.SubstitutionMap, isApk bool, destDir string) error {
		fmt.Printf("Running step: %s\n", step.Uses)
		stepsRun = append(stepsRun, step.Uses)
		return nil
	}

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	testCases := []struct {
		fileName      string
		expectedSteps []string
		expectedName  string
		expectedFiles []string
	}{
		{"fetch.yaml", []string{"fetch"}, "fetch", nil},
		{"fetch-with-patch.yaml", []string{"fetch", "patch"}, "fetch-with-patch", []string{"foo.patch"}},
		{"git-checkout.yaml", []string{"git-checkout"}, "git-checkout", nil},
	}

	// Test each file
	testdataDir := "testdata"
	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			// Clear out the stepsRun before each test
			stepsRun = []string{}

			filePath := filepath.Join(testdataDir, tc.fileName)
			destDir := filepath.Join(tmpDir, tc.fileName)

			// Call FetchSourceFromMelange
			ctx := context.Background()
			cfg, err := FetchSourceFromMelange(ctx, filePath, destDir)
			if err != nil {
				t.Fatalf("FetchSourceFromMelange failed: %v", err)
			}

			// Validate the configuration
			if cfg.Package.Name != tc.expectedName {
				t.Errorf("Expected name %s, got %s", tc.expectedName, cfg.Package.Name)
			}

			// Validate the steps run
			if len(stepsRun) != len(tc.expectedSteps) {
				t.Fatalf("Expected %d steps, got %d", len(tc.expectedSteps), len(stepsRun))
			}
			for i, step := range stepsRun {
				if step != tc.expectedSteps[i] {
					t.Errorf("Expected step %s, got %s", tc.expectedSteps[i], step)
				}
			}

			// Validate the files in the destination directory
			if tc.expectedFiles == nil {
				return
			}
			for _, file := range tc.expectedFiles {
				filePath := filepath.Join(destDir, file)
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					t.Errorf("Expected file %s to exist in %s, but it does not", file, destDir)
				}
			}
		})
	}
}

// TestFetchSourceFromMelange_inputsTreatedAsData runs the real (unmocked)
// dispatcher against configs whose inputs contain shell-like syntax, and
// asserts those inputs are treated as literal data: the fetch/checkout fails
// (the value is not a valid URL or git remote) and no side-effect file is
// produced.
func TestFetchSourceFromMelange_inputsTreatedAsData(t *testing.T) {
	tmpDir := t.TempDir()
	marker := filepath.Join(tmpDir, "marker")

	// If a value were ever evaluated by a shell, it would create the marker
	// file. As literal data (a URL / git remote) it cannot.
	configs := map[string]string{
		"fetch-uri": `package:
  name: example
  version: "1.0.0"
  epoch: 0
  copyright:
    - license: MIT
pipeline:
  - uses: fetch
    with:
      uri: "$(touch ` + marker + `; echo x)"
      expected-none: "true"
`,
		"git-checkout-repository": `package:
  name: example
  version: "1.0.0"
  epoch: 0
  copyright:
    - license: MIT
pipeline:
  - uses: git-checkout
    with:
      repository: "$(touch ` + marker + `; echo x)"
`,
	}

	for name, content := range configs {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(marker)

			cfgPath := filepath.Join(tmpDir, name+".yaml")
			if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			// The value is not a valid URL/remote, so fetching fails.
			_, err := FetchSourceFromMelange(context.Background(), cfgPath, filepath.Join(tmpDir, name+"-out"))
			if err == nil {
				t.Errorf("expected an error fetching from an invalid uri/repository, got nil")
			}

			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatalf("input was not treated as literal data (marker file %s was created)", marker)
			}
		})
	}
}

// TestFetchSourceFromMelange_pathsConfinedToWorkspace asserts that the path
// inputs of the source steps resolve inside the workspace: absolute values and
// `../` traversal are rejected, and the step leaves nothing behind outside the
// destination directory.
func TestFetchSourceFromMelange_pathsConfinedToWorkspace(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	header := `package:
  name: example
  version: "1.0.0"
  epoch: 0
  copyright:
    - license: MIT
pipeline:
`

	configs := map[string]string{
		"fetch-directory-absolute": header + `  - uses: fetch
    with:
      uri: https://example.invalid/archive.tar.gz
      directory: ` + outsideDir + `
`,
		"fetch-directory-traversal": header + `  - uses: fetch
    with:
      uri: https://example.invalid/archive.tar.gz
      directory: ../outside
`,
		"git-checkout-destination-absolute": header + `  - uses: git-checkout
    with:
      repository: https://example.invalid/repo.git
      destination: ` + outsideDir + `
`,
		"git-checkout-destination-traversal": header + `  - uses: git-checkout
    with:
      repository: https://example.invalid/repo.git
      destination: ../outside
`,
		"patch-absolute": header + `  - uses: patch
    with:
      patches: /etc/passwd
`,
		"patch-traversal": header + `  - uses: patch
    with:
      patches: ../outside/x.patch
`,
		"series-traversal": header + `  - uses: patch
    with:
      series: ../outside/series
`,
	}

	for name, content := range configs {
		t.Run(name, func(t *testing.T) {
			cfgPath := filepath.Join(tmpDir, name+".yaml")
			if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			workspace := filepath.Join(tmpDir, name+"-out")
			_, err := FetchSourceFromMelange(context.Background(), cfgPath, workspace)
			if err == nil {
				t.Fatalf("expected a path-confinement error, got nil")
			}
			// The step must be rejected on the path, not merely fail later on
			// an unreachable host.
			if !strings.Contains(err.Error(), "escapes the workspace") &&
				!strings.Contains(err.Error(), "are not allowed") {
				t.Fatalf("expected a path-confinement error, got: %v", err)
			}

			entries, readErr := os.ReadDir(outsideDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("wrote %d entries outside the workspace: %v", len(entries), entries)
			}
		})
	}
}

// TestFetchSourceFromMelange_symlinkedDirectoryRejected covers a `directory:`
// that is relative and lexically inside the workspace but names a symlink
// pointing out of it, as an earlier step in the same pipeline could have
// created. Containment is checked after resolving symlinks, so it is rejected.
func TestFetchSourceFromMelange_symlinkedDirectoryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := filepath.Join(tmpDir, "outside")
	workspace := filepath.Join(tmpDir, "workspace")
	for _, d := range []string{outsideDir, workspace} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Stands in for a symlink a previous fetch step extracted.
	if err := os.Symlink(outsideDir, filepath.Join(workspace, "outward-link")); err != nil {
		t.Fatal(err)
	}

	content := `package:
  name: example
  version: "1.0.0"
  epoch: 0
  copyright:
    - license: MIT
pipeline:
  - uses: fetch
    with:
      uri: https://example.invalid/archive.tar.gz
      directory: outward-link
`
	cfgPath := filepath.Join(tmpDir, "symlink.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := FetchSourceFromMelange(context.Background(), cfgPath, workspace)
	if err == nil {
		t.Fatalf("expected a path-confinement error, got nil")
	}
	if !strings.Contains(err.Error(), "escapes the workspace") {
		t.Fatalf("expected a path-confinement error, got: %v", err)
	}
}
