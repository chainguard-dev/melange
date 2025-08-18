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
	"testing"

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

// TestFetchSourceFromMelange tests the FetchSourceFromMelange function with mocked sourceRunCommand
func TestFetchSourceFromMelange(t *testing.T) {
	// Mock the sourceRunCommand function
	stepsRun := []string{}
	originalSourceRunPipelineStep := sourceRunPipelineStep
	defer func() { sourceRunPipelineStep = originalSourceRunPipelineStep }()
	sourceRunPipelineStep = func(ctx context.Context, step config.Pipeline) error {
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
