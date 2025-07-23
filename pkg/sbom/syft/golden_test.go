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
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/melange/pkg/sbom"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

var apks = []string{
	"crane-0.19.1-r6.apk",
	"jenkins-2.461-r0.apk",
	"jruby-9.4-9.4.7.0-r0.apk",
	"openjdk-21-21.0.3-r3.apk",
	"openssl-3.3.0-r8.apk",
	"perl-yaml-syck-1.34-r3.apk",
	"powershell-7.4.1-r0.apk",
	"php-odbc-8.2.11-r1.apk",
	"py3-poetry-core-1.9.0-r1.apk",
	"python-3.11-base-3.11.9-r6.apk",
	"terraform-1.5.7-r12.apk",
	"thanos-0.32-0.32.5-r4.apk",
	// TODO: keycloak
}

func TestGoldenScans(t *testing.T) {
	// Skip if UPDATE_GOLDEN is not set and no golden files exist
	if os.Getenv("UPDATE_GOLDEN") != "true" {
		// Check if any golden files exist
		goldenExists := false
		for _, apkName := range apks {
			goldenFile := filepath.Join("testdata", apkName+".golden.json")
			if _, err := os.Stat(goldenFile); err == nil {
				goldenExists = true
				break
			}
		}
		if !goldenExists {
			t.Skip("No golden files exist and UPDATE_GOLDEN is not set")
		}
	}

	for _, apkName := range apks {
		t.Run(apkName, func(t *testing.T) {
			ctx := slogtest.Context(t)

			// Create a temporary directory for extraction
			tmpDir := t.TempDir()
			extractDir := filepath.Join(tmpDir, "extracted")
			require.NoError(t, os.MkdirAll(extractDir, 0755))

			// Check if APK exists locally
			apkPath := filepath.Join("testdata", apkName)
			if _, err := os.Stat(apkPath); os.IsNotExist(err) {
				// Download the APK if UPDATE_GOLDEN is set
				if os.Getenv("UPDATE_GOLDEN") == "true" {
					t.Logf("Downloading APK: %s", apkName)
					err := downloadAPK(apkName, apkPath)
					if err != nil {
						t.Skipf("Failed to download APK %s: %v", apkName, err)
						return
					}
				} else {
					t.Skipf("APK not found locally: %s", apkName)
					return
				}
			}

			// Extract the APK
			err := extractAPK(apkPath, extractDir)
			require.NoError(t, err)

			// Scan the extracted contents
			scanner := NewScanner(extractDir)
			packages, err := scanner.Scan(ctx)
			require.NoError(t, err)

			goldenFile := filepath.Join("testdata", apkName+".golden.json")

			// Generate golden file if it needs update
			if os.Getenv("UPDATE_GOLDEN") == "true" {
				generateGoldenFile(t, goldenFile, packages)
			}

			// Compare with golden file
			if _, err := os.Stat(goldenFile); err == nil {
				compareWithGolden(t, goldenFile, packages)
			} else {
				t.Skipf("Golden file does not exist: %s", goldenFile)
			}
		})
	}
}

// generateGoldenFile creates a golden file from the scan results
func generateGoldenFile(t *testing.T, filename string, packages []sbom.Package) {
	// Extract the package name from the APK filename
	apkName := filepath.Base(filename)
	apkName = strings.TrimSuffix(apkName, ".golden.json")

	// Parse package info from APK name (e.g., "crane-0.19.1-r6.apk")
	pkgName, version := parseAPKName(apkName)

	// Create an SBOM document
	doc := sbom.NewDocument()
	doc.CreatedTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Add the main package
	mainPkg := &sbom.Package{
		Name:            pkgName,
		Version:         version,
		Arch:            "x86_64",
		Namespace:       "wolfi",
		LicenseDeclared: "NOASSERTION",
	}
	doc.AddPackageAndSetDescribed(mainPkg)

	// Add all Syft-detected packages
	for _, pkg := range packages {
		p := pkg // Create a copy
		doc.AddPackage(&p)
		// Add relationship: main package contains detected package
		doc.AddRelationship(mainPkg, &p, "CONTAINS")
	}

	// Convert to SPDX format
	ctx := slogtest.Context(t)
	releaseData := &apko_build.ReleaseData{
		ID:        "wolfi",
		VersionID: "20230201",
	}
	spdxDoc := doc.ToSPDX(ctx, releaseData)

	// Write the SPDX JSON
	data, err := json.MarshalIndent(spdxDoc, "", "  ")
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

	// Generate the same SBOM structure for comparison
	apkName := filepath.Base(filename)
	apkName = strings.TrimSuffix(apkName, ".golden.json")

	// Parse package info from APK name
	pkgName, version := parseAPKName(apkName)

	// Create the same SBOM structure
	doc := sbom.NewDocument()
	doc.CreatedTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	mainPkg := &sbom.Package{
		Name:            pkgName,
		Version:         version,
		Arch:            "x86_64",
		Namespace:       "wolfi",
		LicenseDeclared: "NOASSERTION",
	}
	doc.AddPackageAndSetDescribed(mainPkg)

	for _, pkg := range packages {
		p := pkg
		doc.AddPackage(&p)
		doc.AddRelationship(mainPkg, &p, "CONTAINS")
	}

	ctx := slogtest.Context(t)
	releaseData := &apko_build.ReleaseData{
		ID:        "wolfi",
		VersionID: "20230201",
	}
	spdxDoc := doc.ToSPDX(ctx, releaseData)

	actualData, err := json.MarshalIndent(spdxDoc, "", "  ")
	require.NoError(t, err)

	require.JSONEq(t, string(goldenData), string(actualData),
		"SBOM output differs from golden file. Run with UPDATE_GOLDEN=true to update.")
}

// parseAPKName parses an APK filename to extract package name and version
// Examples:
//   - "crane-0.19.1-r6.apk" → ("crane", "0.19.1-r6")
//   - "perl-yaml-syck-1.34-r3.apk" → ("perl-yaml-syck", "1.34-r3")
//   - "python-3.11-base-3.11.9-r6.apk" → ("python-3.11-base", "3.11.9-r6")
func parseAPKName(apkName string) (name, version string) {
	// Remove .apk suffix
	nameWithoutApk := strings.TrimSuffix(apkName, ".apk")

	// Find the last -r followed by a number (release/epoch)
	rIndex := -1
	for i := len(nameWithoutApk) - 2; i >= 0; i-- {
		if nameWithoutApk[i] == '-' && nameWithoutApk[i+1] == 'r' {
			// Check if what follows 'r' is a number
			if i+2 < len(nameWithoutApk) {
				restIsNumber := true
				for j := i + 2; j < len(nameWithoutApk); j++ {
					if nameWithoutApk[j] < '0' || nameWithoutApk[j] > '9' {
						restIsNumber = false
						break
					}
				}
				if restIsNumber && len(nameWithoutApk[i+2:]) > 0 {
					rIndex = i
					break
				}
			}
		}
	}

	if rIndex == -1 {
		// No -r<number> found, treat the whole thing as the name
		return nameWithoutApk, ""
	}

	// Everything from -r onwards is part of the version
	nameAndMainVersion := nameWithoutApk[:rIndex]
	release := nameWithoutApk[rIndex+1:] // includes the 'r'

	// Find where the version starts
	// Look for the last segment that starts with a digit after a dash
	versionStartIndex := -1
	for i := len(nameAndMainVersion) - 1; i >= 0; i-- {
		if nameAndMainVersion[i] == '-' && i+1 < len(nameAndMainVersion) {
			// Check if the next character is a digit
			if nameAndMainVersion[i+1] >= '0' && nameAndMainVersion[i+1] <= '9' {
				versionStartIndex = i + 1
				break
			}
		}
	}

	if versionStartIndex == -1 {
		// No version found, everything is the name
		return nameAndMainVersion, release
	}

	name = nameAndMainVersion[:versionStartIndex-1] // -1 to exclude the dash
	mainVersion := nameAndMainVersion[versionStartIndex:]
	version = mainVersion + "-" + release

	return name, version
}

// downloadAPK downloads an APK from the Wolfi package repository
func downloadAPK(apkName, destPath string) error {
	url := fmt.Sprintf("https://packages.wolfi.dev/os/x86_64/%s", apkName)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download APK: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download APK: HTTP %d", resp.StatusCode)
	}

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// extractAPK extracts the contents of an APK file to a directory
func extractAPK(apkPath, destDir string) error {
	file, err := os.Open(apkPath)
	if err != nil {
		return fmt.Errorf("failed to open APK: %w", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to extract file: %w", err)
			}

			outFile.Close()

			if err := os.Chmod(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set file permissions: %w", err)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}

	return nil
}
