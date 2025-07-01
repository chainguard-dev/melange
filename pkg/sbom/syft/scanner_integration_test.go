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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/sbom"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

// TestScanPackageDirectory tests scanning a directory structure like Melange creates
func TestScanPackageDirectory(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := slogtest.Context(t)
	
	// Create a package directory structure similar to what Melange creates
	tmpDir := t.TempDir()
	
	// Create usr/bin directory
	binDir := filepath.Join(tmpDir, "usr", "bin")
	err := os.MkdirAll(binDir, 0755)
	require.NoError(t, err)
	
	// Build a test binary with known dependencies
	mainGo := `package main
import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)
func main() {
	logrus.Info("Test")
	cmd := &cobra.Command{Use: "test"}
	cmd.Execute()
	fmt.Println("done")
}`
	
	goMod := `module testapp
go 1.21
require (
	github.com/spf13/cobra v1.8.0
	github.com/sirupsen/logrus v1.9.3
)`

	// Create a temp build directory
	buildDir := t.TempDir()
	
	// Write files
	err = os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(mainGo), 0644)
	require.NoError(t, err)
	
	err = os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(goMod), 0644)
	require.NoError(t, err)
	
	// Build the binary
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = buildDir
	err = cmd.Run()
	require.NoError(t, err)
	
	binaryPath := filepath.Join(binDir, "test-app")
	cmd = exec.Command("go", "build", "-o", binaryPath, "main.go")
	cmd.Dir = buildDir
	err = cmd.Run()
	require.NoError(t, err)
	
	// Also add some Python files
	libDir := filepath.Join(tmpDir, "usr", "lib", "python3.11", "site-packages")
	err = os.MkdirAll(libDir, 0755)
	require.NoError(t, err)
	
	err = os.WriteFile(filepath.Join(libDir, "requirements.txt"), []byte(`
requests==2.31.0
numpy==1.26.0
`), 0644)
	require.NoError(t, err)
	
	// Scan the package directory
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, packages)
	
	// Verify we found Go modules from the binary
	foundCobra := false
	foundLogrus := false
	
	// Verify we found Python packages
	foundRequests := false
	foundNumpy := false
	
	for _, pkg := range packages {
		if strings.Contains(pkg.Name, "cobra") {
			foundCobra = true
			require.Equal(t, "v1.8.0", pkg.Version)
		}
		if strings.Contains(pkg.Name, "logrus") {
			foundLogrus = true
			require.Equal(t, "v1.9.3", pkg.Version)
		}
		if pkg.Name == "python:requests" {
			foundRequests = true
			require.Equal(t, "2.31.0", pkg.Version)
		}
		if pkg.Name == "python:numpy" {
			foundNumpy = true
			require.Equal(t, "1.26.0", pkg.Version)
		}
	}
	
	require.True(t, foundCobra, "should find cobra module in binary")
	require.True(t, foundLogrus, "should find logrus module in binary")
	require.True(t, foundRequests, "should find requests package")
	require.True(t, foundNumpy, "should find numpy package")
}

// TestScanDirectory tests scanning a directory with multiple package types
func TestScanDirectory(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a directory with multiple package files
	tmpDir := t.TempDir()
	
	// Python requirements
	err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(`
requests==2.31.0
flask==3.0.0
`), 0644)
	require.NoError(t, err)
	
	// Go mod file
	err = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(`
module example.com/test
go 1.21
require github.com/spf13/cobra v1.8.0
`), 0644)
	require.NoError(t, err)
	
	// Scan the directory
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	require.NoError(t, err)
	
	// Verify we found packages from both ecosystems
	var pythonPkgs, goPkgs []sbom.Package
	
	for _, pkg := range packages {
		if strings.HasPrefix(pkg.Name, "python:") {
			pythonPkgs = append(pythonPkgs, pkg)
		} else if strings.HasPrefix(pkg.Name, "go-module:") {
			goPkgs = append(goPkgs, pkg)
		}
	}
	
	require.NotEmpty(t, pythonPkgs, "should find Python packages")
	require.NotEmpty(t, goPkgs, "should find Go packages")
	
	// Verify specific packages
	foundRequests := false
	foundCobra := false
	
	for _, pkg := range packages {
		if pkg.Name == "python:requests" && pkg.Version == "2.31.0" {
			foundRequests = true
		}
		if strings.Contains(pkg.Name, "cobra") && pkg.Version == "v1.8.0" {
			foundCobra = true
		}
	}
	
	require.True(t, foundRequests, "should find requests package")
	require.True(t, foundCobra, "should find cobra package")
}

// TestMergerIntegration tests the full integration of scanning and merging
func TestMergerIntegration(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a test SBOM document
	doc := sbom.NewDocument()
	apkPkg := sbom.Package{
		Name:    "test-package",
		Version: "1.0.0",
	}
	doc.Packages = []sbom.Package{apkPkg}
	
	// Create a test directory with some packages
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(`
numpy==1.26.0
pandas==2.1.1
`), 0644)
	require.NoError(t, err)
	
	// Scan the directory
	scanner := NewScanner(tmpDir)
	syftPackages, err := scanner.Scan(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, syftPackages)
	
	// Merge into document
	err = MergeIntoDocument(ctx, doc, syftPackages, "test-package")
	require.NoError(t, err)
	
	// Verify the merge
	require.Greater(t, len(doc.Packages), 1, "should have more than just the APK package")
	require.NotEmpty(t, doc.Relationships, "should have relationships")
	
	// Check that all Syft packages were added
	for _, syftPkg := range syftPackages {
		found := false
		for _, pkg := range doc.Packages {
			if pkg.Name == syftPkg.Name && pkg.Version == syftPkg.Version {
				found = true
				// Verify the package has the syft-detected ID component
				require.Contains(t, pkg.IDComponents, "syft-detected")
				break
			}
		}
		require.True(t, found, "Syft package %s should be in document", syftPkg.Name)
	}
	
	// Check relationships
	for _, rel := range doc.Relationships {
		require.Equal(t, apkPkg.ID(), rel.Element)
		require.Equal(t, "CONTAINS", rel.Type)
		
		// Verify the related package exists
		found := false
		for _, pkg := range doc.Packages {
			if pkg.ID() == rel.Related {
				found = true
				break
			}
		}
		require.True(t, found, "relationship should point to existing package")
	}
}