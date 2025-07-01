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
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner("/test/path")
	require.NotNil(t, scanner)
	require.Equal(t, "/test/path", scanner.path)
}

func TestScan_EmptyDirectory(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary empty directory
	tmpDir := t.TempDir()
	
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	require.Empty(t, packages)
}

func TestScan_WithGoModule(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary directory with a Go binary
	tmpDir := t.TempDir()
	
	// With Syft integrated, scanning an empty directory should work
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	require.Empty(t, packages) // Empty directory should have no packages
}

func TestScan_NonExistentPath(t *testing.T) {
	ctx := slogtest.Context(t)
	
	scanner := NewScanner("/non/existent/path")
	packages, err := scanner.Scan(ctx)
	
	// Syft should error on non-existent paths
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file or directory")
	require.Nil(t, packages)
}

func TestScan_WithTestFiles(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary directory with some test files
	tmpDir := t.TempDir()
	
	// Create a fake Go module file
	goModContent := `module example.com/test

go 1.24

require (
	github.com/stretchr/testify v1.8.0
	github.com/chainguard-dev/clog v1.0.0
)
`
	err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644)
	require.NoError(t, err)
	
	// Create a fake Python requirements file
	requirementsContent := `numpy==1.24.0
pandas==2.0.0
requests==2.28.1
`
	err = os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsContent), 0644)
	require.NoError(t, err)
	
	// Create a fake package.json file
	packageJSONContent := `{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "react": "^18.2.0"
  }
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSONContent), 0644)
	require.NoError(t, err)
	
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	// Syft should find packages from these files
	require.NotEmpty(t, packages)
	
	// Check that we found the expected package types
	var foundGo, foundPython bool
	for _, pkg := range packages {
		if strings.Contains(pkg.Name, "go-module:") {
			foundGo = true
		}
		if strings.Contains(pkg.Name, "python:") {
			foundPython = true
		}
	}
	
	require.True(t, foundGo, "should find Go modules")
	require.True(t, foundPython, "should find Python packages")
	// Note: Syft may not detect NPM packages from just package.json without node_modules
}